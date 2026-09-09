defmodule Foray.Fuzz.Ffuf do
  @moduledoc "ffuf v2.2 engine using streamed `-json` NDJSON output."

  @behaviour Foray.Fuzz.Engine

  alias Foray.Finding
  alias Foray.Job
  alias Foray.NDJSON
  alias Foray.Oracle
  alias Foray.Stream.Cursor
  alias Foray.Wordlist
  alias Foray.Wordlist.Materializer

  @impl true
  def option_schema do
    [
      executable: [type: :string, default: "ffuf"],
      runner: [type: :atom, default: Core.Runner.backend()],
      runner_options: [type: :keyword_list, default: []],
      request_timeout: [type: :pos_integer, default: 10],
      http2: [type: :boolean, default: false],
      raw: [type: :boolean, default: false],
      ignore_body: [type: :boolean, default: false],
      proxy: [type: {:or, [:string, nil]}, default: nil],
      replay_proxy: [type: {:or, [:string, nil]}, default: nil],
      minimum_version: [type: :string, default: "2.2.0"],
      allow_unsupported_version: [type: :boolean, default: false],
      version_timeout: [type: :pos_integer, default: 2_000],
      max_chunk_size: [type: :pos_integer, default: 65_535],
      exit_timeout: [type: :pos_integer, default: 5_000]
    ]
  end

  @impl true
  def capabilities do
    [
      :auto_calibration,
      :input_command,
      :multi_keyword,
      :native_recursion,
      :request_body,
      :request_headers,
      :streaming_ndjson
    ]
  end

  @impl true
  def validate_runtime(opts) do
    opts = NimbleOptions.validate!(opts, option_schema())

    with executable when is_binary(executable) <- System.find_executable(opts[:executable]),
         :ok <- validate_version(executable, opts) do
      :ok
    else
      nil -> {:error, {:executable_not_found, opts[:executable]}}
      {:error, _reason} = error -> error
    end
  end

  @impl true
  def stream(%Job{} = job, opts) do
    opts = NimbleOptions.validate!(opts, option_schema())

    Stream.resource(
      fn -> start_stream(job, opts) end,
      &next_match/1,
      &close_stream/1
    )
  end

  @doc "Builds the exact argv for a materialized job."
  @spec command(Job.t(), keyword()) :: [String.t()]
  def command(%Job{} = job, opts) do
    opts = NimbleOptions.validate!(opts, option_schema())
    validate_job!(job)
    request = request_arguments(job)

    [opts[:executable], "-noninteractive", "-s", "-json"] ++
      ["-u", request.url, "-X", job.method] ++
      header_arguments(request.headers) ++
      optional_pair("-d", request.body) ++
      optional_pair("-b", request.cookies) ++
      input_arguments(job) ++
      ["-mode", Atom.to_string(job.mode)] ++
      oracle_arguments(job.oracle) ++
      [
        "-t",
        Integer.to_string(job.threads),
        "-rate",
        Integer.to_string(job.request_rate),
        "-maxtime",
        Integer.to_string(job.max_time),
        "-timeout",
        Integer.to_string(opts[:request_timeout])
      ] ++
      optional_pair("-p", job.delay) ++
      boolean_argument("-http2", opts[:http2]) ++
      boolean_argument("-raw", opts[:raw]) ++
      boolean_argument("-ignore-body", opts[:ignore_body]) ++
      optional_pair("-x", opts[:proxy]) ++
      optional_pair("-replay-proxy", opts[:replay_proxy]) ++
      recursion_arguments(job.recursion)
  end

  defp start_stream(job, opts) do
    {materialized_job, paths} = Materializer.materialize(job)

    try do
      runner_opts =
        Keyword.merge(opts[:runner_options],
          stderr: :consume,
          max_chunk_size: opts[:max_chunk_size],
          exit_timeout: opts[:exit_timeout],
          ignore_epipe: true
        )

      matches =
        materialized_job
        |> command(opts)
        |> Core.Runner.stream(Keyword.put(runner_opts, :backend, opts[:runner]))
        |> Stream.transform(nil, &stdout_chunk/2)
        |> NDJSON.stream()
        |> Stream.map(&Finding.from_match(&1, job))

      %{cursor: Cursor.new(matches), paths: paths}
    rescue
      exception ->
        Materializer.cleanup(paths)
        reraise exception, __STACKTRACE__
    end
  end

  defp next_match(%{cursor: cursor} = state) do
    case Cursor.next(cursor) do
      {:ok, finding, cursor} -> {[finding], %{state | cursor: cursor}}
      :done -> {:halt, %{state | cursor: :done}}
    end
  end

  defp close_stream(state) do
    Cursor.halt(state.cursor)
    Materializer.cleanup(state.paths)
  end

  defp stdout_chunk({:stdout, chunk}, state), do: {[IO.iodata_to_binary(chunk)], state}
  defp stdout_chunk({:stderr, _chunk}, state), do: {[], state}
  defp stdout_chunk(chunk, state), do: {[IO.iodata_to_binary(chunk)], state}

  defp request_arguments(%Job{mode: :sniper} = job) do
    %{
      url: sniper_template(job.target.url, job.fuzz_points),
      headers:
        Map.new(job.headers, fn {key, value} -> {key, sniper_template(value, job.fuzz_points)} end),
      body: sniper_template(job.body, job.fuzz_points),
      cookies: sniper_template(job.cookies, job.fuzz_points)
    }
  end

  defp request_arguments(job) do
    %{url: job.target.url, headers: job.headers, body: job.body, cookies: job.cookies}
  end

  defp sniper_template(nil, _points), do: nil

  defp sniper_template(value, points) do
    points
    |> Enum.map(& &1.keyword)
    |> Enum.uniq()
    |> Enum.reduce(value, fn keyword, template ->
      String.replace(template, keyword, "§#{keyword}§")
    end)
  end

  defp header_arguments(headers) do
    headers
    |> Enum.sort()
    |> Enum.flat_map(fn {name, value} -> ["-H", "#{name}: #{value}"] end)
  end

  defp input_arguments(%Job{mode: :sniper, wordlists: [wordlist | _rest]}) do
    source_arguments(wordlist, false)
  end

  defp input_arguments(job) do
    Enum.flat_map(job.wordlists, &source_arguments(&1, true))
  end

  defp source_arguments(%Wordlist{source: {:file, path}, keyword: keyword}, include_keyword?) do
    value = if include_keyword?, do: path <> ":" <> keyword, else: path
    ["-w", value]
  end

  defp source_arguments(
         %Wordlist{source: {:command, command, count, shell}, keyword: keyword},
         include_keyword?
       ) do
    value = if include_keyword?, do: command <> ":" <> keyword, else: command

    ["-input-cmd", value, "-input-num", Integer.to_string(count)] ++
      optional_pair("-input-shell", shell)
  end

  defp oracle_arguments(%Oracle{} = oracle) do
    matcher_arguments(oracle.matchers) ++
      filter_arguments(oracle.filters) ++
      [
        "-mmode",
        Atom.to_string(oracle.matcher_mode),
        "-fmode",
        Atom.to_string(oracle.filter_mode)
      ] ++
      boolean_argument("-ac", oracle.auto_calibrate) ++
      Enum.flat_map(oracle.calibration_strings, &["-acc", &1])
  end

  defp matcher_arguments(criteria) do
    criterion_arguments(criteria, %{
      codes: "-mc",
      lines: "-ml",
      regex: "-mr",
      size: "-ms",
      time: "-mt",
      words: "-mw"
    })
  end

  defp filter_arguments(criteria) do
    criterion_arguments(criteria, %{
      codes: "-fc",
      lines: "-fl",
      regex: "-fr",
      size: "-fs",
      time: "-ft",
      words: "-fw"
    })
  end

  defp criterion_arguments(criteria, flags) do
    flags
    |> Enum.sort()
    |> Enum.flat_map(fn {name, flag} ->
      case Map.fetch(criteria, name) do
        {:ok, value} -> [flag, encode_criterion(value)]
        :error -> []
      end
    end)
  end

  defp encode_criterion(:all), do: "all"
  defp encode_criterion({:gt, milliseconds}), do: ">#{milliseconds}"
  defp encode_criterion({:lt, milliseconds}), do: "<#{milliseconds}"
  defp encode_criterion(%Range{} = range), do: "#{range.first}-#{range.last}"

  defp encode_criterion(values) when is_list(values) do
    Enum.map_join(values, ",", &encode_criterion/1)
  end

  defp encode_criterion(value), do: to_string(value)

  defp recursion_arguments(nil), do: []

  defp recursion_arguments(%{depth: depth, strategy: strategy}) do
    [
      "-recursion",
      "-recursion-depth",
      Integer.to_string(depth),
      "-recursion-strategy",
      Atom.to_string(strategy)
    ]
  end

  defp validate_version(executable, opts) do
    Core.Telemetry.launch(:foray, %{kind: :runtime_check, executable: executable})

    case Core.Runner.run([executable, "-V"],
           backend: opts[:runner],
           timeout: opts[:version_timeout]
         ) do
      {output, 0} -> compare_version(output, opts)
      {output, status} -> {:error, {:version_check_failed, status, output}}
    end
  rescue
    exception -> {:error, {:version_check_failed, Exception.message(exception)}}
  end

  defp compare_version(output, opts) do
    with {:ok, found} <- parse_version(output),
         {:ok, required} <- parse_version(opts[:minimum_version]) do
      if opts[:allow_unsupported_version] or version_gte?(found, required) do
        :ok
      else
        {:error, {:unsupported_ffuf_version, format_version(found), format_version(required)}}
      end
    end
  end

  defp parse_version(version) do
    case Regex.run(~r/(?:^|\s)v?(\d+)\.(\d+)\.(\d+)(?:\D|$)/, version) do
      [_, major, minor, patch] ->
        {:ok, {String.to_integer(major), String.to_integer(minor), String.to_integer(patch)}}

      nil ->
        {:error, {:unrecognized_ffuf_version, String.trim(version)}}
    end
  end

  defp version_gte?(found, required), do: Tuple.to_list(found) >= Tuple.to_list(required)
  defp format_version(version), do: version |> Tuple.to_list() |> Enum.join(".")

  defp validate_job!(%Job{} = job) do
    cond do
      job.wordlists == [] ->
        raise ArgumentError, "ffuf jobs require at least one input source"

      command_source_count(job) > 1 ->
        raise ArgumentError, "ffuf supports only one input-command source"

      command_source_count(job) == 1 and length(job.wordlists) > 1 ->
        raise ArgumentError, "ffuf input-command mode cannot be combined with wordlist files"

      job.recursion && (job.mode != :clusterbomb or not String.ends_with?(job.target.url, "FUZZ")) ->
        raise ArgumentError, "ffuf recursion requires clusterbomb mode and a URL ending in FUZZ"

      true ->
        :ok
    end
  end

  defp command_source_count(job) do
    Enum.count(job.wordlists, &match?(%Wordlist{source: {:command, _, _, _}}, &1))
  end

  defp optional_pair(_flag, nil), do: []
  defp optional_pair(flag, value), do: [flag, value]
  defp boolean_argument(_flag, false), do: []
  defp boolean_argument(flag, true), do: [flag]
end
