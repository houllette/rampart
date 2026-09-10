defmodule RampartSAST.Isolated do
  @moduledoc """
  Disposable-VM scanning for untrusted Elixir and Erlang source trees.

  `RampartSAST.scan/3` is the fastest API for trusted snapshots, but Elixir and
  Erlang parsers intern source atoms in their VM-global atom table. This module
  runs discovery, parsing, inventory construction, and optional rules in a
  short-lived OS process. The parent receives only bounded, string-keyed plain
  data and never decodes the target AST.

  The worker has a wall-clock deadline, finite response/log limits, a finite
  atom table, and a default per-process heap ceiling. Those ERTS limits are not
  a portable total-RSS sandbox. The caller must still apply filesystem and
  execution isolation appropriate to its threat model. Target code is parsed,
  never compiled or executed.
  """

  alias RampartSAST.Inventory.Index
  alias RampartSAST.Isolated.{Limits, Result, Wire}

  @type rule_specification :: RampartSAST.Rule.specification()

  @doc "Builds a broad portable inventory in a disposable BEAM instance."
  @spec inventory(root :: Path.t(), options :: keyword()) :: Result.t()
  def inventory(root, options \\ []) when is_binary(root) and is_list(options) do
    scan(root, [], options)
  end

  @doc "Builds a broad portable inventory from in-memory snapshots in a disposable BEAM instance."
  @spec inventory_sources(entries :: [{Path.t(), String.t()}], options :: keyword()) :: Result.t()
  def inventory_sources(entries, options \\ []) when is_list(entries) and is_list(options) do
    scan_sources(entries, [], options)
  end

  @doc "Runs host-selected static signal rules in a disposable BEAM instance."
  @spec scan(root :: Path.t(), rules :: [rule_specification()], options :: keyword()) ::
          Result.t()
  def scan(root, rules, options \\ [])
      when is_binary(root) and is_list(rules) and is_list(options) do
    isolate(%{operation: :root, root: Path.expand(root)}, rules, options)
  end

  @doc "Scans in-memory snapshots with host-selected rules in a disposable BEAM instance."
  @spec scan_sources(
          entries :: [{Path.t(), String.t()}],
          rules :: [rule_specification()],
          options :: keyword()
        ) :: Result.t()
  def scan_sources(entries, rules, options \\ [])
      when is_list(entries) and is_list(rules) and is_list(options) do
    isolate(%{operation: :sources, entries: entries}, rules, options)
  end

  defp isolate(request, rules, options) do
    {isolation_options, scanner_options} = Keyword.pop(options, :isolation, [])

    isolation_options =
      Keyword.validate!(isolation_options, [:limits, :elixir_executable, :tmp_dir])

    limits = isolation_options |> Keyword.get(:limits, []) |> Limits.new!()
    executable = isolation_options[:elixir_executable] || System.find_executable("elixir")
    tmp_dir = isolation_options[:tmp_dir] || System.tmp_dir!()
    request = Map.merge(request, %{rules: rules, options: scanner_options})
    started_at = System.monotonic_time()

    case executable do
      nil ->
        failure("elixir_not_found", "could not find the Elixir executable", started_at, %{})

      executable ->
        caller = self()
        reference = make_ref()

        {owner, monitor} =
          spawn_monitor(fn ->
            result =
              run_worker(
                {executable, caller},
                request,
                rules,
                scanner_options,
                tmp_dir,
                limits,
                started_at
              )

            send(caller, {reference, result})
          end)

        receive do
          {^reference, result} ->
            Process.demonitor(monitor, [:flush])
            result

          {:DOWN, ^monitor, :process, ^owner, reason} ->
            failure(
              "worker_owner_failed",
              "isolated worker owner exited: #{inspect(reason, limit: 10)}",
              started_at,
              %{}
            )
        end
    end
  end

  @doc "Filters portable fact maps and returns a bounded page."
  @spec query_page(Result.t(), keyword()) :: map()
  def query_page(%Result{} = result, filters \\ []) when is_list(filters) do
    filters =
      Keyword.validate!(filters, [
        :kind,
        :subject,
        :relation,
        :object,
        :file,
        :target_module,
        :target_function,
        :subject_prefix,
        :object_prefix,
        limit: 100,
        offset: 0
      ])

    limit = positive_integer!(filters[:limit], :limit)
    offset = non_negative_integer!(filters[:offset], :offset)
    index = result.index || Index.build(result.inventory["facts"])
    {facts, total} = Index.page(index, filters, &matches?(&1, filters))
    returned = length(facts)

    %{
      inventory_id: result.inventory["id"],
      facts: facts,
      offset: offset,
      limit: limit,
      returned: returned,
      total: total,
      next_offset: if(offset + returned < total, do: offset + returned)
    }
  end

  @doc "Returns a bounded list of portable fact maps."
  @spec query(Result.t(), keyword()) :: [map()]
  def query(%Result{} = result, filters \\ []) do
    result |> query_page(filters) |> Map.fetch!(:facts)
  end

  defp run_worker(executable, request, rules, scanner_options, tmp_dir, limits, started_at) do
    with :ok <- portable_request?(request),
         {:ok, paths} <- temporary_paths(tmp_dir) do
      try do
        case write_request(paths.request, request) do
          :ok -> execute_worker(executable, paths, rules, scanner_options, limits, started_at)
          {:error, message} -> failure("worker_setup_failed", message, started_at, %{})
        end
      after
        cleanup(paths)
      end
    else
      {:error, {code, message}} -> failure(code, message, started_at, %{})
      {:error, message} -> failure("worker_setup_failed", message, started_at, %{})
    end
  end

  defp execute_worker({executable, owner}, paths, rules, scanner_options, limits, started_at) do
    arguments = worker_arguments(paths, rules, scanner_options, limits)

    case Core.Runner.run([executable | arguments],
           owner: owner,
           timeout: limits.timeout_ms,
           max_output_bytes: limits.max_log_bytes,
           exit_timeout: 1_000
         ) do
      {log, 0} ->
        read_response(paths.response, log, limits, started_at)

      {log, status} ->
        failure(
          "worker_failed",
          "isolated SAST worker exited with status #{status}#{format_log(log)}",
          started_at,
          %{"exit_status" => status}
        )
    end
  rescue
    _error in Core.Runner.TimeoutError ->
      failure("worker_timeout", "isolated SAST worker exceeded its deadline", started_at, %{})

    error in Core.Runner.Error ->
      code =
        if match?({:output_limit, _limit}, error.reason),
          do: "worker_log_limit",
          else: "worker_failed"

      failure(code, Exception.message(error), started_at, %{})
  end

  defp read_response(path, log, limits, started_at) do
    with {:ok, stat} <- File.stat(path),
         :ok <- response_size(stat.size, limits.max_response_bytes),
         {:ok, binary} <- File.read(path),
         {:ok, envelope} <- decode(binary, limits) do
      worker =
        envelope
        |> Map.get("worker_metrics", %{})
        |> Map.merge(worker_metrics(started_at, byte_size(binary), log, %{}))

      case envelope do
        %{"type" => "result"} ->
          Result.from_wire!(envelope, worker)

        %{"type" => "error", "code" => code, "message" => message} ->
          Result.failure(code, message, worker)

        _other ->
          Result.failure("invalid_worker_response", "worker returned an unknown envelope", worker)
      end
    else
      {:error, :enoent} ->
        failure(
          "missing_worker_response",
          "isolated SAST worker produced no response",
          started_at,
          %{}
        )

      {:error, {code, message}} ->
        failure(code, message, started_at, %{})

      {:error, reason} ->
        failure(
          "worker_response_failed",
          "could not read isolated SAST response: #{inspect(reason)}",
          started_at,
          %{}
        )
    end
  rescue
    error in ArgumentError ->
      failure("invalid_worker_response", Exception.message(error), started_at, %{})
  end

  defp decode(binary, limits) do
    {:ok,
     Wire.decode!(binary,
       max_bytes: limits.max_response_bytes,
       max_terms: limits.max_wire_terms,
       max_depth: limits.max_wire_depth
     )}
  rescue
    error in [ArgumentError, ErlangError] ->
      {:error, {"invalid_worker_response", Exception.message(error)}}
  end

  defp response_size(size, max_bytes) when size <= max_bytes, do: :ok

  defp response_size(size, max_bytes) do
    {:error,
     {"worker_response_limit", "isolated SAST response has #{size} bytes; limit is #{max_bytes}"}}
  end

  defp worker_arguments(paths, rules, scanner_options, limits) do
    code_paths = worker_code_paths(rules, scanner_options)

    [
      "--no-halt",
      "--erl",
      "+hmax #{limits.max_heap_words} +hmaxk true +t #{limits.atom_table_size}"
    ] ++
      Enum.flat_map(code_paths, &["-pa", &1]) ++
      [
        "-e",
        "RampartSAST.Isolated.Worker.main(System.argv())",
        "--",
        paths.request,
        paths.response
      ]
  end

  defp worker_code_paths(rules, scanner_options) do
    modules =
      [RampartSAST, RampartSAST.Isolated.Worker, Core.Finding] ++
        rule_modules(rules) ++
        Keyword.get(scanner_options, :context_providers, []) ++
        Keyword.get(scanner_options, :behavior_classifiers, [])

    modules
    |> Enum.flat_map(&module_code_path/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp rule_modules(rules) do
    Enum.flat_map(rules, fn
      module when is_atom(module) -> [module]
      {module, _options} when is_atom(module) -> [module]
      _other -> []
    end)
  end

  defp module_code_path(module) when is_atom(module) do
    case :code.which(module) do
      path when is_list(path) -> [path |> List.to_string() |> Path.dirname()]
      _other -> []
    end
  end

  defp temporary_paths(tmp_dir) do
    case File.mkdir_p(tmp_dir) do
      :ok ->
        nonce = Base.url_encode64(:crypto.strong_rand_bytes(18), padding: false)
        base = Path.join(tmp_dir, "rampart-sast-#{nonce}")
        {:ok, %{request: base <> ".request", response: base <> ".response"}}

      {:error, reason} ->
        {:error, "could not create isolated SAST temporary directory: #{inspect(reason)}"}
    end
  end

  defp write_request(path, request) do
    binary = :erlang.term_to_binary(request)

    with :ok <- File.write(path, binary, [:binary, :exclusive]),
         :ok <- File.chmod(path, 0o600) do
      :ok
    else
      {:error, reason} -> {:error, "could not write isolated SAST request: #{inspect(reason)}"}
    end
  end

  defp cleanup(paths) do
    Enum.each([paths.request, paths.response, paths.response <> ".part"], &File.rm/1)
  end

  defp portable_request?(request) do
    if portable_request_value?(request),
      do: :ok,
      else:
        {:error,
         {"invalid_worker_request",
          "isolated SAST options must not contain functions, PIDs, ports, or references"}}
  end

  defp portable_request_value?(value)
       when is_binary(value) or is_number(value) or is_atom(value),
       do: true

  defp portable_request_value?(value) when is_list(value),
    do: Enum.all?(value, &portable_request_value?/1)

  defp portable_request_value?(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.all?(&portable_request_value?/1)

  defp portable_request_value?(%_module{} = value),
    do: value |> Map.from_struct() |> portable_request_value?()

  defp portable_request_value?(value) when is_map(value) do
    Enum.all?(value, fn {key, item} ->
      portable_request_value?(key) and portable_request_value?(item)
    end)
  end

  defp portable_request_value?(_value), do: false

  defp matches?(fact, filters) do
    exact_match?(fact, filters, :kind) and exact_match?(fact, filters, :subject) and
      exact_match?(fact, filters, :relation) and exact_match?(fact, filters, :object) and
      exact_match?(fact["attributes"], filters, :target_module) and
      exact_match?(fact["attributes"], filters, :target_function) and
      exact_file?(fact, filters[:file]) and
      prefix_match?(fact["subject"], filters[:subject_prefix]) and
      prefix_match?(fact["object"], filters[:object_prefix])
  end

  defp exact_match?(fact, filters, key) do
    case Keyword.fetch(filters, key) do
      {:ok, expected} -> fact[Atom.to_string(key)] == portable_filter(expected)
      :error -> true
    end
  end

  defp exact_file?(_fact, nil), do: true
  defp exact_file?(fact, file), do: get_in(fact, ["span", "file"]) == file
  defp prefix_match?(_value, nil), do: true
  defp prefix_match?(value, prefix), do: is_binary(prefix) and String.starts_with?(value, prefix)
  defp portable_filter(value) when is_atom(value), do: Atom.to_string(value)
  defp portable_filter(value), do: value

  defp worker_metrics(started_at, response_bytes, log, extra) do
    Map.merge(
      %{
        "duration_ms" => duration_ms(started_at),
        "response_bytes" => response_bytes,
        "log_bytes" => byte_size(log)
      },
      extra
    )
  end

  defp failure(code, message, started_at, extra) do
    Result.failure(code, message, worker_metrics(started_at, 0, <<>>, extra))
  end

  defp duration_ms(started_at) do
    System.convert_time_unit(System.monotonic_time() - started_at, :native, :millisecond)
  end

  defp format_log(<<>>), do: ""
  defp format_log(log), do: "; worker output: " <> String.trim(log)

  defp positive_integer!(value, _name) when is_integer(value) and value > 0, do: value
  defp positive_integer!(_value, name), do: raise(ArgumentError, "#{name} must be positive")
  defp non_negative_integer!(value, _name) when is_integer(value) and value >= 0, do: value

  defp non_negative_integer!(_value, name),
    do: raise(ArgumentError, "#{name} must not be negative")
end
