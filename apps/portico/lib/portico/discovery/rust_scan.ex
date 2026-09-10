defmodule Portico.Discovery.RustScan do
  @moduledoc "RustScan discovery engine using its greppable output contract."

  @behaviour Portico.Discovery.Engine

  alias Portico.Discovery.{LineStream, Result}
  alias Portico.Engine.OutputError
  alias Portico.Target

  @impl true
  def option_schema do
    [
      executable: [type: :string, default: "rustscan"],
      runner: [type: :atom, default: Core.Runner.backend()],
      runner_options: [type: :keyword_list, default: []],
      ports: [type: {:custom, __MODULE__, :validate_ports, []}, default: :full],
      batch_size: [type: :pos_integer, default: 4_500],
      socket_timeout: [type: :pos_integer, default: 1_500],
      tries: [type: :pos_integer, default: 1],
      max_chunk_size: [type: :pos_integer, default: 65_535],
      exit_timeout: [type: :pos_integer, default: 2_000]
    ]
  end

  @impl true
  def capabilities do
    %{
      protocols: [:tcp],
      target_kinds: [:ip, :cidr, :hostname],
      output_contract: :greppable,
      requires_privileges: []
    }
  end

  @impl true
  def validate_runtime(opts) do
    opts = NimbleOptions.validate!(opts, option_schema())

    if System.find_executable(opts[:executable]) do
      :ok
    else
      {:error, {:executable_not_found, opts[:executable]}}
    end
  end

  @impl true
  def stream(%Target{} = target, opts) do
    opts = NimbleOptions.validate!(opts, option_schema())
    runner = opts[:runner]
    command = command(target, opts)

    runner_opts =
      Keyword.merge(opts[:runner_options],
        stderr: :consume,
        ignore_epipe: true,
        max_chunk_size: opts[:max_chunk_size],
        exit_timeout: opts[:exit_timeout]
      )

    command
    |> Core.Runner.stream(Keyword.put(runner_opts, :backend, runner))
    |> Stream.transform(nil, &stdout_chunk/2)
    |> LineStream.transform(&parse_line(&1, target))
  end

  @doc "Builds the pinned RustScan command for conformance testing."
  @spec command(Target.t(), keyword()) :: [String.t()]
  def command(%Target{} = target, opts) do
    [
      opts[:executable],
      "--addresses",
      Target.to_arg(target),
      "--greppable",
      "--batch-size",
      Integer.to_string(opts[:batch_size]),
      "--timeout",
      Integer.to_string(opts[:socket_timeout]),
      "--tries",
      Integer.to_string(opts[:tries])
    ] ++ port_arguments(opts[:ports])
  end

  @doc "Parses one RustScan greppable line."
  @spec parse_line(String.t(), Target.t() | nil) ::
          {:ok, Result.t()} | :ignore | {:error, Exception.t()}
  def parse_line(line, target \\ nil) when is_binary(line) do
    with {:ok, line} <- LineStream.check_line(line) do
      case Regex.run(~r/^(.+?)\s*->\s*\[\s*([0-9,\s]*)\s*\]\s*$/, String.trim(line)) do
        [_, ip, ports_string] -> parse_result(String.trim(ip), ports_string, line, target)
        nil -> invalid_or_ignored(line)
      end
    end
  end

  @doc false
  @spec validate_ports(term()) :: {:ok, :full | [1..65_535]} | {:error, String.t()}
  def validate_ports(:full), do: {:ok, :full}

  def validate_ports(ports) when is_list(ports) do
    if ports != [] and Enum.all?(ports, &is_integer/1) and Enum.all?(ports, &(&1 in 1..65_535)) do
      {:ok, ports |> Enum.uniq() |> Enum.sort()}
    else
      {:error, "expected :full or a non-empty list of ports in 1..65535"}
    end
  end

  def validate_ports(_ports),
    do: {:error, "expected :full or a non-empty list of ports in 1..65535"}

  defp stdout_chunk({:stdout, chunk}, state), do: {[IO.iodata_to_binary(chunk)], state}

  defp stdout_chunk({:stderr, _chunk}, state), do: {[], state}

  defp stdout_chunk(chunk, state), do: {[IO.iodata_to_binary(chunk)], state}

  defp parse_result(ip, ports_string, line, target) do
    with {:ok, %Target{kind: :ip, value: canonical_ip}} <- Target.parse(ip),
         {:ok, ports} <- parse_ports(ports_string) do
      case ports do
        [] -> :ignore
        ports -> {:ok, %Result{target: target, ip: canonical_ip, ports: ports}}
      end
    else
      {:error, reason} -> output_error(line, reason)
      {:ok, _non_ip_target} -> output_error(line, :invalid_ip)
    end
  end

  defp parse_ports(ports_string) do
    ports_string
    |> String.split(",", trim: true)
    |> Enum.reduce_while({:ok, []}, fn port_string, {:ok, acc} ->
      case Integer.parse(String.trim(port_string)) do
        {port, ""} when port in 1..65_535 -> {:cont, {:ok, [port | acc]}}
        _other -> {:halt, {:error, :invalid_port}}
      end
    end)
    |> case do
      {:ok, ports} -> {:ok, ports |> Enum.uniq() |> Enum.sort()}
      error -> error
    end
  end

  defp invalid_or_ignored(line) do
    if String.contains?(line, "->") do
      output_error(line, :unexpected_greppable_format)
    else
      :ignore
    end
  end

  defp output_error(line, reason) do
    {:error, OutputError.exception(engine: :rustscan, line: line, reason: reason)}
  end

  defp port_arguments(:full), do: ["--range", "1-65535"]
  defp port_arguments(ports), do: ["--ports", Enum.join(ports, ",")]
end
