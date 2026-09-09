defmodule Portico.Enrichment.Nmap do
  @moduledoc "Nmap enrichment engine with bounded execution and streaming XML parsing."

  @behaviour Portico.Enrichment.Engine

  alias Portico.Discovery.Result
  alias Portico.{Host, NmapXML, Timeout}

  @impl true
  def option_schema do
    [
      executable: [type: :string, default: "nmap"],
      runner: [type: :atom, default: Core.Runner.backend()],
      runner_options: [type: :keyword_list, default: []],
      timeout: [type: :pos_integer, default: 120_000],
      scan_type: [type: {:in, [:auto, :connect, :syn, :udp]}, default: :auto],
      service_detection: [type: :boolean, default: true],
      version_intensity: [type: {:in, 0..9}, default: 7],
      os_detection: [type: :boolean, default: false],
      scripts: [type: {:list, :string}, default: []],
      timing_template: [type: {:in, 0..5}, default: 3],
      resolve_dns: [type: {:in, [:default, :never, :always]}, default: :default],
      reason: [type: :boolean, default: true],
      host_timeout: [type: :timeout, default: :infinity],
      max_chunk_size: [type: :pos_integer, default: 65_535],
      exit_timeout: [type: :pos_integer, default: 5_000]
    ]
  end

  @impl true
  def capabilities do
    %{
      protocols: [:tcp, :udp],
      target_kinds: [:ip],
      batch_constraint: :identical_ports_and_protocol,
      output_contract: :nmap_xml,
      optional_privileges: [:net_raw]
    }
  end

  @doc "Returns OS privileges required by a concrete nmap configuration."
  @impl true
  def required_privileges(opts) do
    opts = NimbleOptions.validate!(opts, option_schema())

    if opts[:scan_type] in [:syn, :udp] or opts[:os_detection] do
      [:net_raw]
    else
      []
    end
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
  def enrich([%Result{} | _rest] = entries, opts) do
    opts = NimbleOptions.validate!(opts, option_schema())

    with :ok <- validate_batch(entries),
         :ok <- validate_scan_type(entries, opts[:scan_type]) do
      execute(entries, opts)
    end
  end

  def enrich([], _opts), do: {:ok, []}

  @doc "Builds a target-safe nmap command for a compatible discovery batch."
  @spec command([Result.t()], keyword()) :: [String.t()]
  def command([%Result{} = first | _rest] = entries, opts) do
    opts = NimbleOptions.validate!(opts, option_schema())

    with :ok <- validate_batch(entries),
         :ok <- validate_scan_type(entries, opts[:scan_type]) do
      scan_type = effective_scan_type(opts[:scan_type], first.protocol)

      [opts[:executable], scan_type_argument(scan_type)] ++
        service_arguments(opts) ++
        os_arguments(opts) ++
        script_arguments(opts) ++
        timing_arguments(opts) ++
        dns_arguments(opts) ++
        reason_arguments(opts) ++
        host_timeout_arguments(opts) ++
        ["-p", Enum.join(first.ports, ","), "-oX", "-"] ++
        Enum.map(entries, & &1.ip)
    else
      {:error, reason} -> raise ArgumentError, "unsafe nmap batch: #{inspect(reason)}"
    end
  end

  defp execute(entries, opts) do
    started_at = DateTime.utc_now()

    case Timeout.run(fn -> run_command(entries, opts, started_at) end, opts[:timeout]) do
      {:ok, {:ok, hosts}} -> {:ok, align_hosts(entries, hosts, started_at)}
      {:ok, {:error, reason}} -> {:error, {:xml_parse_error, reason}}
      {:exit, reason} -> {:error, {:runner_exit, normalize_exit(reason)}}
      :timeout -> {:ok, Enum.map(entries, &outcome_host(&1, :timeout, started_at, :timeout))}
    end
  end

  defp run_command(entries, opts, started_at) do
    runner_opts =
      Keyword.merge(opts[:runner_options],
        stderr: :consume,
        max_chunk_size: opts[:max_chunk_size],
        exit_timeout: opts[:exit_timeout]
      )

    entries
    |> command(opts)
    |> Core.Runner.stream(Keyword.put(runner_opts, :backend, opts[:runner]))
    |> Stream.transform(nil, &stdout_chunk/2)
    |> NmapXML.parse_stream(scanned_at: started_at)
  end

  defp stdout_chunk({:stdout, chunk}, state), do: {[IO.iodata_to_binary(chunk)], state}

  defp stdout_chunk({:stderr, _chunk}, state), do: {[], state}

  defp stdout_chunk(chunk, state), do: {[IO.iodata_to_binary(chunk)], state}

  defp align_hosts(entries, hosts, scanned_at) do
    hosts_by_ip = Map.new(hosts, &{canonical_ip(&1.ip), &1})

    single_host =
      case {entries, hosts} do
        {[_entry], [%Host{ip: nil} = host]} -> host
        _other -> nil
      end

    Enum.map(entries, fn entry ->
      case Map.get(hosts_by_ip, canonical_ip(entry.ip)) || single_host do
        %Host{} = host ->
          %{host | ip: host.ip || entry.ip, meta: Map.put(host.meta, "engine", "nmap")}

        nil ->
          outcome_host(entry, :down, scanned_at, :not_reported_by_nmap)
      end
    end)
  end

  defp outcome_host(entry, status, scanned_at, reason) do
    %Host{
      ip: entry.ip,
      status: status,
      scanned_at: scanned_at,
      meta: %{"engine" => "nmap", "reason" => inspect(reason)}
    }
  end

  defp validate_batch(entries) do
    with :ok <- validate_results(entries) do
      keys = Enum.uniq_by(entries, &{&1.protocol, &1.ports})

      case keys do
        [_one] -> :ok
        _many -> {:error, :batch_requires_identical_ports_and_protocol}
      end
    end
  end

  defp validate_results(entries) do
    if Enum.all?(entries, &valid_result?/1), do: :ok, else: {:error, :invalid_discovery_result}
  end

  defp valid_result?(%Result{} = entry) do
    valid_ip?(entry.ip) and entry.protocol in [:tcp, :udp] and entry.ports != [] and
      Enum.all?(entry.ports, &is_integer/1) and Enum.all?(entry.ports, &(&1 in 1..65_535))
  end

  defp valid_result?(_entry), do: false

  defp valid_ip?(ip) do
    case Portico.Target.parse(ip) do
      {:ok, %Portico.Target{kind: :ip}} -> true
      _other -> false
    end
  end

  defp validate_scan_type([first | _rest], :udp) when first.protocol == :udp, do: :ok

  defp validate_scan_type([first | _rest], scan_type)
       when scan_type in [:connect, :syn] and first.protocol == :tcp, do: :ok

  defp validate_scan_type(_entries, :auto), do: :ok
  defp validate_scan_type(_entries, _scan_type), do: {:error, :scan_type_protocol_mismatch}

  defp effective_scan_type(:auto, :udp), do: :udp
  defp effective_scan_type(:auto, _protocol), do: :connect
  defp effective_scan_type(scan_type, _protocol), do: scan_type

  defp scan_type_argument(:connect), do: "-sT"
  defp scan_type_argument(:syn), do: "-sS"
  defp scan_type_argument(:udp), do: "-sU"

  defp service_arguments(opts) do
    if opts[:service_detection] do
      ["-sV", "--version-intensity", Integer.to_string(opts[:version_intensity])]
    else
      []
    end
  end

  defp os_arguments(opts) do
    if opts[:os_detection], do: ["-O"], else: []
  end

  defp script_arguments(opts) do
    case opts[:scripts] do
      [] -> []
      scripts -> ["--script", Enum.join(scripts, ",")]
    end
  end

  defp timing_arguments(opts), do: ["-T#{opts[:timing_template]}"]

  defp dns_arguments(opts) do
    case opts[:resolve_dns] do
      :never -> ["-n"]
      :always -> ["-R"]
      :default -> []
    end
  end

  defp reason_arguments(opts) do
    if opts[:reason], do: ["--reason"], else: []
  end

  defp host_timeout_arguments(opts) do
    case opts[:host_timeout] do
      :infinity -> []
      timeout -> ["--host-timeout", "#{timeout}ms"]
    end
  end

  defp canonical_ip(nil), do: nil

  defp canonical_ip(ip) do
    case Portico.Target.parse(ip) do
      {:ok, target} -> target.value
      {:error, _reason} -> ip
    end
  end

  defp normalize_exit({exception, stacktrace}) when is_exception(exception) do
    %{
      exception: Exception.message(exception),
      stacktrace: Exception.format_stacktrace(stacktrace)
    }
  end

  defp normalize_exit(reason), do: inspect(reason)
end
