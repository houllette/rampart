defmodule Portico.Pipeline do
  @moduledoc """
  Supervised Broadway topology for advanced embedding scenarios.

  `:on_result` is synchronous and therefore participates in backpressure. A
  slow persistence callback slows enrichment, which reduces producer demand and
  eventually stops reads from the discovery scanner.
  """

  @behaviour Broadway

  alias Broadway.Message
  alias Portico.Discovery.Producer
  alias Portico.Enrichment.Stage, as: EnrichmentStage
  alias Portico.{Runtime, Sink}

  @doc "Starts an authorized Broadway scan pipeline."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    scan = Keyword.fetch!(opts, :scan)
    name = Keyword.get(opts, :name, __MODULE__)
    sink = Keyword.fetch!(opts, :on_result)
    shutdown = Keyword.get(opts, :shutdown, default_shutdown(scan))

    Runtime.validate!(scan)

    Core.Scope.ensure_all_authorized!(scan.targets, scan.scope)
    finding_counter = :counters.new(1, [:write_concurrency])
    discovery_status = :atomics.new(1, [])
    target = telemetry_target(scan)
    scan_span = Core.Telemetry.start_span(:portico, :scan, %{target: target})

    result =
      Broadway.start_link(__MODULE__,
        name: name,
        shutdown: shutdown,
        max_restarts: 0,
        context: %{scan: scan, sink: sink, finding_counter: finding_counter},
        producer: producer_options(scan, discovery_status),
        processors: [
          default: [
            concurrency: 1,
            min_demand: 0,
            max_demand: max(scan.host_batch_size * scan.max_concurrency, 1)
          ]
        ],
        batchers: [
          default: [
            concurrency: scan.max_concurrency,
            batch_size: scan.host_batch_size,
            batch_timeout: max(scan.batch_timeout, 1)
          ]
        ]
      )

    track_scan(result, scan_span, finding_counter, discovery_status, target)
  end

  @doc "Returns a supervisor child specification with sufficient drain grace."
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    scan = Keyword.fetch!(opts, :scan)

    %{
      id: Keyword.get(opts, :name, __MODULE__),
      start: {__MODULE__, :start_link, [opts]},
      shutdown: Keyword.get(opts, :shutdown, default_shutdown(scan))
    }
  end

  @doc "Gracefully drains and stops a named Broadway pipeline."
  @spec stop(Broadway.name(), timeout()) :: :ok
  def stop(name, timeout \\ :infinity), do: Broadway.stop(name, :normal, timeout)

  @impl Broadway
  def handle_message(_processor, %Message{data: result} = message, _context) do
    message
    |> Message.put_batcher(:default)
    |> Message.put_batch_key({result.protocol, result.ports})
  end

  @impl Broadway
  def handle_batch(:default, messages, _batch_info, %{
        scan: scan,
        sink: sink,
        finding_counter: finding_counter
      }) do
    entries = Enum.map(messages, & &1.data)
    {:ok, hosts} = EnrichmentStage.run(entries, scan)

    Enum.each(hosts, fn host ->
      findings = Portico.Finding.emit(host)
      :counters.add(finding_counter, 1, length(findings))
      Sink.deliver(sink, host)
    end)

    Enum.zip_with(messages, hosts, fn message, host ->
      Message.put_data(message, host)
    end)
  end

  defp producer_options(scan, discovery_status) do
    producer_opts = [scan: scan, discovery_status: discovery_status]
    options = [module: {Producer, producer_opts}, concurrency: 1]

    case scan.rate_limit do
      nil -> options
      rate_limit -> Keyword.put(options, :rate_limiting, Map.to_list(rate_limit))
    end
  end

  defp track_scan(
         {:ok, pipeline} = result,
         scan_span,
         finding_counter,
         discovery_status,
         target
       ) do
    {:ok, _tracker} =
      Task.Supervisor.start_child(Portico.TaskSupervisor, fn ->
        monitor = Process.monitor(pipeline)

        receive do
          {:DOWN, ^monitor, :process, ^pipeline, reason} ->
            complete_scan(scan_span, finding_counter, discovery_status, target, reason)
        end
      end)

    result
  end

  defp track_scan({:error, reason} = result, scan_span, finding_counter, _status, target) do
    Core.Telemetry.exception_span(scan_span, :error, reason, [], %{
      target: target,
      outcome: :error,
      finding_count: :counters.get(finding_counter, 1)
    })

    result
  end

  defp track_scan(:ignore, scan_span, finding_counter, _status, target) do
    Core.Telemetry.stop_span(scan_span, %{
      target: target,
      outcome: :cancelled,
      finding_count: :counters.get(finding_counter, 1)
    })

    :ignore
  end

  defp complete_scan(scan_span, finding_counter, discovery_status, target, reason) do
    metadata = %{
      target: target,
      outcome: scan_outcome(reason, discovery_status),
      finding_count: :counters.get(finding_counter, 1)
    }

    if normal_exit?(reason) do
      Core.Telemetry.stop_span(scan_span, metadata)
    else
      Core.Telemetry.exception_span(scan_span, :exit, reason, [], metadata)
    end
  end

  defp scan_outcome(reason, discovery_status) do
    cond do
      not normal_exit?(reason) -> :error
      :atomics.get(discovery_status, 1) == 1 -> :ok
      true -> :cancelled
    end
  end

  defp normal_exit?(reason), do: reason in [:normal, :shutdown] or match?({:shutdown, _}, reason)

  defp telemetry_target(scan) do
    case Enum.map(scan.targets, & &1.value) do
      [target] -> target
      targets -> targets
    end
  end

  defp default_shutdown(scan) do
    case scan.enrichment.opts[:timeout] do
      timeout when is_integer(timeout) -> timeout + 5_000
      _other -> 125_000
    end
  end
end
