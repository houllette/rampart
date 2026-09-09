defmodule Portico.TestBlockingDiscoveryEngine do
  @behaviour Portico.Discovery.Engine

  @impl true
  def option_schema, do: [observer: [type: :pid, required: true]]

  @impl true
  def stream(_target, opts) do
    Stream.resource(
      fn -> :waiting end,
      fn state ->
        send(opts[:observer], {:blocked_reader, self()})

        receive do
          :unblock -> {[], state}
        end
      end,
      fn _state -> :ok end
    )
  end
end

defmodule Portico.PipelineTest do
  use ExUnit.Case, async: false

  alias Portico.Host
  alias Portico.Scope.Allowlist

  test "Broadway topology delivers typed results and emits Core findings" do
    handler_id = {__MODULE__, self()}

    :ok =
      :telemetry.attach_many(
        handler_id,
        [[:core, :portico, :finding], [:core, :portico, :scan, :stop]],
        &__MODULE__.handle_event/4,
        self()
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    scope = Allowlist.new!(["10.0.0.0/24"])

    scan =
      Portico.scan("10.0.0.0/24", scope: scope, scan_id: "broadway-test")
      |> Portico.discover(engine: Portico.TestDiscoveryEngine, observer: self(), count: 3)
      |> Portico.enrich(
        engine: Portico.TestEnrichmentEngine,
        observer: self(),
        max_concurrency: 2,
        host_batch_size: 2,
        batch_timeout: 20
      )

    parent = self()

    pid =
      start_supervised!(
        {Portico.Pipeline,
         scan: scan,
         name: Portico.TestBroadwayPipeline,
         on_result: fn host ->
           send(parent, {:result, host})
           :ok
         end}
      )

    assert Process.alive?(pid)

    assert_receive {:result, %Host{ip: first, status: :up}}, 1_000
    assert_receive {:result, %Host{ip: second, status: :up}}, 1_000
    assert_receive {:result, %Host{ip: third, status: :up}}, 1_000
    assert Enum.sort([first, second, third]) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    for _index <- 1..3 do
      assert_receive {:finding, %Core.Finding{source: :portico}}
    end

    assert :ok = Portico.Pipeline.stop(Portico.TestBroadwayPipeline, 5_000)
    assert_receive {:scan_stopped, %{outcome: :ok, finding_count: 3}}, 1_000
  end

  test "drain stops a discovery reader blocked in an external pull" do
    handler_id = {__MODULE__, self()}

    :ok =
      :telemetry.attach(
        handler_id,
        [:core, :portico, :scan, :stop],
        &__MODULE__.handle_event/4,
        self()
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)
    scope = Allowlist.new!(["10.0.0.0/24"])

    scan =
      Portico.scan("10.0.0.1", scope: scope, scan_id: "drain-test")
      |> Portico.discover(engine: Portico.TestBlockingDiscoveryEngine, observer: self())
      |> Portico.enrich(
        engine: Portico.TestEnrichmentEngine,
        observer: self(),
        max_concurrency: 1,
        batch_timeout: 20
      )

    start_supervised!(
      {Portico.Pipeline,
       scan: scan, name: Portico.TestBlockedBroadwayPipeline, on_result: fn _host -> :ok end}
    )

    assert_receive {:blocked_reader, reader}, 1_000
    monitor = Process.monitor(reader)

    assert :ok = Portico.Pipeline.stop(Portico.TestBlockedBroadwayPipeline, 5_000)
    assert_receive {:DOWN, ^monitor, :process, ^reader, _reason}, 1_000
    assert_receive {:scan_stopped, %{outcome: :cancelled, finding_count: 0}}, 1_000
  end

  @doc false
  def handle_event([:core, :portico, :finding], _measurements, %{finding: finding}, parent) do
    send(parent, {:finding, finding})
  end

  def handle_event([:core, :portico, :scan, :stop], _measurements, metadata, parent) do
    send(parent, {:scan_stopped, metadata})
  end
end
