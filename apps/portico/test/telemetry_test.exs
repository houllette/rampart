defmodule Portico.TelemetryTest do
  use ExUnit.Case, async: false

  alias Core.Finding
  alias Portico.Scope.Allowlist

  @events [
    [:core, :portico, :scan, :start],
    [:core, :portico, :scan, :stop],
    [:core, :portico, :enrichment, :start],
    [:core, :portico, :enrichment, :stop],
    [:core, :portico, :finding],
    [:core, :portico, :launch]
  ]

  test "emits shared scan, finding, launch, and stage events" do
    handler_id = {__MODULE__, self()}
    :ok = :telemetry.attach_many(handler_id, @events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)

    scope = Allowlist.new!(["10.0.0.0/24"])

    hosts =
      Portico.scan("10.0.0.1", scope: scope, scan_id: "telemetry-test")
      |> Portico.discover(engine: Portico.TestDiscoveryEngine, observer: self(), count: 1)
      |> Portico.enrich(engine: Portico.TestEnrichmentEngine, observer: self())
      |> Portico.stream()
      |> Enum.to_list()

    assert length(hosts) == 1

    events = collect_events([])

    assert_event(events, [:core, :portico, :scan, :start], fn measurements, metadata ->
      assert is_integer(measurements.monotonic_time)
      assert metadata.target == "10.0.0.1"
    end)

    assert_event(events, [:core, :portico, :scan, :stop], fn measurements, metadata ->
      assert is_integer(measurements.duration)
      assert metadata.target == "10.0.0.1"
      assert metadata.outcome == :ok
      assert metadata.finding_count == 1
    end)

    assert_event(events, [:core, :portico, :finding], fn measurements, metadata ->
      assert measurements == %{}
      assert %Finding{source: :portico, category: :open_port} = metadata.finding
    end)

    assert Enum.count(events, &match?({[:core, :portico, :launch], _, _}, &1)) == 2
    assert Enum.any?(events, &match?({[:core, :portico, :enrichment, :start], _, _}, &1))
    assert Enum.any?(events, &match?({[:core, :portico, :enrichment, :stop], _, _}, &1))
  end

  @doc false
  def handle_event(event, measurements, metadata, parent) do
    send(parent, {:telemetry, event, measurements, metadata})
  end

  defp assert_event(events, expected, assertion) do
    assert {^expected, measurements, metadata} = Enum.find(events, &match?({^expected, _, _}, &1))
    assertion.(measurements, metadata)
  end

  defp collect_events(events) do
    receive do
      {:telemetry, event, measurements, metadata} ->
        collect_events([{event, measurements, metadata} | events])
    after
      0 -> events
    end
  end
end
