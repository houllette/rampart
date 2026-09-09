defmodule Core.TelemetryTest do
  use ExUnit.Case, async: true

  alias Core.{Finding, Telemetry}

  @events [
    [:core, :portico, :scan, :start],
    [:core, :portico, :scan, :stop],
    [:core, :portico, :finding]
  ]

  test "emits conventional spans and findings" do
    handler_id = {__MODULE__, self()}
    :telemetry.attach_many(handler_id, @events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)

    assert :ok =
             Telemetry.span(:portico, :scan, %{target: "192.0.2.1"}, fn ->
               {:ok, %{target: "192.0.2.1", outcome: :ok, finding_count: 1}}
             end)

    finding = %Finding{id: "finding-id", source: :portico, confidence: :high}
    assert :ok = Telemetry.finding(:portico, finding)

    assert_receive {:telemetry, [:core, :portico, :scan, :start], start_measurements,
                    start_metadata}

    assert is_integer(start_measurements.monotonic_time)
    assert start_metadata.target == "192.0.2.1"

    assert_receive {:telemetry, [:core, :portico, :scan, :stop], stop_measurements, stop_metadata}
    assert is_integer(stop_measurements.duration)
    assert stop_metadata.finding_count == 1

    assert_receive {:telemetry, [:core, :portico, :finding], %{}, %{finding: ^finding}}
  end

  test "manual span completion retains start metadata" do
    handler_id = {__MODULE__, self()}
    event = [:core, :portico, :scan, :stop]
    :telemetry.attach(handler_id, event, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)

    span = Telemetry.start_span(:portico, :scan, %{target: "192.0.2.1"})
    assert :ok = Telemetry.stop_span(span, %{outcome: :ok, finding_count: 0})

    assert_receive {:telemetry, ^event, _measurements, metadata}
    assert metadata.target == "192.0.2.1"
    assert metadata.telemetry_span_context == span.context
  end

  @doc false
  def handle_event(event, measurements, metadata, parent) do
    send(parent, {:telemetry, event, measurements, metadata})
  end
end
