defmodule ForayTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Core.Scope.Error
  alias Foray.Scope.Allowlist

  test "high-level stream is lazy and bounds whole-job concurrency" do
    scope = Allowlist.new!(["https://*.example/"])

    stream =
      Foray.target(
        ["https://one.example", "https://two.example", "https://three.example"],
        scope: scope
      )
      |> Foray.fuzz_path(wordlist: "paths.txt")
      |> Foray.rate(requests_per_second: 20, max_jobs: 2)
      |> Foray.engine(Foray.TestEngine, observer: self(), block: true)
      |> Foray.stream()

    refute_receive {:job_started, _worker, _job_id}
    consumer = Task.async(fn -> Enum.take(stream, 1) end)

    assert_receive {:job_started, first_worker, _job_id}
    assert_receive {:job_started, second_worker, _job_id}
    refute_receive {:job_started, _third_worker, _job_id}, 50

    send(first_worker, :release)
    send(second_worker, :release)
    assert [%Core.Finding{source: :foray}] = Task.await(consumer, 2_000)
  end

  test "consumer owner death tears down the dynamically started pipeline" do
    scope = Allowlist.new!(["https://app.example/"])
    registrations_before = Registry.count(Foray.Registry)

    stream =
      Foray.target("https://app.example", scope: scope)
      |> Foray.fuzz_path(wordlist: "paths.txt")
      |> Foray.engine(Foray.TestEngine, observer: self(), block: true)
      |> Foray.stream()

    capture_log(fn ->
      consumer = Task.async(fn -> Enum.to_list(stream) end)
      assert_receive {:job_started, _worker, _job_id}
      assert Task.shutdown(consumer, :brutal_kill) == nil
      assert_receive {:job_stopped, _job_id}, 2_000
      assert eventually(fn -> Registry.count(Foray.Registry) == registrations_before end, 2_000)
    end)
  end

  test "authorizes every job before any engine starts" do
    scope = Allowlist.new!(["https://one.example/"])

    stream =
      Foray.target(["https://one.example", "https://two.example"], scope: scope)
      |> Foray.fuzz_path(wordlist: "paths.txt")
      |> Foray.engine(Foray.TestEngine, observer: self())
      |> Foray.stream()

    assert_raise Error, fn -> Enum.to_list(stream) end
    refute_receive {:job_started, _worker, _job_id}
  end

  test "emits shared job, launch, and finding telemetry" do
    events = [
      [:core, :foray, :job, :start],
      [:core, :foray, :job, :stop],
      [:core, :foray, :finding],
      [:core, :foray, :launch]
    ]

    handler_id = {__MODULE__, self()}
    :ok = :telemetry.attach_many(handler_id, events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)

    findings =
      Foray.target("https://app.example", scope: Allowlist.new!(["https://app.example/"]))
      |> Foray.fuzz_path(wordlist: "paths.txt")
      |> Foray.engine(Foray.TestEngine, observer: self())
      |> Foray.stream()
      |> Enum.to_list()

    assert [_finding] = findings
    received = collect_events([])

    for expected <- events do
      assert Enum.any?(received, &match?({^expected, _, _}, &1))
    end

    assert {_, _, stop_metadata} =
             Enum.find(received, &match?({[:core, :foray, :job, :stop], _, _}, &1))

    assert stop_metadata.outcome == :ok
    assert stop_metadata.finding_count == 1
  end

  test "a rejected synchronous audit hook prevents launch telemetry and engine execution" do
    event = [:core, :foray, :launch]
    handler_id = {__MODULE__, :audit_rejection, self()}
    :ok = :telemetry.attach(handler_id, event, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)

    stream =
      Foray.target("https://app.example",
        scope: Allowlist.new!(["https://app.example/"]),
        audit: fn _event, _metadata -> :denied end
      )
      |> Foray.fuzz_path(wordlist: "paths.txt")
      |> Foray.engine(Foray.TestEngine, observer: self())
      |> Foray.stream()

    assert_raise Foray.PipelineError, fn -> Enum.to_list(stream) end
    refute_receive {:job_started, _worker, _job_id}
    refute_receive {:telemetry, ^event, _measurements, _metadata}
  end

  test "promotes findings into corpus seeds with a stable origin" do
    finding = %Core.Finding{id: "foray:finding", source: :foray}
    seed = Foray.promote(finding, "' OR 1=1 --", classes: [:sqli])

    assert seed.provenance == :promoted_finding
    assert seed.origin == {:foray, "foray:finding"}
    assert seed.classes == [:sqli]
  end

  @doc false
  def handle_event(event, measurements, metadata, parent) do
    send(parent, {:telemetry, event, measurements, metadata})
  end

  defp eventually(predicate, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    eventually_until(predicate, deadline)
  end

  defp eventually_until(predicate, deadline) do
    cond do
      predicate.() ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        Process.sleep(20)
        eventually_until(predicate, deadline)
    end
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
