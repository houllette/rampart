defmodule RampartIAST.ValidationTest do
  use ExUnit.Case, async: false

  alias Core.Validation.{Result, Wire}

  alias RampartIAST.{
    AmbiguousProvider,
    DeliveryFailureBackend,
    Limits,
    StaticFixture,
    TeardownFailureBackend,
    TestProvider,
    TestSink,
    UntraceableProvider
  }

  test "advertises a hypothesis-only exact-marker validation action" do
    assert [action] = RampartIAST.validation_actions()

    assert action.id == "iast.exact-marker-reaches-sink.v1"
    assert action.accepts == [:hypothesis]
    assert action.side_effects == :test_execution
    assert action.meta.observation_level == :exact_marker
    assert action.meta.process_scope == :single_process
  end

  test "builds an inert hypothesis from a provider-reviewed static candidate" do
    seed = seed()

    hypothesis =
      RampartIAST.hypothesis!(TestProvider, "test.callback-to-consume.v1", seed)

    assert hypothesis.source == :iast
    assert hypothesis.kind == :taint_reaches_sink
    assert hypothesis.seed == seed
    assert hypothesis.locus.context == :library
    assert hypothesis.locus.source_id == "test.callback-argument.v1"
    assert hypothesis.locus.sink_id == "test.consume.v1"
    assert hypothesis.locus.static_candidate_id == "test.callback-to-consume.v1"
    assert hypothesis.meta.observation_level == :exact_marker
    assert hypothesis.meta.static_candidate_id == "test.callback-to-consume.v1"
  end

  test "confirms a static candidate with provenance and qualified unique localization" do
    hypothesis =
      RampartIAST.hypothesis!(TestProvider, "test.callback-to-consume.v1", seed())

    assert %Result{
             verdict: :confirmed,
             findings: [finding],
             evidence: evidence,
             meta: meta
           } =
             result =
             RampartIAST.validate(hypothesis,
               provider: TestProvider,
               execute: &StaticFixture.direct/1
             )

    assert finding.locus.static_candidate_id == "test.callback-to-consume.v1"
    assert finding.locus.static_flow_basis == :value_dependence
    assert finding.locus.static_sanitizer_status == :none_observed
    assert finding.locus.sink_localization_basis == :unique_static_call_site
    assert finding.locus.static_sink_candidate_count == 1

    assert finding.locus.sink_source_span.file ==
             "apps/rampart_iast/test/support/fixture.ex"

    assert evidence.facts.static_candidate.provenance.analyzer == "reach"
    assert evidence.facts.static_candidate.provenance.analyzer_version == "2.8.3"
    assert evidence.facts.static_candidate.flow_basis == :value_dependence
    assert meta.static_candidate_id == "test.callback-to-consume.v1"
    assert meta.static_localization == :unique_static_call_site

    projection = Wire.result(result)
    encoded = Wire.encode!(projection)

    assert projection["evidence"]["facts"]["static_candidate"]["provenance"]["analyzer"] ==
             "reach"

    refute encoded =~ hypothesis.seed.value
  end

  test "does not attach a static span when a runtime sink has ambiguous call sites" do
    hypothesis =
      RampartIAST.hypothesis!(AmbiguousProvider, "test.ambiguous-consume.v1", seed())

    assert %Result{verdict: :confirmed, findings: [finding], evidence: evidence, meta: meta} =
             RampartIAST.validate(hypothesis,
               provider: AmbiguousProvider,
               execute: fn marker -> StaticFixture.ambiguous(marker, true) end
             )

    assert finding.locus.sink_localization_basis == :ambiguous
    assert finding.locus.static_sink_candidate_count == 2
    assert finding.locus.static_flow_basis == :mixed_dependence
    assert finding.locus.static_sanitizer_status == :observed
    refute Map.has_key?(finding.locus, :sink_source_span)

    assert evidence.facts.static_candidate.localization == :ambiguous
    assert length(evidence.facts.static_candidate.sink_sites) == 2
    assert meta.static_localization == :ambiguous
  end

  test "re-resolves static candidate declarations before executing" do
    hypothesis =
      TestProvider
      |> RampartIAST.hypothesis!("test.callback-to-consume.v1", seed())
      |> put_in([Access.key!(:locus), Access.key!(:source_id)], "transcript.supplied.v1")

    test_process = self()

    assert_raise ArgumentError, ~r/does not match the hypothesis declarations/, fn ->
      RampartIAST.validate(hypothesis,
        provider: TestProvider,
        execute: fn marker -> send(test_process, {:executed, marker}) end
      )
    end

    refute_receive {:executed, _marker}
  end

  test "confirms when the unchanged marker reaches the watched sink argument" do
    hypothesis = hypothesis()

    assert %Result{verdict: :confirmed, findings: [finding], evidence: evidence, seed: seed} =
             RampartIAST.validate(hypothesis,
               provider: TestProvider,
               execute: &TestSink.consume/1
             )

    assert finding.source == :iast
    assert finding.category == :test_sink_reachability
    assert finding.confidence == :high
    assert finding.seed == seed
    assert finding.locus.observation_level == :exact_marker
    assert finding.locus.source_id == "test.callback-argument.v1"
    assert finding.locus.sink_id == "test.consume.v1"
    assert evidence.facts.observation_level == :exact_marker
    assert evidence.facts.matched_event_count == 1
    assert evidence.facts.trace_envelope == :intact
    assert seed.value == hypothesis.seed.value
    assert :exact_marker in seed.classes
  end

  test "recognizes unchanged marker bytes embedded in a larger binary" do
    hypothesis = hypothesis()

    assert %Result{verdict: :confirmed} =
             RampartIAST.validate(hypothesis,
               provider: TestProvider,
               execute: fn marker -> TestSink.consume("prefix:" <> marker <> ":suffix") end
             )
  end

  test "refutes only after a complete execution and intact trace envelope" do
    assert %Result{verdict: :refuted, findings: [], evidence: evidence} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               execute: fn _marker -> :completed_without_sink end
             )

    assert evidence.facts.execution == :completed
    assert evidence.facts.trace_envelope == :intact
    assert evidence.facts.event_count == 0
  end

  test "refutes an exact-marker claim when the sink receives another value" do
    assert %Result{verdict: :refuted, evidence: evidence} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               execute: fn _marker -> TestSink.consume("different") end
             )

    assert evidence.facts.event_count == 1
    assert evidence.facts.matched_event_count == 0
  end

  test "does not trace sink calls made by an unconfigured descendant" do
    assert %Result{verdict: :refuted, evidence: evidence} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               execute: fn marker ->
                 task = Task.async(fn -> TestSink.consume(marker) end)
                 Task.await(task)
               end
             )

    assert evidence.facts.event_count == 0
    assert evidence.facts.process_scope == :single_process
  end

  test "concurrent sessions remain isolated by execution process" do
    marker = "shared-but-process-scoped-marker"

    results =
      1..5
      |> Task.async_stream(
        fn index ->
          hypothesis = put_in(hypothesis().seed.value, marker)

          execute =
            if index == 5,
              do: fn _input -> :no_sink_call end,
              else: &TestSink.consume/1

          {index,
           RampartIAST.validate(hypothesis,
             provider: TestProvider,
             execute: execute
           )}
        end,
        max_concurrency: 5,
        ordered: false
      )
      |> Enum.map(fn {:ok, result} -> result end)
      |> Map.new()

    assert results[5].verdict == :refuted
    assert Enum.all?(1..4, &(results[&1].verdict == :confirmed))
  end

  test "returns inconclusive when the execution callback raises" do
    baseline = sink_sessions()

    assert %Result{verdict: :inconclusive, evidence: evidence} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               execute: fn _marker -> raise "fixture failed" end
             )

    assert evidence.facts.trace_envelope == :incomplete
    assert evidence.facts.execution == :callback_failed
    assert evidence.summary =~ "could not decide"
    assert sink_sessions() == baseline
  end

  test "returns inconclusive when execution exceeds its deadline" do
    baseline = sink_sessions()

    assert %Result{verdict: :inconclusive, evidence: evidence} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               limits: Limits.new!(timeout_ms: 20),
               execute: fn _marker -> Process.sleep(:infinity) end
             )

    assert evidence.facts.execution == :timeout
    assert evidence.facts.trace_envelope == :incomplete
    assert sink_sessions() == baseline
  end

  test "returns inconclusive when the event limit is exceeded" do
    assert %Result{verdict: :inconclusive, evidence: evidence} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               limits: Limits.new!(max_events: 1),
               execute: fn marker ->
                 TestSink.consume(marker)
                 TestSink.consume(marker)
               end
             )

    assert :event_limit in evidence.facts.limit_failures
    assert evidence.facts.event_count == 2
    assert evidence.facts.trace_envelope == :incomplete
  end

  test "returns inconclusive instead of inspecting an oversized sink argument" do
    assert %Result{verdict: :inconclusive, evidence: evidence} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               limits: Limits.new!(max_argument_bytes: 16),
               execute: fn marker -> TestSink.consume(marker <> String.duplicate("x", 100)) end
             )

    assert :argument_bytes in evidence.facts.limit_failures
    assert evidence.facts.trace_envelope == :incomplete
  end

  test "returns inconclusive when the declared sink cannot be traced" do
    hypothesis = put_in(hypothesis().locus.sink_id, "test.missing.v1")

    assert %Result{verdict: :inconclusive, evidence: evidence} =
             RampartIAST.validate(hypothesis,
               provider: UntraceableProvider,
               execute: &TestSink.consume/1
             )

    assert evidence.facts.execution == :setup_failed
    assert evidence.facts.reason == :setup_failed
  end

  test "resolves inert declaration IDs from the host-selected provider" do
    hypothesis = put_in(hypothesis().locus.sink_id, "transcript.supplied.v1")
    test_process = self()

    assert_raise ArgumentError, ~r/unknown IAST sink/, fn ->
      RampartIAST.validate(hypothesis,
        provider: TestProvider,
        execute: fn marker -> send(test_process, {:executed, marker}) end
      )
    end

    refute_receive {:executed, _marker}
  end

  test "the transcript-safe projection excludes marker and native trace details" do
    hypothesis = hypothesis()

    result =
      RampartIAST.validate(hypothesis,
        provider: TestProvider,
        execute: &TestSink.consume/1
      )

    projection = Wire.result(result)
    encoded = Wire.encode!(projection)

    refute encoded =~ hypothesis.seed.value
    refute Map.has_key?(projection["evidence"], "raw")
    assert projection["seed"]["value_included"] == false
    assert projection["evidence"]["facts"]["observation_level"] == "exact_marker"
  end

  test "a missing delivery barrier prevents a captured marker from becoming confirmation" do
    assert %Result{verdict: :inconclusive, findings: [], evidence: evidence} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               limits: Limits.new!(delivery_timeout_ms: 20),
               trace_backend: DeliveryFailureBackend,
               execute: &TestSink.consume/1
             )

    assert evidence.facts.trace_envelope == :incomplete
    assert evidence.facts.reason == :trace_capture_failed
  end

  test "a teardown failure prevents a captured marker from becoming confirmation" do
    assert %Result{verdict: :inconclusive, findings: [], evidence: evidence} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               trace_backend: TeardownFailureBackend,
               execute: &TestSink.consume/1
             )

    assert evidence.facts.trace_envelope == :incomplete
    assert evidence.facts.teardown == :failed
  end

  test "destroys its trace session after a completed validation" do
    baseline = sink_sessions()

    assert %Result{} =
             RampartIAST.validate(hypothesis(),
               provider: TestProvider,
               execute: &TestSink.consume/1
             )

    assert sink_sessions() == baseline
  end

  test "the session owner cleans up when its caller dies" do
    baseline = sink_sessions()
    test_process = self()

    caller =
      spawn(fn ->
        RampartIAST.validate(hypothesis(),
          provider: TestProvider,
          limits: Limits.new!(timeout_ms: 5_000),
          execute: fn _marker ->
            send(test_process, {:execution_started, self()})
            Process.sleep(:infinity)
          end
        )
      end)

    assert_receive {:execution_started, tracee}, 1_000
    assert eventually(fn -> sink_sessions() != baseline end)

    monitor = Process.monitor(caller)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^caller, :killed}, 1_000

    assert eventually(fn -> sink_sessions() == baseline end)
    assert eventually(fn -> not Process.alive?(tracee) end)
  end

  test "rejects hypotheses that do not declare the exact-marker proof level" do
    hypothesis = put_in(hypothesis().meta.observation_level, :derived_value)

    assert_raise ArgumentError, ~r/exact-marker observation level/, fn ->
      RampartIAST.validate(hypothesis,
        provider: TestProvider,
        execute: &TestSink.consume/1
      )
    end
  end

  defp hypothesis do
    %Core.Hypothesis{
      id: "hypothesis-#{System.unique_integer([:positive, :monotonic])}",
      source: :iast,
      kind: :taint_reaches_sink,
      claim: "the callback argument reaches the test sink unchanged",
      locus: %{
        context: :library,
        source_id: "test.callback-argument.v1",
        sink_id: "test.consume.v1"
      },
      seed: seed(),
      meta: %{observation_level: :exact_marker}
    }
  end

  defp seed do
    %Core.Seed{
      id: "seed-#{System.unique_integer([:positive, :monotonic])}",
      value: "rampart-iast-marker-#{System.unique_integer([:positive, :monotonic])}",
      classes: [:untrusted_input],
      provenance: :generated
    }
  end

  defp sink_sessions do
    case :trace.session_info({TestSink, :consume, 1}) do
      :undefined -> []
      sessions -> sessions
    end
  end

  defp eventually(fun, attempts \\ 100)

  defp eventually(fun, attempts) when attempts > 0 do
    if fun.() do
      true
    else
      Process.sleep(10)
      eventually(fun, attempts - 1)
    end
  end

  defp eventually(_fun, 0), do: false
end
