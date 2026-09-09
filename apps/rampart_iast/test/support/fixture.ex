defmodule RampartIAST.TestSink do
  @moduledoc false

  def consume(value), do: value
end

defmodule RampartIAST.StaticFixture do
  @moduledoc false

  alias RampartIAST.TestSink

  def direct(value), do: TestSink.consume(value)

  def ambiguous(value, true), do: TestSink.consume(value)
  def ambiguous(value, false), do: TestSink.consume(value)
end

defmodule RampartIAST.TestProvider do
  @moduledoc false
  @behaviour RampartIAST.ContextProvider

  @impl true
  def context, do: :library

  @impl true
  def sources do
    [
      RampartIAST.Source.new!(
        id: "test.callback-argument.v1",
        schema_version: 1,
        context: :library,
        category: :untrusted_input,
        extraction: %{type: :callback_argument, position: 1},
        boundary: :in_process,
        provenance: %{origin: :test_fixture}
      )
    ]
  end

  @impl true
  def sinks do
    [
      RampartIAST.Sink.new!(
        id: "test.consume.v1",
        schema_version: 1,
        context: :library,
        mfa: {RampartIAST.TestSink, :consume, 1},
        argument_positions: [1],
        category: :test_sink_reachability,
        sanitizer_expectations: [],
        severity: :medium,
        rationale: "test fixture sink",
        provenance: %{origin: :test_fixture}
      )
    ]
  end

  @impl true
  def candidates do
    [
      RampartIAST.StaticCandidate.new!(
        id: "test.callback-to-consume.v1",
        schema_version: 1,
        context: :library,
        source_id: "test.callback-argument.v1",
        sink_id: "test.consume.v1",
        source_sites: [span(12)],
        sink_sites: [span(12)],
        flow_basis: :value_dependence,
        sanitizer_status: :none_observed,
        localization: :unique_static_call_site,
        provenance:
          RampartIAST.StaticProvenance.new!(
            analyzer: "reach",
            analyzer_version: "2.8.3",
            rule_id: "fixture.direct-value-flow",
            source_revision: "fixture-revision",
            plugins: %{"fixture_context" => "1.0.0"}
          )
      )
    ]
  end

  defp span(line) do
    RampartIAST.SourceSpan.new!(
      file: "apps/rampart_iast/test/support/fixture.ex",
      start_line: line
    )
  end
end

defmodule RampartIAST.AmbiguousProvider do
  @moduledoc false
  @behaviour RampartIAST.ContextProvider

  alias RampartIAST.{SourceSpan, StaticCandidate, TestProvider}

  @impl true
  defdelegate context(), to: TestProvider

  @impl true
  defdelegate sources(), to: TestProvider

  @impl true
  defdelegate sinks(), to: TestProvider

  @impl true
  def candidates do
    [candidate] = TestProvider.candidates()

    [
      candidate
      |> Map.merge(%{
        id: "test.ambiguous-consume.v1",
        sink_sites: [span(14), span(15)],
        flow_basis: :mixed_dependence,
        sanitizer_status: :observed,
        localization: :ambiguous
      })
      |> StaticCandidate.validate!()
    ]
  end

  defp span(line) do
    SourceSpan.new!(
      file: "apps/rampart_iast/test/support/fixture.ex",
      start_line: line
    )
  end
end

defmodule RampartIAST.UntraceableProvider do
  @moduledoc false
  @behaviour RampartIAST.ContextProvider

  @impl true
  def context, do: :library

  @impl true
  def sources, do: RampartIAST.TestProvider.sources()

  @impl true
  def sinks do
    [
      RampartIAST.Sink.new!(
        id: "test.missing.v1",
        schema_version: 1,
        context: :library,
        mfa: {RampartIAST.MissingSink, :consume, 1},
        argument_positions: [1],
        category: :test_sink_reachability,
        sanitizer_expectations: [],
        severity: :medium,
        rationale: "missing test sink",
        provenance: %{origin: :test_fixture}
      )
    ]
  end
end

defmodule RampartIAST.DeliveryFailureBackend do
  @moduledoc false
  @behaviour RampartIAST.TraceBackend

  alias RampartIAST.TraceBackend.OTP

  @impl true
  defdelegate session_create(name, tracer, opts), to: OTP

  @impl true
  defdelegate function(session, mfa, match_spec, flags), to: OTP

  @impl true
  defdelegate process(session, tracee, enabled, flags), to: OTP

  @impl true
  def delivered(_session, _tracee), do: make_ref()

  @impl true
  defdelegate session_destroy(session), to: OTP
end

defmodule RampartIAST.TeardownFailureBackend do
  @moduledoc false
  @behaviour RampartIAST.TraceBackend

  alias RampartIAST.TraceBackend.OTP

  @impl true
  defdelegate session_create(name, tracer, opts), to: OTP

  @impl true
  defdelegate function(session, mfa, match_spec, flags), to: OTP

  @impl true
  defdelegate process(session, tracee, enabled, flags), to: OTP

  @impl true
  defdelegate delivered(session, tracee), to: OTP

  @impl true
  def session_destroy(session) do
    _destroyed? = OTP.session_destroy(session)
    false
  end
end
