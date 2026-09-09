defmodule RampartIAST.ContractsTest do
  use ExUnit.Case, async: true

  alias RampartIAST.{Limits, Sink, Source, SourceSpan, StaticCandidate, StaticProvenance}

  test "source IDs are explicitly versioned" do
    assert_raise ArgumentError, ~r/invalid IAST source/, fn ->
      Source.new!(
        id: "unversioned-source",
        schema_version: 1,
        context: :library,
        category: :untrusted_input,
        extraction: %{type: :callback_argument, position: 1},
        boundary: :in_process,
        provenance: %{}
      )
    end
  end

  test "sink argument positions must exist in the declared MFA" do
    assert_raise ArgumentError, ~r/invalid IAST sink/, fn ->
      Sink.new!(
        id: "test.invalid-position.v1",
        schema_version: 1,
        context: :library,
        mfa: {Enum, :join, 2},
        argument_positions: [3],
        category: :test_sink,
        sanitizer_expectations: [],
        severity: :info,
        rationale: "invalid fixture",
        provenance: %{}
      )
    end
  end

  test "trace limits must remain finite and positive" do
    assert_raise ArgumentError, ~r/invalid IAST limits/, fn ->
      Limits.new!(max_events: 0)
    end
  end

  test "source spans are bounded to repository-relative paths and valid ranges" do
    span =
      SourceSpan.new!(
        file: "apps/example/lib/example.ex",
        start_line: 10,
        start_column: 3,
        end_line: 12,
        end_column: 8
      )

    assert SourceSpan.to_map(span) == %{
             file: "apps/example/lib/example.ex",
             start_line: 10,
             start_column: 3,
             end_line: 12,
             end_column: 8
           }

    for file <- ["/tmp/example.ex", "../example.ex", "apps/example/../secret.ex"] do
      assert_raise ArgumentError, ~r/invalid IAST source span/, fn ->
        SourceSpan.new!(file: file, start_line: 1)
      end
    end
  end

  test "static provenance requires reproducible analyzer identity" do
    assert_raise ArgumentError, ~r/invalid IAST static provenance/, fn ->
      StaticProvenance.new!(
        analyzer: "reach",
        analyzer_version: "",
        rule_id: "example.rule",
        source_revision: "abc123"
      )
    end
  end

  test "static candidate localization cannot claim uniqueness for several sink sites" do
    assert_raise ArgumentError, ~r/invalid IAST static candidate/, fn ->
      static_candidate(
        sink_sites: [span(20), span(30)],
        localization: :unique_static_call_site
      )
    end
  end

  test "static candidate evidence preserves dependence and sanitizer qualifications" do
    candidate =
      static_candidate(
        sink_sites: [span(20), span(30)],
        flow_basis: :control_dependence,
        sanitizer_status: :observed,
        localization: :ambiguous
      )

    projection = StaticCandidate.to_map(candidate)

    assert projection.flow_basis == :control_dependence
    assert projection.sanitizer_status == :observed
    assert projection.localization == :ambiguous
    assert length(projection.sink_sites) == 2
  end

  defp static_candidate(overrides) do
    attributes =
      [
        id: "example.static-flow.v1",
        schema_version: 1,
        context: :library,
        source_id: "example.source.v1",
        sink_id: "example.sink.v1",
        source_sites: [span(10)],
        sink_sites: [span(20)],
        flow_basis: :value_dependence,
        sanitizer_status: :none_observed,
        localization: :unique_static_call_site,
        provenance:
          StaticProvenance.new!(
            analyzer: "reach",
            analyzer_version: "2.8.3",
            rule_id: "example.rule",
            source_revision: "abc123"
          )
      ]
      |> Keyword.merge(overrides)

    StaticCandidate.new!(attributes)
  end

  defp span(line) do
    SourceSpan.new!(file: "apps/example/lib/example.ex", start_line: line)
  end
end
