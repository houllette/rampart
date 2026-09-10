# RampartIAST

RampartIAST is Rampart's experimental BEAM trace sensor. Its first validation
action runs one controlled callback in a dedicated process and observes whether
unchanged marker bytes reach a reviewed sink argument.

This package currently proves only **level-1 exact-marker reachability**. It does
not claim transformed-value propagation, cross-process taint, or exploitability.
A completed execution with an intact trace envelope can refute that narrow
claim; any setup, execution, capture, limit, or teardown failure is
inconclusive.

## Contracts

Context providers implement `RampartIAST.ContextProvider` and return inert,
versioned `RampartIAST.Source` and `RampartIAST.Sink` declarations. A validation
subject names declaration IDs. The current host—not a transcript or model—binds
the provider and execution callback.

The initial source envelope is intentionally narrow:

- context: any provider-defined atom;
- boundary: `:in_process`;
- extraction: `%{type: :callback_argument, position: 1}`;
- execution scope: the dedicated callback process only; and
- marker: one non-empty binary `Core.Seed.value`, unchanged either directly or
  inside bounded list, tuple, or map sink arguments.

Sink calls in spawned tasks or other descendants are not observed. A hypothesis
whose metadata requires any scope other than `:single_process` is refused before
callback execution and returns explicit inconclusive evidence.

Providers may also expose reviewed `RampartIAST.StaticCandidate` declarations.
This analyzer-independent seam preserves source spans, analyzer/rule/plugin
provenance, value-versus-control dependence, sanitizer observations, and sink
localization ambiguity without promoting any of them to runtime proof.
`RampartIAST.hypothesis!/4` turns a provider-owned candidate into an inert
hypothesis, and validation resolves the candidate and its declarations again
under current host authority.

RampartSAST owns high-recall source/package inventory and optional syntactic
rule signals. A future separately publishable adapter may turn agent-selected,
reviewed sink facts into these provider declarations; RampartIAST does not
depend on its sister tool, and a broad static fact never configures tracing by
itself.

Static knowledge never changes the exact-marker verdict. A confirmed finding
receives a `sink_source_span` only when the candidate has exactly one sink span
and declares `:unique_static_call_site` or `:instrumented_call_site`.
Ambiguous spans remain in evidence without being attached as the observed
runtime location. Likewise, `:observed` sanitizer status qualifies evidence; it
does not suppress or refute a result.

## Example

```elixir
defmodule Example.Provider do
  @behaviour RampartIAST.ContextProvider

  def context, do: :library

  def sources do
    [
      RampartIAST.Source.new!(
        id: "example.callback-input.v1",
        schema_version: 1,
        context: :library,
        category: :untrusted_input,
        extraction: %{type: :callback_argument, position: 1},
        boundary: :in_process,
        provenance: %{owner: "example"}
      )
    ]
  end

  def sinks do
    [
      RampartIAST.Sink.new!(
        id: "example.consume.v1",
        schema_version: 1,
        context: :library,
        mfa: {Example.Sink, :consume, 1},
        argument_positions: [1],
        category: :sink_reachability,
        sanitizer_expectations: [],
        severity: :info,
        rationale: "example reviewed sink",
        provenance: %{owner: "example"}
      )
    ]
  end

  def candidates do
    span =
      RampartIAST.SourceSpan.new!(
        file: "lib/example/application.ex",
        start_line: 42
      )

    [
      RampartIAST.StaticCandidate.new!(
        id: "example.callback-to-consume.v1",
        schema_version: 1,
        context: :library,
        source_id: "example.callback-input.v1",
        sink_id: "example.consume.v1",
        source_sites: [span],
        sink_sites: [span],
        flow_basis: :value_dependence,
        sanitizer_status: :none_observed,
        localization: :unique_static_call_site,
        provenance:
          RampartIAST.StaticProvenance.new!(
            analyzer: "reach",
            analyzer_version: "2.8.3",
            rule_id: "example.direct-flow",
            source_revision: "replace-with-source-revision",
            plugins: %{"example_context" => "1.0.0"}
          )
      )
    ]
  end
end

seed = %Core.Seed{
  id: "example-seed",
  value: "unique-inert-marker",
  classes: [:untrusted_input],
  provenance: :generated
}

hypothesis =
  RampartIAST.hypothesis!(
    Example.Provider,
    "example.callback-to-consume.v1",
    seed
  )

RampartIAST.validate(hypothesis,
  provider: Example.Provider,
  execute: fn input -> Example.Application.handle(input) end,
  limits: RampartIAST.Limits.new!(timeout_ms: 1_000)
)
```

The result is an ordinary `Core.Validation.Result`. Confirmed results include a
high-confidence finding about exact-marker reachability and an exact replay
seed. `Core.Validation.Wire` omits the marker and native trace details by
default.

## Safety envelope

Each invocation:

- uses an OTP trace session rather than legacy global trace configuration;
- loads one exact sink MFA and traces one execution process;
- bounds wall time, event count, argument bytes, nested argument depth/term
  traversal, and tracer mailbox size;
- waits for the trace-delivery barrier before taking a snapshot;
- stores bounded metadata rather than raw sink arguments; and
- destroys the session after success, callback failure, timeout, limit failure,
  or caller death.

See [RESEARCH.md](RESEARCH.md) and the repository-level
[`IAST_RESEARCH.md`](../../IAST_RESEARCH.md) for the remaining gates.
