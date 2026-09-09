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
- marker: one non-empty binary `Core.Seed.value`.

Sink calls in spawned tasks or other descendants are not observed.

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
end

marker = "unique-inert-marker"

hypothesis = %Core.Hypothesis{
  id: "example-hypothesis",
  source: :iast,
  kind: :taint_reaches_sink,
  claim: "the callback input reaches example.consume.v1 unchanged",
  locus: %{
    context: :library,
    source_id: "example.callback-input.v1",
    sink_id: "example.consume.v1"
  },
  seed: %Core.Seed{
    id: "example-seed",
    value: marker,
    classes: [:untrusted_input],
    provenance: :generated
  },
  meta: %{observation_level: :exact_marker}
}

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
- bounds wall time, event count, argument bytes, and tracer mailbox size;
- waits for the trace-delivery barrier before taking a snapshot;
- stores bounded metadata rather than raw sink arguments; and
- destroys the session after success, callback failure, timeout, limit failure,
  or caller death.

See [RESEARCH.md](RESEARCH.md) and the repository-level
[`IAST_RESEARCH.md`](../../IAST_RESEARCH.md) for the remaining gates.
