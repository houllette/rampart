# IAST sensor research gates

This document fixes the boundary for Rampart's experimental IAST sensor. It is
a gated research plan, not a claim that BEAM tracing provides complete taint
tracking.

## Current implementation

The `apps/rampart_iast` package implements the first single-process,
exact-marker vertical slice behind the versioned
`iast.exact-marker-reaches-sink.v1` validation action. It uses provider-owned
source and sink declarations, optional provider-reviewed static candidates, a
host-owned execution callback, bounded OTP trace sessions, delivery barriers,
exact replay seeds, and fail-closed verdicts.

It remains experimental: transformed values, descendant/cross-process
provenance, broad Phoenix sink knowledge, exploitability, artifact-backed trace
evidence, and measured production safety are not implemented. Exact markers are
now found recursively inside bounded list, tuple, and map arguments, but the
bytes must remain unchanged and the observation is still single-process.

## Goal of the first spike

Given:

- one concrete `%Core.Seed{}` carrying attacker-controlled input;
- one context provider's reviewed source and sink declarations;
- one controlled in-process execution callback; and
- one `%Core.Hypothesis{kind: :taint_reaches_sink}`;

run the callback under targeted instrumentation and return a
`%Core.Validation.Result{}` that confirms only when captured runtime evidence
supports that exact hypothesis. A non-observation is `:refuted` only when the
execution completed and the configured observation envelope was intact;
tracer loss, unsupported code, timeout, or setup failure is `:inconclusive`.

## Verified OTP substrate

The repository pins OTP 29. The installed runtime exposes the session-oriented
`trace` module with `session_create/3`, `session_destroy/1`, `function/4`,
`process/4`, `send/3`, `recv/3`, and `delivered/2`. The spike should use trace
sessions instead of mutating the node's legacy global trace configuration.

A session must still be explicitly bounded:

- trace only the execution process (and explicitly opted-in descendants);
- install patterns only for reviewed sink MFAs;
- bound event count, argument bytes, wall time, and tracer mailbox size;
- tear down the session in `after`; and
- treat dropped events or teardown failure as inconclusive.

Do not use OTP Cover as the sensor. Cover is node-global, changes loaded code,
and reports line execution rather than taint or sink arguments. It remains an
opt-in search fitness source in `havoc_proper`.

## Proposed sensor-owned contracts

These types should live in the future sensor package, not `security_core`:

- **Context provider behaviour:** identifies a context (`:phoenix`,
  `:live_view`, `:nerves`, `:library`, `:otp`) and returns versioned source and
  sink declarations.
- **Source declaration:** extraction rule, boundary semantics, category, and
  provenance for attacker-controlled data.
- **Sink declaration:** MFA and argument positions, vulnerability category,
  sanitizer expectations, severity rationale, and provenance/version of the
  static knowledge.
- **Trace observation:** session ID, process identity, monotonic timestamp, sink
  MFA, bounded argument evidence, and source/sink declaration IDs.

Core owns only the surrounding `%Core.Hypothesis{}` and validation result.
Context providers must be replaceable and independently testable. Sobelow-
derived Phoenix knowledge is one provider, not a hardcoded universal map.

## Taint levels—do not conflate them

The spike must label what it proves:

1. **Exact marker reaches sink:** a unique inert marker is present unchanged in
   a watched sink argument. Strong reachability evidence, but it may miss
   transformed values.
2. **Derived value reaches sink:** an explicit instrumented propagation rule
   links source and sink values. Useful but only as complete as the rule set.
3. **Cross-process propagation:** a provenance edge survives send/receive, ETS,
   process dictionary, or another boundary. Research-only until demonstrated.
4. **Exploitability:** a context oracle demonstrates an unsafe effect. Sink
   reachability alone does not prove exploitability.

Findings and evidence must state the achieved level. A level-1 observation must
never be presented as level 4.

## Dedicated cross-process feasibility spike

Test at least these flows separately:

- direct `send`/`receive` between two processes;
- `GenServer.call` and `GenServer.cast` request paths;
- task handoff;
- ETS write/read with different owners/readers;
- process dictionary storage;
- supervised worker replacement during the trace envelope.

For each, measure event correlation accuracy, dropped-event behavior, memory,
scheduler impact, and false joins under concurrent identical values. Value
equality alone is insufficient when two requests carry the same input. Any
proposal must preserve per-execution provenance without changing application
semantics.

The repository-local boundary matrix now covers direct messages,
`GenServer.call/3`, `GenServer.cast/2`, `Task.async/3`, ETS, and the process
dictionary under the pinned runtime. Eight direct flows from four concurrent
senders deliberately reuse one marker. Unique IDs in the application message
envelope support eight exact send/receive joins with no false joins; removing
those IDs leaves 64 possible value-only pairings and no unique edge. Four
concurrent GenServer calls also join exactly because OTP already carries a
unique alias in every call envelope.

The new cases make their narrower preconditions explicit:

- `GenServer.cast/2` has no native request correlation ID. Four casts join only
  because the fixture already carries a unique application request ID; erasing
  it leaves value-only ambiguity.
- The observed `Task.async/3` implementation exposes its unique task reference
  in both the parent-to-task work message and task-to-owner result, while process
  tracing supplies spawn lineage. This supports the exact Elixir Task protocol
  tested here, not every task/supervisor API or future implementation.
- ETS calls and returns can be correlated across distinct accessors by table,
  unique key, and an ordered interval with no intervening overwrite or delete.
  Reusing a key destroys unique provenance even when the stored marker matches.
- On the pinned runtime, the fixture's targeted `:erlang.get/1` read executes but
  emits no call-trace event. A full `:erlang.get/0` snapshot is observable, but
  capturing an entire process dictionary is too broad a data-handling strategy
  and is deliberately rejected. That boundary remains unresolved.

Adversarial variants now verify those limits instead of only documenting them.
Four identical casts without IDs produce 16 possible send/receive pairings and
no unique edge. Task crash and timeout events remain correlated to task
references but produce inconclusive execution evidence and no value-flow edge.
Four concurrent ETS overwrites identify the winner only while an explicit write
version remains in the stored value; projecting that ID away restores ambiguity,
and deleting the key terminates the edge. An injected missing receive event
keeps the result incomplete even after the trace delivery barrier completes.
Finally, an ordinary permanent-worker restart exposes the old exit and new spawn
but does not transfer process-local state, so provenance terminates at the old
PID.

The frontier probe now distinguishes that terminating case from explicit
external restoration. An independently owned ETS record survives the worker
restart and the replacement can restore one edge only while the application key
and write version are both retained. PID continuity is not used, and projecting
away the version returns the result to `:ambiguous`.

A higher-concurrency pressure case sends 64 explicit envelopes from 16 senders
while 512 unrelated messages stay queued at a selective receiver. Targeted trace
patterns still capture 64 sends, 64 receives, and 64 exact joins with no false
joins. Erasing envelope IDs yields 4,096 value-only candidates and no unique
edge. This is a bounded stress observation, not a production throughput claim.

A two-node handoff case uses one local and one remote trace session, one delivery
barrier per session, and explicit envelope IDs to join four messages. Remote and
local monotonic timestamps are deliberately never ordered against each other.
Distribution is optional in local runs that cannot bind node sockets but is
required in the pinned runtime CI matrix.

Every case reuses identical marker values and refuses to promote equality to
provenance. The matrix is therefore explicitly `:partial`; safe targeted
process-dictionary reads and distributed handoffs without explicit envelopes
remain unresolved. None of these results changes the production validator,
which continues to reject all cross-process-required hypotheses before
execution.

The roadmap must stop at intra-process validation if the remaining spikes cannot
produce reliable edges within the overhead budget. CI now compares the same
semantic checks on OTP 28.3.1/Elixir 1.20.2-otp-28 and OTP 29.0.2/Elixir
1.20.2-otp-29. Runtime timings and reductions are retained as observations;
case/check parity and zero false confirmations are the compatibility gate.

## Static-knowledge extraction requirements

A sink map imported from RampartSAST, Sobelow, or another source needs:

- a stable sink ID and schema version;
- package/tool version and rule provenance;
- MFA plus argument positions and applicable library versions;
- context and vulnerability category;
- sanitizer/guard conditions that suppress or qualify the sink; and
- fixtures for vulnerable, fixed, and ambiguous examples.

Do not scrape human report strings into sensor configuration. Build a reviewed
adapter over structured static knowledge. RampartSAST owns high-recall source
and package inventory, optional syntactic signals, and exact static replay; a
separate adapter must convert agent-selected, qualified sink facts into provider
declarations so neither tool depends on its sister. Broad inventory facts may
be emitted on their own, but IAST
confirmation must point back to the exact sink declaration used.

## Reach 2.8.3 evaluation

Reach's source frontend and program-dependence graph are useful as an optional
**hypothesis generator**, not as an IAST verdict engine. It lowers Elixir source
to expression-level IR, builds per-function control- and data-dependence graphs,
adds call/return summaries and selected OTP/plugin edges, and joins modules into
a project graph with source spans. That can provide candidate source/sink paths,
call-site spans, dependency context, and framework-specific semantics before a
controlled runtime replay.

Its current flow API is too broad for Rampart's trust boundary:
`data_flows?/3` traverses the merged dependence graph rather than a value-only
taint graph, so control dependence can count as flow; def-use resolution can
retain an earlier binding after a later rebinding; and sanitizer reporting asks
whether any node in the source/sink chop matches a sanitizer rather than proving
that every realizable path is sanitized. A traced sink MFA also remains
ambiguous when several static call sites invoke it. These are useful review
leads, but none can confirm, refute, sanitize, or localize a runtime observation
by themselves.

RampartIAST now implements the analyzer-independent half of that boundary.
Providers may expose versioned `StaticCandidate` declarations with bounded
repository-relative `SourceSpan` values, exact `StaticProvenance`, explicit
value/control/mixed dependence, sanitizer observation status, and localization
qualification. `RampartIAST.hypothesis!/4` produces an inert hypothesis from a
reviewed candidate; validation resolves it again under host authority. The
candidate is retained as evidence, but the existing exact-marker action remains
the sole authority for its narrowly stated runtime reachability verdict. A
static span is attached to the confirmed finding only for one uniquely supported
or instrumented sink call site; ambiguous spans remain evidence only.

A Reach-specific integration is still optional and should live in a separately
publishable, version-pinned context-map adapter, never in `security_core` or the
runtime sensor. That adapter should:

- retain Reach version, rule/plugin provenance, source revision, and source span;
- convert only reviewed source/sink candidates into RampartIAST declarations;
- distinguish value dependence from control-only or mixed graph paths;
- treat static sanitizer and path results as qualifications requiring fixtures,
  not as proof or automatic suppression; and
- claim unique localization only with unique call-site evidence or added
  instrumentation.

## Trust and evaluation gates

Before a sensor package is called v1:

- vulnerable examples confirm and fixed examples refute for at least three
  distinct sink classes;
- tracer/oracle failures produce no confirmed finding;
- replay seeds reproduce the same execution setup without a generator;
- evidence identifies source, sink, execution, and observation level;
- trace session cleanup is tested after success, exception, timeout, and owner
  death;
- overhead is measured with tracing disabled, targeted tracing enabled, and a
  deliberately rejected broad configuration; and
- context-provider tests prove a Phoenix assumption cannot leak into OTP,
  Nerves, or plain-library operation.

The repository-local `mix rampart.eval` gate now exercises real
`System.cmd/2`, `:erlang.binary_to_term/2`, `File.write!/2`, and
`Plug.Conn.send_resp/3` boundaries. Checksummed composed cases confirm in
vulnerable executions, refute in patched executions, remain inconclusive on
callback failure, and reproduce verdicts from the same seeds. An ambiguous
static localization remains ambiguous after runtime confirmation. A GenServer
case requires cross-process scope and proves the validator refuses execution
with an explicit inconclusive result. An attributed historical Plug regression
separately demonstrates why an unchanged noisy static candidate needs a concrete
vulnerable/fixed oracle.

The gate also records seven interleaved disabled/targeted samples around a
controlled boundary and rejects a broader process scope before execution. This
is an initial fixed-cost measurement, not production overhead evidence.

This satisfies more of the fixture diversity gate, not the full claim. The Plug
provider is intentionally narrow, the historical case executes an adapted
predicate while statically scanning exact upstream source files rather than a
full application revision, and realistic workload overhead, more cleanup faults,
framework/provider isolation, and reliable cross-process provenance remain
required.

Only after these gates should an external adapter register the sensor validator
as a callable agent tool. It may reuse Core's transport-neutral Binding/Wire
contracts during development, but must not advertise an unvalidated sensor to
Lemieux. Full trace evidence belongs in content-addressed artifacts; the model
sees bounded facts and references.
