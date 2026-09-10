# Rampart evaluation

Rampart's evaluation lab is repository-local engineering infrastructure, not a
publishable suite component or an agent harness. It measures whether Rampart can
turn noisy static reconnaissance into a bounded, replayable deterministic
validation without collapsing syntax, reachability, and exploitability into one
score.

Run the current gate with:

```sh
mix rampart.eval
mix rampart.eval --json
mix rampart.eval --json --output tmp/rampart-evaluation.json
mix rampart.eval.compare report-otp-28.json report-otp-29.json
```

`mix precommit` runs the human-readable gate. JSON reports use a versioned,
string-keyed projection and include the exact OTP, ERTS, Elixir, architecture,
and scheduler manifest. They are suitable for retaining benchmark history in
CI. Timing budgets are deliberately broad enough for shared runners; semantic
and fail-closed checks remain strict.

## Current vertical slices

The corpus currently has fourteen cases spanning composed, package, runtime-
measurement, OTP-boundary, and historical tiers.

Five composed cases use checksummed target/dependency workspaces and real, safely
invoked APIs at the observed boundary:

- `System.cmd/2` command arguments;
- `:erlang.binary_to_term/2` deserialization input;
- `File.write!/2` filesystem content;
- an intentionally ambiguous pair of `System.cmd/2` call sites; and
- `Plug.Conn.send_resp/3` through a versioned, reviewed Plug provider.

The first three and the Plug case inventory package ownership, narrow noisy
static candidates, preserve `:unknown` flow basis, confirm exact-marker
reachability in vulnerable executions, refute patched executions, remain
inconclusive on callback failure, and replay from the same seed. Exact markers
may occur inside bounded lists, tuples, or maps; that is still unchanged-value
reachability, not derived taint or exploitability.

The ambiguous command case deliberately retains both source spans. Runtime
observation can confirm the watched MFA and argument, but cannot invent which
static call site executed, so no unique source span is attached.

A targeted-tracing case compares seven interleaved disabled and process-scoped
samples around the same side-effect-free boundary. It records median and p95
latency, reports the observed ratio without treating one machine as a universal
performance claim, and verifies that a broader process-scope request is refused
before execution.

The cross-process feasibility matrix traces eight concurrent direct messages
from four senders carrying the same marker. It joins send/receive events only by
a unique explicit message-envelope ID and produces zero false joins. Erasing
those IDs yields 64 possible value-only pairings and zero uniquely supportable
edges. Four concurrent `GenServer.call/3` requests join by the unique OTP alias
already present in each call envelope.

The matrix also exercises four concurrent flows through additional boundaries:

- `GenServer.cast/2` joins only when the application request already contains a
  unique ID; the native cast envelope supplies none.
- The tested `Task.async/3` protocol joins work and result messages by the task
  reference plus traced spawn lineage. The conclusion is scoped to that Elixir
  implementation rather than generalized to every task API.
- ETS joins writes and reads only by table, unique key, and an overwrite-free
  ordered interval. A reused key remains explicitly ambiguous.
- A targeted process-dictionary read executes but is not visible to call tracing
  on the pinned runtime. Full-dictionary snapshots are visible but rejected as
  an unacceptably broad sensor strategy.

The adversarial half of the matrix checks fail-closed behavior: identical casts
without IDs remain ambiguous; Task crashes and timeouts correlate failure but
never value flow; concurrent ETS overwrites require a stored write version and a
delete terminates the edge; and one deliberately discarded receive event keeps
the result incomplete even though the trace delivery barrier completes. A
permanent supervisor replacement exposes the old worker exit and replacement
spawn, but ordinary process-local state does not cross into the new PID.

The frontier half tests the next boundary conditions without weakening those
rules:

- A replacement worker can restore an edge from an external ETS owner only when
  the stored record retains both the application key and an explicit write
  version. The old and new PIDs are not treated as one process, and projecting
  away the version makes the edge ambiguous again.
- Sixty-four flows from sixteen concurrent senders cross a receiver while 512
  unrelated messages remain queued. Targeted send/receive patterns capture 64
  exact envelope joins and no false joins; value-only matching still has 4,096
  possible pairs and no unique edge.
- A two-node probe uses separate trace sessions and delivery barriers on each
  node to join four distributed messages by explicit envelope ID. It never
  compares timestamps from different nodes. Local evaluation leaves this probe
  optional because some sandboxes cannot bind distribution sockets; the pinned
  runtime CI jobs require it and fail closed if it is unavailable.

The matrix remains explicitly partial and does not make cross-process support
load-bearing. Safe targeted process-dictionary reads and distributed handoffs
without explicit application envelopes remain unresolved. The production
validator still refuses every hypothesis that requires cross-process scope.

A separate GenServer case records the statically visible OTP request and sink
while the bounded source graph honestly lacks a runtime dispatch edge. Its
hypothesis requires cross-process scope. The single-process IAST validator
refuses that action without executing the callback and returns deterministic
inconclusive evidence rather than a false refutation.

The historical tier contains exact, digest-pinned copies of the upstream
`Plug.Static` source file at vulnerable and fixed revisions for the disclosed
null-byte path advisory (CVE-2017-1000052), plus an attributed Apache-2.0 adapted
predicate that can execute on the current toolchain. Static analysis retains the
same high-noise `String.contains?/2` candidate in both snapshots, while the
runtime predicate separately replays the vulnerable/fixed behavior. The full
upstream files also exposed and now regress a nested-module lexical-scope bug in
RampartSAST. This remains a source-file regression fixture, not a claim that the
full historical package revision was executed.

Five additional historical cases graduate representative findings from the
[recent ecosystem CVE primitive review](evaluation/HISTORICAL_CVE_FRONTIER.md)
into executable contracts:

- a terminal byte-safety invariant adapted from CVE-2026-82710, which also
  covers the control-sequence class in CVE-2026-82584;
- a canonical decode/re-encode invariant adapted from CVE-2026-81638;
- parser-backed quoted authentication-parameter integrity over a real Plug
  response, adapted from CVE-2026-82756;
- a two-tenant shared-cache replay with independent uncached Plug controls,
  adapted from CVE-2026-82755; and
- actor-paired protected-field checks across record and aggregate paths, adapted
  from CVE-2026-78216 and the related aggregate-policy class.

All are original reduced predicates rather than copied/full package executions.
Each is pinned to the public vulnerable parent and fix revision. A bounded SAST
expression relationship localizes the hypothesis; optional Plug/Ash classifiers
name the reviewed package boundary; and separately queryable vulnerable/fixed
control facts retain the patch-shaped difference without treating it as a
verdict. The same Havoc oracle then confirms the vulnerable control, refutes the
fixed control, stays inconclusive on injected harness failure, and replays the
same concrete seed. This proves the reusable primitive and its fail-closed
verdict contract, not that Rampart independently rediscovered the advisory or
established every real-world exploit precondition. The remaining review entries
continue to be roadmap evidence.

Across cases, the gate measures inventory, query, graph, artifact, evidence,
atom, memory, and execution characteristics. A runtime confirmation proves only
the action's narrow exact-marker, terminal-byte, canonical-codec, parsed-header,
cache-replay, or actor-paired field-visibility claim.

## Metrics

### Accuracy

The report records structural expectations, explicit ambiguity, vulnerable,
patched, and failure verdicts, replay success, and false confirmations. False
confirmation is the primary hard failure and has a target of zero. Static signal
precision is intentionally not used as a suite-wide score because RampartSAST is
a high-recall reconnaissance engine.

### Efficiency

The report records source/fact counts, scan and graph duration, bounded-query p95,
artifact and model-facing evidence bytes, targeted-trace median/p95 latency,
observational overhead ratio, cross-process probe duration, external-state,
mailbox-pressure, and distributed-probe durations, mailbox reductions, and host
memory/atom deltas. Disposable workers report sampled BEAM memory and atom
counts. On Linux they additionally
report `/proc` RSS/high-water values and, when cgroup v2 files are available,
cgroup current/peak/limit values. CI retains the JSON report so these host-level
measurements can be trended rather than inferred from one local run. The atom
delta from the trusted in-process fixture is observational; the security gate for
untrusted source is the disposable worker test described below.

CI runs the full evaluation with OTP 28.3.1/Elixir 1.20.2-otp-28 and OTP
29.0.2/Elixir 1.20.2-otp-29. `mix rampart.eval.compare` requires every report to
pass with zero false confirmations, verifies identical case IDs and check names,
and rejects duplicate runtime identities. Latency, reductions, and memory remain
per-runtime observations rather than equality gates. The comparison artifact
retains the targeted-trace and cross-process measurements for trend review.

### Usefulness

The report records bounded query count, candidate reduction, graph size and
truncation, compatible proof actions, replayable verdicts, and content-addressed
inventory identity. These metrics ask whether a consumer can investigate with
small evidence pages rather than whether Rampart can print a long report.

## Disposable parsing boundary

`RampartSAST.Isolated` runs discovery, parsing, inventory construction, and
optional rules in a short-lived OS-level BEAM instance. The parent receives only
bounded string-keyed data and does not decode source AST. Tests generate a unique
source identifier and prove it is never interned in the parent VM.

The boundary enforces:

- a worker deadline;
- response, log, nesting, and decoded-term limits;
- a finite worker atom table;
- a default ERTS per-process heap ceiling;
- an executable-free request shape; and
- incomplete results for worker, protocol, and limit failures.

The worker never compiles or executes target code. ERTS heap controls are not a
portable total-RSS or filesystem sandbox, so an outer host must still isolate
filesystem authority and dynamic validation when scanning hostile repositories.
Linux `/proc` and cgroup readings are measurements, not enforcement; their
absence on another OS remains explicit as a missing metric. RampartSAST does not
manage Docker or another deployment sandbox. A multi-tenant service or a harness
that compiles/runs target code owns that outer policy. The portable result
intentionally excludes native source snapshots and findings; a host must retain
or reacquire an authorized exact snapshot before static replay.

## Corpus growth

The corpus has three intended tiers:

1. **Labeled micro-fixtures:** parser, lexical resolution, rebinding, macros,
   callbacks, protocols, OTP boundaries, Mix/Rebar metadata, malformed inputs,
   and limits. Existing ExUnit inventory/graph/scanner tests and metamorphic tests
   form the first tier.
2. **Composed applications:** cross-package source-to-effect chains with
   vulnerable, fixed, ambiguous, package-specific, and unsupported executions.
   The current cases exercise real BEAM/filesystem APIs, one Plug provider,
   targeted tracing overhead, the partial direct-message/GenServer/Task/ETS/
   process-dictionary matrix plus external-state, mailbox-pressure, and
   distributed frontier probes, one explicit unsupported OTP process-scope
   boundary, and five exact vulnerable/fixed Havoc contracts.
3. **Historical cases:** pinned vulnerable and fixed source snapshots from real,
   already-disclosed open-source projects. These include provenance, licensing,
   expected claims, and no evaluation-time network dependency.

The corpus is still deliberately small. Next growth should add full pinned
package/application executions, macro-generated and protocol/callback dispatch,
dependency misuse, executable Phoenix/Ecto/Ash provider fixtures, less cooperative
distributed topologies, sustained pressure/stress runs, and reviewed
differential observations. Historical cases are accepted only after licensing,
revision stability, and disclosure status are reviewed.

## Metamorphic and fault tests

The SAST tests require stable relationship semantics across formatting, comments,
equivalent alias spelling, unrelated definitions, and identical snapshot replay.
The scanner and IAST suites inject malformed source, timeouts, rule/provider
failures, trace delivery loss, event/argument limits, callback exceptions, and
teardown failures.

The invariant is:

> Infrastructure failure may produce incomplete or inconclusive evidence, but
> never confirmation or a false clean result.

## Differential tools

Sobelow, Reach, and Credo are useful comparison instruments, not ground truth:

- Sobelow contributes Phoenix candidate knowledge;
- Reach contributes dependence/path candidates and known over-approximation
  cases; and
- Credo contributes mature source-handling and location behavior.

A future differential corpus should store normalized candidate observations and
reviewed disagreements, never a requirement that Rampart duplicate another
tool's output. Security truth comes from labeled snapshots and deterministic
validation of the exact claim.
