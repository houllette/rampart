# Rampart north-star architecture

## BEAM-native deterministic analysis for agent-driven vulnerability discovery

Rampart is a foundation of composable, deterministic, BEAM-native security
primitives spanning static, dynamic, and interactive analysis. A human-facing
platform or an autonomous agent harness may consume those primitives, but
neither the platform nor the harness belongs in Rampart.

The long-term target is an autonomous security-research foundation for Elixir
and Erlang applications. High-recall static reconnaissance exposes program and
package relationships that may matter to insecurity or abuse. An external agent
turns those noisy facts into concrete hypotheses; Portico, Foray, Havoc, IAST,
and real traffic then drive deterministic confirmation or refutation. Runtime
facts reduce static uncertainty and give the agent ground truth instead of an
opportunity to hallucinate.

## Membership gates

A component belongs in Rampart only when it is all of the following:

1. a focused static, dynamic, or interactive security-analysis primitive—not a
   platform, UI, report product, or reasoning harness;
2. BEAM/Elixir-native in a way that uses the runtime, OTP semantics, Elixir AST,
   or ecosystem-specific security knowledge;
3. interoperable through `%Core.Finding{}` and `%Core.Seed{}`; and
4. capable of validating a specific hypothesis, not merely reporting a
   candidate.

Every primitive must remain useful and correct without an LLM. An agent is a
driver, not a dependency. Prompt strategy, attack narratives, tool selection,
and stopping policy belong to the external harness (working name: Lemieux).

Extension packages are narrower: `muex_security`, for example, contributes
operators to Muex rather than pretending to be an independent assessment tool.
The Muex execution/report adapter is where normalized observations and
validation eventually belong.

## Observe → validate

Rampart tools expose two operations:

- **Observe:** produce structured `%Core.Finding{}` values from a scan, static
  pass, property search, or runtime trace.
- **Validate:** execute one versioned deterministic action against an identified
  finding, concrete seed, or structured hypothesis and return
  `:confirmed | :refuted | :inconclusive`, structured evidence, normalized
  findings when confirmed, and an exact replay `%Core.Seed{}`.

`Core.Validation` and `Core.Validator` define this boundary. The contract is a
plain Elixir API and remains transport-independent; MCP or another agent-call
transport is a harness concern. `Core.Validation.Binding` lets that transport
resolve inert subject IDs under current host authority, while
`Core.Validation.Wire` provides a transcript-safe JSON projection that excludes
native raw terms and executable context. The consuming harness still enforces
its execution-specific byte limit.

```text
observe likely issue
        │
        ▼
validate exact hypothesis ──▶ verdict + evidence + replay seed
        │
        ▼
confirmed finding becomes a fact a consumer may safely chain
```

The trust chain ends at deterministic code. An oracle or sensor must never turn
an implementation failure into a confirmation, and a signal must not claim
more than it proves. Exact validation distinguishes pass, skip, violation, and
harness failure: missing observations are inconclusive rather than false
refutations. In particular, a reflected marker is not automatically XSS and a
database error is not automatically SQL execution.

## Lemieux seam, grounded in its implementation

Review of Lemieux at commit
`76bd70322daae8ce47f53ed3993ee8d07f2c8452` confirms that it already owns the
model/tool loop, current host-tool authority, policy hooks, bounded execution,
append-only transcripts, structured tool results, and content-addressed run
evidence. Rampart must fit those seams rather than build a second harness.

A Lemieux tool adapter remains outside Rampart and depends on both projects.
The host binds policies, scan plans, target functions, resolvers, deadlines,
and artifact access; a model supplies only an action-scoped subject reference.
Resuming a transcript never restores that authority. Expected Rampart verdicts
are successful tool results, while scope denial, harness deadline/cancellation,
and implementation failure remain distinct harness outcomes. A target timeout
captured by a completed validator may still be domain-level inconclusive
evidence. Large scan and IAST proof is artifact-backed rather than copied into
model context.

Lemieux's harness-learning discovery/confirmation contracts optimize harness
assets and are intentionally separate from Rampart security validation. A
Pareto-frontier harness candidate is not a confirmed vulnerability, and search
observations cannot pre-populate independent confirmation evidence. See
[LEMIEUX_INTEGRATION.md](LEMIEUX_INTEGRATION.md) for the reviewed contract map.

## Converging analysis modes

```text
RampartSAST facts + rule signals ─▶ external hypothesis reasoning
                                           │
                                           ▼
Portico / Foray / Havoc drivers ─────▶ RampartIAST sensor ─▶ confirmed runtime fact
                                           │
real or replayed application traffic ──────┘
```

- **Portico** discovers and rechecks reachable TCP/service surface.
- **Foray** exercises and exactly replays HTTP matches under scope and rate
  controls.
- **Havoc** is the in-process validation engine. Its conservative oracles,
  exact-payload validation, generators, and durable corpus are the trust anchor.
  Codec, parsed HTTP parameter, shared-cache, actor-paired field-policy,
  differential, and external-state observations support narrowly stated
  canonicalization, grammar, policy/noninterference, and lifecycle contracts;
  terminal classification covers captured output bytes. Fixtures still own
  independent expectations, exploit preconditions, controls, and cleanup.
- **HavocProper** is an opt-in execution driver for coverage-guided research; it
  does not replace Havoc's oracle verdicts.
- **RampartSAST** is the high-recall static reconnaissance and exact signal-
  replay primitive. It parses Elixir and Erlang, inventories definitions, calls,
  directives, dependency declarations/locks, and host-resolved package use, and
  runs optional rule/provider packs. Sobelow-derived knowledge is one signal
  pack, not the engine's shape. Inventory facts and rule matches prove syntax,
  never taint, reachability, abuse, or exploitability.
- **RampartIAST** currently implements the experimental single-process,
  exact-marker trace-session spike plus an analyzer-independent seam for
  reviewed static candidates. It recognizes unchanged markers inside bounded
  container arguments and explicitly refuses hypotheses requiring cross-process
  scope. Static provenance, dependence type, sanitizer observations, and
  ambiguous spans qualify evidence but never override the runtime verdict.
  Future levels consume richer context-specific knowledge only after their
  research gates.
- **Core** owns interchange and action contracts only. It never owns tool logic,
  sink knowledge, or harness reasoning.

## Contexts are pluggable

Phoenix, LiveView, Nerves, plain libraries, Erlang applications, and bare OTP
services have different sources, sinks, trust boundaries, package APIs, and
execution drivers. RampartSAST and RampartIAST model context providers behind
behaviours rather than hardcoding an HTTP request shape. RampartSAST's inventory
is intentionally broad; providers add qualified ecosystem meaning without
assigning trust. Sobelow-derived knowledge can seed a Phoenix signal/context
pack, while package ownership comes from inspected artifacts rather than naming
guesses.

`Core.Hypothesis.locus` and `Core.Finding.locus` remain source-shaped maps so
these contexts can carry useful identifiers without a premature web-only union.
Scanner-owned source/match/observation types live in `rampart_sast`, and
sensor-owned source/sink/observation and static-candidate types live in
`rampart_iast`; neither belongs in Core. Conversion from reviewed SAST sink
observations to IAST declarations belongs in a separate adapter so neither tool
depends on its sister.

## Honest research boundaries

- `:erlang.trace` can efficiently observe selected calls, arguments, sends, and
  receives, but it does not magically attach taint labels to transformed terms.
- Cross-process taint through messages, ETS, the process dictionary, and OTP
  topology is the line-of-death. The partial boundary matrix supports direct
  messages and GenServer casts only with existing application IDs, GenServer
  calls with OTP aliases, the tested `Task.async/3` protocol with task references
  plus spawn lineage, and ETS only with unique keys and an overwrite-free
  interval. Concurrent value equality remains ambiguous. Adversarial probes keep
  ID-less casts ambiguous, Task crash/timeout inconclusive, overwrite without a
  write version ambiguous, delete and ordinary worker replacement terminating,
  and injected event loss incomplete. Versioned external records can restore an
  edge across replacement without treating PIDs as continuous. A bounded
  64-flow/16-sender/512-noise mailbox probe and a separate-session two-node
  handoff preserve exact explicit-envelope joins, but still reject value-only or
  cross-node-clock correlation. Targeted process-dictionary reads are not
  call-trace visible on the pinned runtime, and full snapshots are rejected as
  overbroad. Intra-process/single-node reachability must ship first, and broader
  cross-process reconstruction remains a gated spike.
- A traced sink MFA does not by itself identify a unique source call site. The
  static map, debug information, or narrowly inserted instrumentation must
  provide localization.
- OTP Cover is node-global and line-oriented. HavocProper serializes it and is a
  search aid, not the IAST sensor or branch/edge coverage proof.
- Instrumentation is initially for test, CI, and controlled staging. Production
  safety requires separate overhead, isolation, sampling, and data-handling
  evidence.
- IAST observes only exercised code. Deterministic replay and execution-driving
  generators/traffic are therefore part of the architecture, not optional
  polish.

See [IAST_RESEARCH.md](IAST_RESEARCH.md) for the pre-implementation gates and
proposed spike boundaries.

## Dependency direction

```text
security_core
  ▲       ▲       ▲
  │       │       │
portico  foray   havoc ◀── havoc_proper

muex ◀── muex_security

rampart_sast ──▶ security_core
rampart_iast ──▶ security_core
future SAST rule/context packs ──▶ RampartSAST contracts + security_core
future SAST-to-IAST adapters ──▶ both tool contracts + security_core
```

Tools never depend on sister tools. Cross-tool workflows live in a separate
integration application. RampartIAST consumes context-provider data, but Core
never depends on the sensor, a static analyzer, or an agent harness.

## Roadmap gates

1. Keep the current Core, Portico, Foray, Havoc, guided-generation, target-
   derivation, and Muex work independently shippable.
2. Mature the validation contract and adversarially review Havoc's oracles
   against real vulnerable/fixed examples. Keep the terminal, canonical-codec,
   quoted-parameter, cache-tenancy, and actor-paired field-policy historical
   controls green while adding IP-policy, route-topology, and state-lifecycle
   cases.
3. Mature RampartSAST's project/package inventory, graph queries, and
   Elixir/Erlang resolution before expanding rule count. Harden the initial
   artifact-derived module ownership, checksummed cross-package source indexing,
   callback/protocol facts, typed behavior vocabulary, bounded graph slices, and
   disposable-VM untrusted-source scanner; then extract provenance-carrying
   Sobelow and Reach signal adapters without turning either into a verdict
   engine.
4. Expand the repository-local evaluation corpus beyond its current real
   command/deserialization/filesystem/Plug boundaries, package classifiers,
   ambiguous localization, targeted-overhead measurement, conditional boundary
   correlation, adversarial fail-closed probes, OTP process-scope refusal, exact
   historical Plug source, and adapted vulnerable/fixed terminal-control,
   canonical-codec, quoted-parameter, cache-tenancy, and Ash field-policy
   contracts. Add macro-generated, protocol/callback,
   dependency-misuse, full pinned package/
   application, remaining OTP-boundary, and Erlang examples. Track false
   confirmations, explicit uncertainty, query/evidence budgets, and exact replay
   before optimizing candidate volume.
5. Mature the intra-process exact-marker trace-session spike beyond its current
   real sink fixtures, bounded nested-container matching, exact replay, and
   seven-sample fixed-cost overhead baseline. Add representative workloads,
   scheduler/memory measurements, and more teardown/fault evidence.
6. Gate any cross-process taint roadmap on adversarial boundary evidence. The
   current direct-message, GenServer, Task, ETS, external-restart, mailbox, and
   distributed results are valid only under their explicit envelope/reference/
   key/version preconditions; they do not establish general taint. Extend the
   bounded frontier into sustained pressure, less cooperative distributed
   topologies, and higher-concurrency adversarial runs. Keep the OTP 28/29
   semantic compatibility gate green, and keep process-dictionary provenance
   unsupported unless a targeted, bounded observation mechanism is demonstrated.
7. Keep the transport-neutral binding and wire projection stable, then build an
   action-scoped Lemieux adapter outside Rampart; Lemieux remains the authority,
   policy, transcript, and reasoning harness.

The later architecture is load-bearing only after oracle determinism, tracing
overhead, and cross-process feasibility have evidence. Until then, those are
research claims rather than product guarantees.
