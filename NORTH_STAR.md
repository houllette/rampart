# Rampart north-star architecture

## BEAM-native IAST as the foundation for agent-driven vulnerability discovery

Rampart is a foundation of composable, deterministic, BEAM-native security
primitives spanning static, dynamic, and interactive analysis. A human-facing
platform or an autonomous agent harness may consume those primitives, but
neither the platform nor the harness belongs in Rampart.

The long-term target is an IAST foundation for Elixir applications. Static sink
knowledge says where dangerous operations are. Portico, Foray, Havoc, and real
traffic drive execution. A future BEAM sensor observes whether attacker-
controlled input reaches a watched sink on an actual execution path. The same
runtime fact that reduces static-analysis false positives also gives an agent
ground truth instead of an opportunity to hallucinate.

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
more than it proves. In particular, a reflected marker is not automatically XSS
and a database error is not automatically SQL execution.

## Lemieux seam, grounded in its implementation

Review of Lemieux at commit
`e427221bc6b6c2b70909256d048174b986910fbd` confirms that it already owns the
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
static sink/context knowledge ───────┐
                                     ▼
Portico / Foray / Havoc drivers ─▶ RampartIAST sensor ─▶ localized confirmed finding
                                     │
real or replayed application traffic ┘
```

- **Portico** discovers and rechecks reachable TCP/service surface.
- **Foray** exercises and exactly replays HTTP matches under scope and rate
  controls.
- **Havoc** is the in-process validation engine. Its conservative oracles,
  exact-payload validation, generators, and durable corpus are the trust anchor.
- **HavocProper** is an opt-in execution driver for coverage-guided research; it
  does not replace Havoc's oracle verdicts.
- **Sobelow-derived knowledge** should become a pluggable Phoenix sink/context
  map and a SAST-mode finding source rather than be rebuilt as another generic
  static analyzer.
- **RampartIAST** currently implements the experimental single-process,
  exact-marker trace-session spike. Future levels consume richer
  context-specific source and sink knowledge only after their research gates.
- **Core** owns interchange and action contracts only. It never owns tool logic,
  sink knowledge, or harness reasoning.

## Contexts are pluggable

Phoenix, LiveView, Nerves, plain libraries, and bare OTP services have different
sources, sinks, trust boundaries, and execution drivers. RampartIAST models
context providers behind behaviours rather than hardcoding an HTTP request
shape. Sobelow-derived knowledge can seed the Phoenix provider; other contexts
must be built and validated independently.

`Core.Hypothesis.locus` and `Core.Finding.locus` remain source-shaped maps so
these contexts can carry useful identifiers without a premature web-only union.
Sensor-owned source/sink/observation structs live in `rampart_iast`, not in
Core.

## Honest research boundaries

- `:erlang.trace` can efficiently observe selected calls, arguments, sends, and
  receives, but it does not magically attach taint labels to transformed terms.
- Cross-process taint through messages, ETS, the process dictionary, and OTP
  topology is the line-of-death. Intra-process/single-node reachability must ship
  first; cross-process reconstruction remains a gated spike.
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

rampart_iast ──▶ security_core
future context providers ──▶ RampartIAST contracts + security_core
```

Tools never depend on sister tools. Cross-tool workflows live in a separate
integration application. RampartIAST consumes context-provider data, but Core
never depends on the sensor, a static analyzer, or an agent harness.

## Roadmap gates

1. Keep the current Core, Portico, Foray, Havoc, guided-generation, target-
   derivation, and Muex work independently shippable.
2. Mature the validation contract and adversarially review Havoc's oracles
   against real vulnerable/fixed examples.
3. Extract a versioned, provenance-carrying Phoenix sink map from existing
   static knowledge.
4. Mature the intra-process exact-marker trace-session spike with real sink
   fixtures, measured overhead, and exact replay evidence.
5. Gate any cross-process taint roadmap on a dedicated feasibility result.
6. Keep the transport-neutral binding and wire projection stable, then build an
   action-scoped Lemieux adapter outside Rampart; Lemieux remains the authority,
   policy, transcript, and reasoning harness.

The later architecture is load-bearing only after oracle determinism, tracing
overhead, and cross-process feasibility have evidence. Until then, those are
research claims rather than product guarantees.
