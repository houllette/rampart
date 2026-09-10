# Rampart

Rampart is an Elixir umbrella for composable, deterministic, BEAM-native
security primitives spanning static, dynamic, and interactive analysis. The
north star is autonomous Elixir/Erlang security research: high-recall static
reconnaissance gives an external agent facts for concrete hypotheses, while
Portico, Foray, Havoc, IAST, and real traffic confirm or refute those claims.

Rampart is **not** an assessment platform, UI, or agent reasoning harness. It is
the structured, replayable ground-truth layer those consumers drive. Every tool
must remain correct and useful without an LLM.

**The umbrella is the development and integration boundary, not a monolithic
runtime.** Every tool remains independently versioned, publishable to Hex, and
useful without its sister tools. Read [NORTH_STAR.md](NORTH_STAR.md) before a
component brief; [IAST_RESEARCH.md](IAST_RESEARCH.md) records the sensor's honest
pre-implementation gates. [EVALUATION.md](EVALUATION.md) defines the
repository-local accuracy, efficiency, usefulness, and fail-closed evaluation
lab. [LEMIEUX_INTEGRATION.md](LEMIEUX_INTEGRATION.md) records the concrete
boundary with the external agent harness after review of its current tool,
policy, transcript, and evidence contracts.

> Rampart and the component names are working names until the first packages are
> published.

## Suite map

| Application | Layer | Purpose | Status |
| --- | --- | --- | --- |
| [`security_core`](apps/security_core/README.md) | shared spine | Findings, proof seeds, hypotheses, validation, scope, telemetry, and process contracts | v0.1 conformance work |
| [`portico`](apps/portico/README.md) | network / TCP | Backpressured RustScan discovery followed by nmap enrichment | v1 build |
| [`foray`](apps/foray/README.md) | web / HTTP | Structured, scope-safe, job-orchestrated ffuf integration | v1 build |
| [`havoc`](apps/havoc/README.md) | in-process | StreamData adversarial generation, security oracles, durable regressions, and derived targets | v0.2 |
| [`havoc_proper`](apps/havoc_proper/README.md) | optional research adapter | PropEr targeted PBT with OTP coverage fitness | experimental v0.1 |
| [`muex_security`](apps/muex_security/README.md) | mutation extension | Focused security-control operators for Muex | v0.1 |
| [`rampart_sast`](apps/rampart_sast/README.md) | static / source | High-recall Elixir/Erlang program/package inventory, optional rule signals, queries, and exact replay | experimental v0.1 |
| [`rampart_iast`](apps/rampart_iast/README.md) | interactive / runtime | Process-scoped exact-marker reachability with pluggable source and sink maps | experimental spike |

```text
RampartSAST facts/signals ─▶ external agent hypothesis
                                      │
Havoc / replay / real traffic ────────┼─▶ RampartIAST sensor ─▶ confirmed facts
Portico / Foray DAST ─────────────────┘

security_core: findings · seeds · hypotheses · validation · scope · telemetry · runner
```

## What makes Rampart a suite

All tools normalize observations to `%Core.Finding{}` and exchange targets,
payloads, and counterexamples as `%Core.Seed{}`. Pre-finding claims use
`%Core.Hypothesis{}`. `Core.Validation` adds the agent-neutral contract that each
analysis tool exposes: an identified hypothesis in, then a deterministic
`:confirmed | :refuted | :inconclusive` verdict with structured evidence and an
exact replay seed out.

Core also standardizes the cross-cutting contracts that external tools need:

- fail-closed `Core.Scope` authorization before traffic or process launch;
- `[:core, tool, ...]` telemetry, validation spans, and finding events;
- a swappable, Exile-backed `Core.Runner` process seam;
- stable finding and validation identities.

Portico still exposes its richer `%Portico.Host{}`, `%Portico.Port{}`, and
related structs. Core values are interchange projections, not a lowest-common-
denominator replacement for native models.

The intended corpus loop is:

```text
Portico exposed-service finding ──▶ Foray target seed
Foray HTTP finding              ──▶ Havoc regression seed
Havoc counterexample            ──▶ Foray payload seed
all findings                    ──▶ one correlatable finding bus
```

Cross-tool workflow orchestration and agent reasoning belong outside Core and
outside individual tools. A future integration application can compose them;
the external Lemieux harness can drive their plain observe/validate APIs without
Rampart knowing that the harness exists. `Core.Validation.Binding` keeps scope,
scan plans, target functions, and other authority host-owned while a transport
passes only inert subject IDs. `Core.Validation.Wire` supplies a transcript-safe,
JSON-shaped result projection without serializing native `raw` terms; the
consumer still enforces its configured byte limit.

## Dependency and boundary rules

```text
                    security_core
              ▲       ▲       ▲       ▲       ▲
              │       │       │       │       │
        portico     foray    havoc  rampart_sast  rampart_iast
                              ▲
                         havoc_proper

        muex ◀──── muex_security
```

- `security_core` depends on nothing else inside Rampart.
- Tools depend on Core, never on sister tools.
- Portico and Foray use the shared Runner/Scope spine.
- Havoc is in-process and intentionally does not cargo-cult external process or
  network-scope machinery.
- `havoc_proper` optionally depends on Havoc plus GPL-3.0 PropEr/PropCheck; the
  base Havoc package remains StreamData-only.
- `muex_security` extends Muex and intentionally does not depend on Core.
- `rampart_sast` depends only on Core, keeps framework/package knowledge
  pluggable, exposes noisy syntax and dependency-use facts, and replays exact
  rule signals rather than claiming taint, reachability, abuse, or
  exploitability.
- `rampart_iast` depends only on Core and currently proves single-process,
  exact-marker reachability—not transformed taint or exploitability.
- Each child is an independent Hex package. Tool consumers receive only their
  declared dependencies, not future suite components.

Every analysis tool must pass the north-star gates: it is a focused BEAM-native
primitive, speaks Core interchange, remains deterministic without an agent, and
can validate a specific hypothesis rather than only report a candidate. Existing
quality gates still apply: structured domain values, real backpressure where
applicable, high- and low-level APIs, pluggable engines/contexts, and correct
authorization/lifecycle behavior.

## Development

```sh
mix deps.get
mix test
mix rampart.sast --exit
mix rampart.eval
mix rampart.eval.compare report-otp-28.json report-otp-29.json
mix precommit
mix dialyzer
```

Run one child application's tests from the umbrella root:

```sh
mix test apps/portico/test
mix test apps/foray/test
mix test apps/havoc/test
mix test apps/havoc_proper/test
mix test apps/muex_security/test
mix test apps/rampart_sast/test
mix test apps/rampart_iast/test
mix test apps/security_core/test
```

Before publishing, build each package independently from its child directory:

```sh
(cd apps/security_core && mix hex.build --unpack)
(cd apps/portico && mix hex.build --unpack)
(cd apps/foray && mix hex.build --unpack)
(cd apps/havoc && mix hex.build --unpack)
(cd apps/havoc_proper && mix hex.build --unpack)
(cd apps/muex_security && mix hex.build --unpack)
(cd apps/rampart_sast && mix hex.build --unpack)
(cd apps/rampart_iast && mix hex.build --unpack)
```

Publish dependency-first: `security_core`, then Portico, Foray, Havoc; publish
`havoc_proper` after Havoc and `muex_security` independently after its Muex
compatibility checks. Keep `rampart_sast` and `rampart_iast` unpublished until
their research and evaluation gates pass.
