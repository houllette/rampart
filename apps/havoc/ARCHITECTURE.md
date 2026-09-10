# Havoc architecture

## The base-package boundary

Havoc is a thin security layer over StreamData and ExUnit:

```text
curated Core seeds ─▶ Havoc.Gen ─▶ StreamData.check_all ─▶ Havoc.Oracle
       ▲                                      │                 │
       └──────── exact shrunk counterexample ─┴─ Core finding ◀─┘
```

Havoc does not implement a random engine, shrink traversal, property scheduler,
HTTP client, external-process runner, or authorization system. Those would
either duplicate StreamData or cross into another Rampart tool. Experimental
coverage search lives in the separate `havoc_proper` adapter, where PropEr owns
the search strategy and Havoc continues to own oracles/findings/corpus.

## Why `StreamData.check_all/3` is used directly

`ExUnitProperties.check all` correctly performs shrinking, but its public macro
raises the final assertion and does not return the concrete shrunk value to a
wrapper. StreamData 1.4's public `StreamData.check_all/3` returns both
`:original_failure` and `:shrunk_failure` metadata. Havoc calls that public
runner and puts a structured `Havoc.Property.Failure` in the failure value.
StreamData still owns generation and greedy shrink-tree traversal; Havoc merely
receives the final failure and persists its concrete payload.

`Havoc.Case.security_property/3` still registers the test through
`ExUnitProperties.property`, so ExUnit reporting, filtering, seeding, and the
normal test lifecycle remain intact.

## Execution order

For each property:

1. normalize options and oracle declarations with NimbleOptions;
2. emit `[:core, :havoc, :property, :start]`;
3. load counterexamples whose metadata matches the stable property ID;
4. deduplicate exact values and replay them in sorted seed-ID order;
5. unless corpus-only mode is active, call `StreamData.check_all/3`;
6. on success, emit the property stop event with replay and random-run counts;
7. on a violation, persist the shrunk payload atomically, emit Core findings,
   and raise `Havoc.PropertyError`;
8. on target setup/test errors not governed by `:no_crash`, re-raise the
   original error and do not create a security finding.

Oracle implementation failures are treated as ordinary test errors even when
`:no_crash` is declared. This prevents a broken custom oracle from being
misreported as a crash in the application under test.

## Macro and primitive APIs

`security_property` is the common search API. `Havoc.Property.check!/3`,
`Havoc.Oracle.check/4`, every generator, and all corpus functions are public so
consumers can build custom ExUnit or non-macro integration. `Havoc.validate/3`
is the separate hypothesis-validation API: it executes one concrete Core seed,
performs no random generation, and returns a contract-checked
`Core.Validation.Result`. Exact validation consumes the richer oracle report:
a result is refuted only when every oracle passes, while any skipped oracle
makes the verdict inconclusive. This prevents an observation-shape mismatch
from being reported as evidence that a hypothesis is false.

The macro binds `payload`, records a stable default property ID from module and
property name, and evaluates either a returned observation or an explicit
`havoc_assert/2`. Havoc 0.2's `security_targets` macro runs conservative
`%Havoc.Target{}` descriptors. Function-spec and Phoenix providers derive text
injection points, while execution and non-fuzzed fixtures remain caller-owned.

## StreamData base package and optional search adapter

PropCheck's DETS-backed counterexample persistence informed the corpus design,
but PropCheck is not a v1 dependency. StreamData is the single generation
backend. Stateful authorization/session models may justify a future optional
PropCheck adapter without changing the Generator–Oracle–Corpus boundaries.

Coverage-/search-guided generation remains outside the base package. The
optional `havoc_proper` package uses PropEr targeted PBT, counts OTP Cover lines
per candidate, retains coverage-increasing Core seeds, and feeds violations back
through the public `Havoc.Property` backend contract. This keeps GPL
PropEr/PropCheck dependencies and node-global Cover instrumentation opt-in.

## Core boundary

Havoc uses only:

- `%Core.Finding{}` for normalized violations;
- `%Core.Seed{}` for generated, imported, counterexample, and proof values;
- `Core.Validation` for discoverable concrete-payload verdicts; and
- `Core.Telemetry` for property/validation spans and finding events.

It does not use `Core.Runner` because no binary is launched. It does not use
`Core.Scope` because it evaluates the consumer's own code in-process. A property
whose body chooses to call a remote endpoint is responsible for restricting
that endpoint to the user's own test environment.

This boundary positions Havoc as Rampart's validation engine and oracle trust
root. A target/oracle setup error is inconclusive or an ordinary test error,
never a confirmation. Signal oracles retain their documented confidence and do
not claim exploitability merely because an agent requested validation.

Relational checks use explicit codec, differential, external-state, parsed HTTP
parameter, shared-cache, actor-paired field-policy, explicit-length and
incremental-counter observations. Terminal
safety classifies caller-designated output bytes. These are bounded normalized
evidence shapes rather than package models: fixtures still own independent
policy expectations, actors/tenants, cache execution, field/path adapters,
counters, cleanup, and the security claim's preconditions. The repository
evaluation requires the same oracle to confirm a vulnerable control, refute a
fixed control, remain inconclusive on harness failure, and replay the concrete
seed.

The incremental observation helper drives one finite supplied chunk list
sequentially and snapshots host-supplied counters. It is neither a parser nor
a property runner. Driver input/sample limits are separate from the security
oracle's measured resource limits, and neither contains a nonreturning callback.

## Research findings applied in v1

- StreamData 1.4 provides the required public generator combinators and
  `check_all/3` shrink metadata, but no durable counterexample store.
- PropCheck persists counterexamples in DETS and replays them first; Havoc
  borrows the replay-first model while storing Core seeds in a versioned file.
- No general-purpose Hex package was identified that combines conventional
  adversarial payload generators, StreamData shrinking, security oracles, and
  a persistent Core-compatible corpus. Generic generator extensions and static
  analyzers solve different problems.
- OWASP testing guidance supports specific error-disclosure signals, but raw
  reflection or a database error alone is not exploit confirmation. That drove
  the conservative semantics in ORACLES.md.
