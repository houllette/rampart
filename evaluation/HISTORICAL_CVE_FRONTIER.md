# Recent Erlang/Elixir CVE primitive review

This document records a patch-informed review of the most recent Erlang
Ecosystem Foundation CNA advisories available on 2026-09-08. It is a roadmap
input rather than proof of independent discovery: no new upstream source is
vendored here and no advisory-specific detector is proposed. Five reusable
contracts identified by the review have since graduated into the executable
evaluation gate; the per-advisory table preserves the baseline result from
before those changes.

## What `mix hex.audit` does

Hex 2.5.1's `Mix.Tasks.Hex.Audit` reads locked Hex packages, asks the Hex
registry for advisories matching each package/version, groups aliases, applies
configured ignores, and reports already-known advisories. It is a consumer-side
disclosure check, not the process that discovers a vulnerability.

For Rampart, the useful evaluation method is therefore retrospective:

1. pin the parent of each public fix as the vulnerable snapshot;
2. pin the fix commit as the corrected snapshot;
3. ask whether static reconnaissance independently exposes a useful hypothesis;
4. ask whether a deterministic Rampart action can distinguish the snapshots
   using an oracle stated without consulting the implementation under test; and
5. retain the exact counterexample and proof action for replay.

Canonical disclosure metadata comes from the
[EEF CNA](https://cna.erlef.org/cves/). Patch commits are linked below only to
make the reviewed boundary reproducible.

## Reviewed frontier

| Advisory | Package and bug class | Public fix | Current Rampart result | Reusable primitive needed |
| --- | --- | --- | --- | --- |
| [CVE-2026-78216](https://cna.erlef.org/cves/CVE-2026-78216.html) | `ash_lua`: field-policy bypass through aggregate read | [`266a5dc`](https://github.com/ash-project/ash_lua/commit/266a5dcc56d5015b6d316c10606169e753b07450) | Inventories the aggregate and Ash calls, but emits no relevant signal and cannot infer that aggregate results bypass record-field authorization. | Ash package contract plus actor-paired policy noninterference: protected data must remain absent across every equivalent read/aggregate path. |
| [CVE-2026-78230](https://cna.erlef.org/cves/CVE-2026-78230.html) | `ash_ai`: field-policy bypass through aggregate tool | [`9c02de5`](https://github.com/ash-project/ash_ai/commit/9c02de581625c342c9870a672830bff28c1d701e) | Records `Ash.aggregate`, field lookup, and surrounding calls, but not the meaning or absence of `authorize_fields?: true`. | The same package contract and policy oracle as CVE-2026-78216; shared classes should connect equivalent package APIs across repositories. |
| [CVE-2026-82710](https://cna.erlef.org/cves/CVE-2026-82710.html) | `usage_rules`: package-controlled metadata reaches a terminal without control-character neutralization | [`3b8ebb4`](https://github.com/ash-project/usage_rules/commit/3b8ebb4117d3272bbd436e6c2432113ba6685dbb) | Records network and terminal-related calls, but has no expression flow from response fields through interpolation to terminal output and no terminal-safety contract. | Terminal source/sink model, control-character generator, forbidden-output oracle, and transformed-value localization. |
| [CVE-2026-82584](https://cna.erlef.org/cves/CVE-2026-82584.html) | `igniter`: package metadata rewrites an install confirmation panel | [`d492b1a`](https://github.com/ash-project/igniter/commit/d492b1aa33f8fb0dacc0afa41b703fb922d42816) | The existing starter signals are unrelated and unchanged across the patch. Newline replacement is visible only as an ordinary call, not as an incomplete terminal sanitizer. | The same terminal contract as CVE-2026-82710, including alternate C0/C1 sequences rather than an advisory-specific escape string. |
| [CVE-2026-82586](https://cna.erlef.org/cves/CVE-2026-82586.html) | `ash_lua`: aggregate operation bypasses the exposed-field allow-list | [`c0dfcd9`](https://github.com/ash-project/ash_lua/commit/c0dfcd9494766d548178c37df0bd01cff378e1c7) | Inventories both the normal and aggregate paths but cannot ask whether every path to field materialization passes the same allow-list. | Alternate-path completeness query, package authority model, and differential field-selection oracle. |
| [CVE-2026-81638](https://cna.erlef.org/cves/CVE-2026-81638.html) | `ash_double_entry`: noncanonical ULID strings alias the same identifier | [`d3e688d`](https://github.com/ash-project/ash_double_entry/commit/d3e688d300a581ae214b3ca7d95ef4de63fbb050) | Records codec definitions and calls but has no bit-pattern semantics or relational property synthesis. | Codec contract: every accepted text value must equal `encode(decode(value))`, and distinct accepted spellings must not decode to one identity. |
| [CVE-2026-82758](https://cna.erlef.org/cves/CVE-2026-82758.html) | `ash_authentication_oauth2_server`: empty resolved secret opens a gated registration path | [`30a8710`](https://github.com/ash-project/ash_authentication_oauth2_server/commit/30a87101871775d27d79f9ad6f29eafa4779e118) | Finds dynamic dispatch and authentication-shaped definitions, but cannot infer the non-empty-secret contract or follow the configuration result into route gating. | Refined secret type (`nonempty_binary`), fail-closed configuration matrix, and a negative unauthenticated registration oracle. |
| [CVE-2026-82757](https://cna.erlef.org/cves/CVE-2026-82757.html) | `ash_authentication_oauth2_server`: IPv4-in-IPv6 and site-local SSRF classification gaps | [`268b591`](https://github.com/ash-project/ash_authentication_oauth2_server/commit/268b591261a3473ab9b87272963e4dd2fd99d972) | The Req boundary is visible, but the inventory has no IP-range lattice and cannot establish that all resolved addresses satisfy the outbound policy. | Independent special-use address tables, IPv4/IPv6 embedding generators, DNS multi-answer scenarios, and destination-policy validation. |
| [CVE-2026-82756](https://cna.erlef.org/cves/CVE-2026-82756.html) | `ash_authentication_oauth2_server`: tenant-derived quoted-string parameter injection in `WWW-Authenticate` | [`09f9747`](https://github.com/ash-project/ash_authentication_oauth2_server/commit/09f97476715da031b136eaec7b2cda2363ad8149) | The optional Plug provider identifies response-header writes in both snapshots, but no expression flow or RFC quoted-string grammar connects the tenant to the header value. Exact-marker IAST cannot prove a marker embedded in a transformed string. | Header grammar contract, request-to-header slice, parser-backed parameter-integrity oracle, and bounded transformed-value instrumentation. |
| [CVE-2026-82755](https://cna.erlef.org/cves/CVE-2026-82755.html) | `ash_authentication_oauth2_server`: tenant-varying metadata is publicly cacheable without `Vary` | [`768d87f`](https://github.com/ash-project/ash_authentication_oauth2_server/commit/768d87f70e4e97ae1d2bf1606b5bf3f4d03f24a1) | Header writes and tenant reads are separately visible, but literal header values, dependence, cache semantics, and tenant variance are not queryable. | Cache-policy model and two-tenant noninterference scenario: a shared-cache key must not reuse tenant-specific metadata. |
| [CVE-2026-82754](https://cna.erlef.org/cves/CVE-2026-82754.html) | `ash_authentication_oauth2_server`: state-changing routes also mounted under `/.well-known` | [`a72972d`](https://github.com/ash-project/ash_authentication_oauth2_server/commit/a72972d7ed3eb74c05dfa0653a258ef14454459a) | Directives and route calls are inventoried, but forward-prefix stripping and effective method/path expansion are not represented. | Compiled Phoenix/Plug route topology, mount expansion, attached-control provenance, and negative probes for alternate paths. |
| [CVE-2026-82753](https://cna.erlef.org/cves/CVE-2026-82753.html) | `ash_authentication_oauth2_server`: unauthenticated CIMD requests create unbounded persistent rows/cache entries | [`45e24f6`](https://github.com/ash-project/ash_authentication_oauth2_server/commit/45e24f69e0f95d67413e2508acc2264156acb5ac) | Generic resource-amplification facts are noisy and unchanged; there is no lifecycle relationship between unauthenticated input, cardinality growth, last use, TTL, and expunging. | Stateful workload scenario, external-state counters, growth/retention budget, virtual or injectable time, and post-expiry reclamation oracle. |

## Empirical static pass

Each fix commit and its first parent were scanned locally with the current
starter rules and the then-available BEAM, Plug, Phoenix, and Ecto behavior
classifiers. Full repository scans completed after the `__MODULE__` handling
regression described below was fixed. A second pass isolated each patch's
changed production files.

The direct result is intentionally blunt: **none of the twelve vulnerable
snapshots produced an advisory-relevant rule signal**. For every pair, starter
signal count was unchanged between vulnerable and fixed code. Several files
contained unrelated unsafe-atom or dynamic-code signals, which demonstrates why
raw signal count cannot stand in for recall.

The inventory was still useful for localization. It retained aggregate calls,
network and header effects, directives, definitions, control contexts, and
source spans. It could not represent the security relationship that separated
vulnerable from fixed code: an absent option/guard/sanitizer, an alternate path,
a relational codec invariant, a protocol grammar, cross-tenant variance, or
state growth over a sequence.

Scanning these real repositories also exposed a RampartSAST robustness defect:
valid `__MODULE__.Nested` aliases and remote calls crashed alias normalization.
That syntax is common in generated Mix tasks and library internals. The scanner
now normalizes those segments, resolves them against the enclosing module when
possible, and has a focused regression test. This is exactly the kind of corpus
feedback the historical tier should retain.

## What this says about the architecture

The current tool boundaries remain appropriate, but the middle of the workflow
is too thin:

- RampartSAST should not become twelve new advisory rules. It needs queryable
  expression relationships: assignments, returns, call arguments, literal and
  keyword values, guards, branches, control dependence, and bounded backward or
  forward slices. Missing-control questions must remain explicit uncertainty,
  not taint verdicts.
- Package/context providers should attach reviewed contracts to generic facts:
  Ash field authorities, terminal sinks, HTTP header grammars, effective router
  mounts, cache variance, special-use IP ranges, secret refinements, codecs, and
  resource lifecycles. Package version and provenance determine which model was
  applied.
- Havoc's StreamData search, custom oracles, exact replay, and authorization
  oracle can express all of these checks manually. It now also has first-class
  codec, parsed HTTP parameter, shared-cache, actor-paired field-policy,
  differential, and external-state observations plus reusable terminal-safety,
  canonical-encoding, parameter-integrity, cache-partition, field-policy, and
  bounded-growth contracts. Actors/tenants, alternate routes, cache behavior,
  field/path adapters, and classification tables still need fixture- and
  package-specific models; a generic observation shape must not invent those
  semantics.
- RampartIAST's unchanged-marker proof is useful for exact same-process flow but
  does not cover derived strings, semantic policy bypass, cache confusion,
  canonical aliases, or state growth. Those require separately versioned
  actions with narrower claims, not a broader meaning assigned to marker
  equality.
- MuexSecurity should add only patch-shape operators that ask a reusable control
  question, such as removing a reviewed authorization option or neutralizer.
  It should not encode CVE signatures or mutate every guard/string replacement.

## Executable benchmark slices

The historical tier is turning representative classes into exact
vulnerable/fixed executions in this order:

1. **Terminal neutralization — implemented.** The gate uses a byte-level oracle,
   a malicious OSC/cursor payload, a fixed negative control, failure injection,
   and exact replay. The one contract covers the class shared by two advisories.
2. **Canonical codec — implemented.** The gate uses a reduced ULID overflow
   model and requires every accepted input to equal `encode(decode(input))`.
   This exercises a primitive exact-marker IAST cannot represent.
3. **Quoted HTTP parameters — implemented.** A bounded authentication-header
   parser retains duplicate auth-params and quoted-pair semantics. A real Plug
   response must preserve the independently intended tenant-derived value as
   exactly one quoted parameter.
4. **Cache tenancy — implemented.** Two tenants vary at one shared URL. Uncached
   Plug responses establish distinct controls, and confirmation requires an
   exact cache hit returning tenant A's security projection to tenant B.
5. **Ash authorization alternate paths — implemented as a reduced model.** A
   privileged actor proves both record and aggregate paths are live; the paired
   restricted actor must observe every protected field as hidden. The optional
   Ash classifier identifies aggregate/policy boundaries, while option facts
   remain syntax rather than verdicts. Full pinned Ash package execution remains
   a stronger follow-up.
6. **IP policy** — exhaustive reviewed special-use tables plus generated
   embedding forms; network requests remain stubbed until policy classification
   passes.
7. **Route topology and bounded state growth** — compiled application scenarios
   with negative path assertions, external state measurement, injectable time,
   and cleanup verification.

For each slice, acceptance requires the same oracle to confirm the vulnerable
snapshot and refute the fixed snapshot, zero confirmations on injected harness
failures, a replayable concrete seed/scenario, bounded evidence, and no network
dependency during evaluation.
