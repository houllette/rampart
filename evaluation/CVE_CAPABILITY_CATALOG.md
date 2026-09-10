# Additional CVEs and reusable validation capabilities

This 2026-09-09 source review adds eight advisories to the twelve in the
[historical frontier](HISTORICAL_CVE_FRONTIER.md). The
[structured catalog](https://github.com/houllette/rampart/blob/main/evaluation/CVE_CAPABILITY_CATALOG.json) records primary sources,
affected-version metadata, exact fix/first-parent pairs, prerequisites,
uncertainty, and deterministic proof/refutation contracts. The initial review
added no execution evidence. On 2026-09-10, three reduced Havoc contracts were
implemented and evaluated: resource-length units, incremental buffer budgets,
and numeric work budgets. The separate upstream gate now also builds and runs
complete pinned Mint revisions for CVE-2026-82728 and CVE-2026-82729 through the
actual affected package paths. The Ash case remains reduced-only. All three
reuse `havoc.security-property-reproduces.v1`; no new agent-facing action was
registered.

The local source review uses Rampart commit
`d34ab53c363ef26bb4628f8b2015ebeb9934091e`. Existing evaluation results and
retained performance/integration artifacts keep their original scope.

## Capability map

The first three contracts have **executed reduced models**; the two Mint
contracts additionally have complete upstream package executions. The remaining
five are proposed, and the Ash upstream experiment remains unexecuted. Contract
IDs in the JSON are research identifiers, not `Core.Validation` action IDs; the
implemented models use the existing Havoc action explicitly recorded in each
entry.

| Advisory | Reusable contract | Required observation | Implementation home |
| --- | --- | --- | --- |
| [CVE-2026-82752 — Ash](https://cna.erlef.org/cves/CVE-2026-82752.html) | Resource length uses an explicit unit | Accepted values satisfy the declared byte/codepoint bound at the downstream boundary, including combining characters. | Havoc oracle and bounded StreamData inputs; package fixture in evaluation. |
| [CVE-2026-82728 — Mint](https://cna.erlef.org/cves/CVE-2026-82728.html) | Every incremental parser state has a buffer budget | Retained incomplete response-line bytes respect a byte budget, with exact-boundary and fixed controls. | Reduced Havoc scenario plus complete Mint HTTP1 loopback connect/request/stream execution in `mix rampart.upstream`. |
| [CVE-2026-82729 — Mint](https://cna.erlef.org/cves/CVE-2026-82729.html) | Numeric parsing bounds work before conversion | Hexadecimal digit limits hold before chunk-size integer conversion, with exact-boundary and fixed controls. | Reduced Havoc oracle plus complete execution of Mint's hidden HTTP1 chunk-size parser function via `mix rampart.upstream`. |
| [CVE-2026-69664 — OTP inets](https://cna.erlef.org/cves/CVE-2026-69664.html) | Segmentation preserves cleanup | Malformed requests release their attributed worker/connection resources within the declared interval. | Bounded Havoc scenarios and disposable httpd fixture. |
| [CVE-2026-66835 — OTP inets](https://cna.erlef.org/cves/CVE-2026-66835.html) | Equivalent resources retain authorization | Independently equivalent paths to a protected canary retain its authorization requirement. | Havoc relational oracle; complete local httpd fixture. |
| [CVE-2026-64941 — LiveView](https://cna.erlef.org/cves/CVE-2026-64941.html) | Destination policy matches consumer normalization | An accepted local `redirect/2` destination stays within policy after the actual browser semantics resolve it. | Havoc oracle plus an external consumer driver; no browser dependency in Core. |
| [CVE-2025-32433 — OTP SSH](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2) | Effects require authenticated state | A harmless protected callback cannot run before authentication under bounded message sequences. | StreamData scenarios and disposable SSH fixture; no replacement PBT engine. |
| [CVE-2026-75538 — ERTS](https://cna.erlef.org/cves/CVE-2026-75538.html) | Native lengths remain representable | An independent arithmetic model rejects invalid totals; native reproduction would require separate OS isolation. | External runtime fixture. Patched C code is outside the current SAST parser. |

These cases favor reusable relationships over additional dangerous-API rules:
unit versus resource, input partition versus outcome, resource identity versus
authorization, consumer parsing versus policy, and protocol state versus effect.
SAST can help localize package use and relevant operations. A call, variable,
configuration edge or static path alone cannot establish the prerequisite or
the security outcome.

## How to interpret the JSON

`schema_version: 1` describes an inert research document. Entries are uniquely
keyed by `cve_id`; aliases, canonical JSON URLs and SHA-256 fingerprints identify
the reviewed disclosure metadata. The fingerprints identify fetched bytes;
the catalog does not retain a complete offline copy of each advisory.
EEF CNA metadata is attributed to the Erlang Ecosystem Foundation under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); the catalog selects
version fields and adds Rampart's own summaries and proposed contracts.
`affected_version_metadata` preserves the CNA's version type and ranges. It
must not be interpreted using one generic SemVer comparator, particularly for
OTP component versions and Git revisions.

`revision_pair` pins a reviewed patch and its verified first parent. The parent
is a candidate pre-fix fixture, not an independently demonstrated vulnerable
build. The pair is one branch selection, not a complete backport map. Before
vendoring or execution, review licensing, build dependencies, fixture scope
and whether that parent actually exhibits the exact claimed behavior.

`evidence` deliberately distinguishes advisory/patch review, static scanning,
reduced-contract implementation and full-package execution. The first three
entries include reduced-model evidence and links to the retained evaluation
report. The upstream runner separately records full-package evidence for the two
Mint entries, including exact commit/tree/license/source/BEAM/runtime/input and
proof-artifact identities. Five entries still have advisory/patch-review
evidence only. The catalog JSON's original evidence fields are not silently
rewritten by a local run; interpret them with the generated upstream report.
`static_facts_to_localize` describes useful inputs, including relationships
that current SAST may not yet represent. It is not an inventory of implemented
extractors.

`proposed_contract` gives an invariant, bounded experiment, controls, ownership
and completed domain outcomes. Refutation is limited to the declared claim,
case set, fixture and budget. Host scope denial, harness deadline/cancellation
and crashes remain tool failures; a probe timeout captured by a completed
validator can be inconclusive. Model-only arithmetic evidence cannot resolve
a native-runtime claim. None of these proposals upgrades exact-marker IAST
into transformed-value or cross-process taint tracking.

Only a reviewed host registry may bind a subject to a future action. Targets,
callbacks, scope, budgets and artifact access stay in host-owned
`Core.Validation.Binding` values. Never execute catalog text or restore
authority from it. Tool-specific observations stay native until an external
adapter projects them through Core and `Core.Validation.Wire`; the host must
bound the final serialized response. See
[Lemieux integration](../LEMIEUX_INTEGRATION.md).

## Source qualifications that affect future fixtures

The Mint numeric-parser fix has the buffer fix as its first parent. Retain
that ordering: the numeric experiment should distinguish work amplification
even when the preceding buffer protection is already present. A successful
buffer experiment cannot stand in for the work contract. See the
[numeric patch](https://github.com/elixir-mint/mint/commit/bd2a4e7513594997c140cfef9fe0e968712fb588).

The LiveView GitHub advisory lists `1.0.19` in both its affected-version table
and patched releases, while the EEF structured record uses an exclusive
`1.0.19` upper bound. The catalog retains the EEF ranges and records this
disagreement. Use exact revisions for fixtures. The advisory's detailed
discussion also distinguishes external navigation through `redirect/2` from
the other push APIs; sharing a helper does not establish identical browser
behavior. See the [maintainer advisory](https://github.com/phoenixframework/phoenix_live_view/security/advisories/GHSA-36m4-rm57-3prf)
and [CNA record](https://cna.erlef.org/cves/CVE-2026-64941.json).

For ERTS, retain the specific VM-crash/native-arithmetic scope. The patch is
in C, and this review does not establish an RCE capability or a native SAST
analysis capability. See the
[maintainer advisory](https://github.com/erlang/otp/security/advisories/GHSA-8m6r-2pj2-25pm).

## Implementation order

1. Close the source-visible local boundaries in
   [RESOURCE_LIMITS.md](../RESOURCE_LIMITS.md): diagnostic bytes, runtime patch
   pins, complete-line framing, and XML document/result budgets. Each has a
   concrete specification. These four local boundaries were subsequently
   implemented on 2026-09-10; the resource inventory records their verification
   scope. Two Mint upstream package experiments now execute in the separate
   gate; the other six remain unexecuted.
2. Add the explicit-unit and parser-budget contracts to Havoc using ordinary
   StreamData generation/shrinking. The small reduced cases are now implemented
   and run in `mix rampart.eval`; the exact pinned Mint package pairs now run in
   `mix rampart.upstream`. Keep reduced and full-package evidence levels
   separate, and extend the pattern to the remaining cases.
3. Extend the existing complete-application evaluation approach to path
   authorization, segmentation/cleanup and authentication-state scenarios.
   Have the host own lifecycle measurements and independent positive controls.
4. Add the browser-normalized redirect fixture once the consumer oracle is
   available. Keep native integer-boundary execution deferred until a
   disposable runtime has reviewed OS memory/process/time bounds.

Every implementation should retain the exact input or event sequence, revision
and runtime identity, oracle version, budgets, completed observations, cleanup
evidence and replay reference. Register an agent-facing action only after its
deterministic proof/refutation behavior exists. These proposed cases complement
the original frontier's remaining IP classification, route topology and
persistent-state reclamation work; they do not replace it.

## Implemented library surface and reduced evidence

Havoc now provides `Gen.unicode_length/1`, `Gen.byte_partitions/2`,
`Observation.Length`, `Observation.Incremental.capture/5`, and three configured
oracles: `bounded_length/1`, `incremental_buffer_budget/1`, and
`incremental_work_budget/1`. Inputs and sample counts are bounded, generation
and shrinking remain StreamData-owned, and concrete chunk lists survive corpus
replay. Missing measurements/units stay inconclusive; target/oracle failures
cannot confirm a resource violation unless a separate crash invariant is added.
Measured values, units and limits survive the existing wire projection.

The retained [evaluation report](https://github.com/houllette/rampart/blob/main/evaluation/baselines/2026-09-10/resource-contracts.json)
contains vulnerable/fixed replay and positive/exact-boundary/rejection checks,
bounded SAST localization and wire evidence checks, and source fingerprints.
The three fixture READMEs specify what remains unmodeled: Ash atomic/persistence
paths, Mint protocol grammar and lifecycle cleanup, and actual bignum cost.
See [Havoc oracle semantics](https://github.com/houllette/rampart/blob/main/apps/havoc/ORACLES.md) for the generic library
contract and callback/isolation responsibilities.
