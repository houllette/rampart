# RampartSAST research notes

The first engine spike followed source review of:

- Sobelow 0.15.0 at commit
  `4eb7d16dc09a9fe26b388c30797cc0b8fb386808`; and
- Credo `master`/1.8.0-dev at commit
  `ea1ccb9023b44eecbe079dc4bfd48cca4e8b0187`.

The review informed architecture and rule semantics. RampartSAST does not copy
source from either project and has no runtime dependency on either package.
Sobelow is Apache-2.0 and Credo is MIT; RampartSAST remains independently
implemented under Rampart's MIT license.

## Corrected product boundary

A catalog of hand-written sink rules is useful, but making that catalog the
center of RampartSAST would recreate a smaller Sobelow. That is not sufficient
for an autonomous security-research workflow.

RampartSAST instead owns deterministic static reconnaissance:

- parse bounded Elixir and Erlang source snapshots without executing them;
- inventory ordinary structure and relationships at high recall;
- expose exact, queryable facts about definitions, calls, directives,
  dependencies, versions, and package use;
- run optional domain-specific signal packs over the same snapshots;
- preserve uncertainty and source provenance; and
- replay the exact static predicate that produced a signal.

Lemieux or another external harness owns adaptive reasoning: correlate noisy
facts, decide which security/abuse chain is plausible, request more slices or
artifact inspection, choose a deterministic Rampart validator, and stop only
when the concrete claim is confirmed, refuted, or explicitly inconclusive.
Rampart must expose better instruments than grep without putting an LLM or an
attack-story engine inside the library.

## Lessons retained from Sobelow

Sobelow's most valuable contribution is Elixir/Phoenix security knowledge:

- rule families for command/SQL injection, XSS, traversal, dynamic evaluation,
  atom exhaustion, deserialization, configuration, routes, and dependencies;
- a metadata pass for controllers, routers, endpoints, imports, and repos;
- separate source, configuration, template, and dependency inputs;
- source locations, confidence qualifications, SARIF, and suppressions; and
- concurrent file analysis with deterministic output.

That knowledge should seed optional providers and signal packs. It should not
force a Phoenix-only engine, define the project fact model, or turn a syntactic
sink into a vulnerability verdict.

## Lessons retained from Credo

Credo provides the stronger general analysis architecture:

- explicit execution data instead of implicit CLI/global flow;
- parse-once snapshots with hashes, AST, comments, lines, and validity;
- source and project check contracts;
- explicit plugin modules/options;
- concurrent bounded work followed by stable sorting;
- exact issue locations; and
- source-local controls.

RampartSAST retains parse-once snapshots, invocation-local state, explicit
host-selected code, source/project rule scopes, finite limits, deterministic
normalization, and comments as data. It deliberately has a much smaller
presentation/configuration layer because it is a library primitive.

## Boundaries intentionally changed

### Facts, signals, and bugs are different things

An inventory fact says that syntax exists in an exact source snapshot. A rule
signal says a versioned predicate matched that syntax. A security hypothesis
combines facts into a concrete falsifiable claim. A confirmed bug requires the
appropriate deterministic validation. These stages must not collapse into one
`confidence` score.

### Static confidence is not taint

A controller role, parameter-shaped variable, dangerous API, package version,
or apparent call path does not establish attacker control or runtime
reachability. Argument shape, alias resolution, package ownership, framework
role, and sanitizer observations are qualifications with explicit provenance.

### Parse failure is never an empty program

Invalid/timed-out sources produce error diagnostics and an incomplete scan.
Partial facts remain useful, but a consumer cannot call the result a complete
inventory or a clean assessment.

### Host authority selects executable analysis code

Rules and context providers are module values selected by the host. Inert IDs
select only among already supplied modules. Source text, model output, package
metadata, and transcripts are never converted into modules or atoms.

### Dependency use requires provenance

Hex application names, package names, and Elixir/Erlang module names do not
share a reliable naming convention. RampartSAST therefore does not guess that
`Phoenix.HTML` belongs to `phoenix_html`. A host may supply a module-owner map,
use the bounded BEAM atom-table reader, or index checksummed dependency source
components. Package-use facts record the provenance-backed resolution. Ambiguous
ownership is omitted instead of guessed, and artifact code is never loaded.

### Stable signal identity excludes line movement

Rule anchors hash metadata-free Elixir or Erlang AST with SHA-256 and combine it
with versioned rule ID, repository-relative path, and deterministic occurrence.
The source hash records the exact snapshot. Inventory fact identity is
snapshot-specific because it describes the current graph rather than a durable
security verdict.

### Suppression is evidence, not deletion

The first reporting suppression is one versioned rule, next line, mandatory
reason. Suppressed observations remain available and do not alter validation of
whether the syntax exists. Broad high-recall inventory facts are not suppressed.

### Bounded execution is correctness

File count, file bytes, total bytes, parser time, context-provider time, rule
time, and concurrency are finite. Limit failures make a scan incomplete or a
validation inconclusive rather than silently truncating evidence.

## Deterministic substrate implemented in this spike

The priority is not the number of vulnerability rules. It is how effectively an
agent can investigate and validate a chain without inventing facts. The current
substrate now includes:

1. **Package provenance:** checksummed target/dependency source components,
   origin on every fact, host module-owner maps, and bounded direct BEAM
   atom-table inspection without loading artifact modules. Conflicting ownership
   remains unresolved.
2. **Cross-package workspaces:** collision-free target and selected dependency
   source indexing with package, version, path, and component checksum.
3. **Resolution:** source aliases, explicit import filters, local calls,
   explicitly ambiguous imports and dynamic receivers, behavior/callback
   declarations, protocol implementations, and syntactic callback implementation
   edges.
4. **Bounded graph instruments:** callers/callees/effects, callback edges,
   shared-variable candidates, and same-control-region candidates with explicit
   depth/node/page limits.
5. **Typed behavior vocabulary:** noisy facts for configuration and environment
   reads, authorization/authentication-shaped functions, OTP messages and
   requests, shared/process state, files/network/processes/NIFs, dynamic code,
   deserialization, cryptography, randomness, and resource amplification.
6. **Ecosystem and agent inputs:** Mix and Rebar manifests/locks, exact locked
   versions, stable inventory IDs, content-addressed bounded artifacts, and
   bounded query pages with continuation metadata.
7. **Disposable untrusted-source scanning:** `RampartSAST.Isolated` runs the
   entire source-facing scan in a short-lived OS-level BEAM instance, projects
   only bounded string-keyed data, and turns worker/response failures into
   incomplete results. Tests prove source-only atoms do not enter the parent VM.
8. **Evaluation gate:** the repository-local `mix rampart.eval` task checks
   real command, deserialization, filesystem, and Plug response boundaries;
   ambiguous localization; an explicitly unsupported OTP process boundary; an
   attributed historical Plug regression; and adapted terminal-control,
   canonical-codec, quoted-parameter, cache-tenancy, and actor-paired Ash field-
   policy contracts pinned to disclosed vulnerable/fixed revisions. It covers
   exact-oracle replay, negative controls, injected harness failure,
   fail-closed verdicts, and broad efficiency/evidence budgets. Metamorphic tests
   preserve semantic relationships while retaining snapshot-specific identity.
9. **Package behavior seam:** optional, versioned Plug, Phoenix, Ecto, and Ash
   classifiers contribute noisy reviewed API semantics without introducing
   runtime framework dependencies or making the engine application-specific.
   Ash annotations retain aggregate/field, read, authorization-decision, and
   tenant-context boundaries while expression facts expose options separately.
10. **Lexical module restoration:** exact historical `Plug.Static` sources exposed
    a nested-module scope leak. Module ranges now use parser end metadata, nested
    module names retain their lexical parent, and definitions after an inner
    module return to the outer module.
11. **Bounded expression relationships:** Elixir assignments and Elixir/Erlang
    call arguments now retain syntax-only expression kind, literal status,
    source variables, one-based argument position, and a UTF-8-safe 240-byte
    preview. These facts make literal options, interpolated output, and package
    API arguments directly queryable without pretending to prove flow.

## Next gates

1. Retain the isolated worker's Linux `/proc` RSS/high-water and optional cgroup
   v2 current/peak/limit measurements in CI history. Define the authority and
   artifact contract an external host uses for stronger deployment isolation;
   do not make RampartSAST manage containers. Add isolated exact-static replay
   without restoring source or executable authority from portable output.
2. Add scope-correct lexical alias/import semantics, captures, dynamic `apply`,
   macro-expansion provenance, and runtime protocol/callback dispatch candidates
   while preserving ambiguity.
3. Build assignment-aware intra/interprocedural dependence and real control-flow
   graphs on top of the bounded binding/argument relationships. The expression
   facts, shared-variable slices, and control-region slices remain syntax
   neighborhoods, not flow proof.
4. Inspect exports/debug info and ingest Hex/Rebar archives under explicit byte,
   file, decompression, and checksum limits; preserve package → application →
   module → version provenance.
5. Add templates, application/release config, routes, Phoenix pipelines, Ecto
   query shapes, and package-specific semantics through typed providers rather
   than global engine branches.
6. Let signal packs advertise compatible proof actions and required fixtures;
   keep actual cross-tool planning in the external adapter/harness.
7. Expand the versioned evaluation corpus beyond the initial real sinks, package
   classifiers, trace-overhead measurement, partial direct-message/GenServer/
   Task/ETS/process-dictionary feasibility matrix, OTP refusal, and digest-pinned
   historical Plug source. Add macro-generated, protocol/callback dispatch,
   dependency-misuse, full pinned package/application, adversarial OTP-boundary,
   and Erlang cases plus reviewed differential observations from Sobelow, Reach,
   and Credo without treating their output as ground truth.
8. Add pure JSON/SARIF projections for portable SAST results and stable benchmark
   history suitable for CI trend analysis.

Sobelow-derived checks remain useful coverage. They are one source of security
vocabulary feeding this substrate, not the north-star architecture.
