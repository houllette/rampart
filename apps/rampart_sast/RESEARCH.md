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

## Next gates

1. Isolate untrusted parsing from the long-lived VM so source atom interning
   cannot exhaust the host node; current byte/time limits do not solve that
   process-global risk.
2. Add scope-correct lexical alias/import semantics, captures, dynamic `apply`,
   macro-expansion provenance, and runtime protocol/callback dispatch candidates
   while preserving ambiguity.
3. Add assignment-aware intra/interprocedural dependence and real control-flow
   graphs. Current shared-variable/control-region slices are neighborhoods, not
   flow proof.
4. Inspect exports/debug info and ingest Hex/Rebar archives under explicit byte,
   file, decompression, and checksum limits; preserve package → application →
   module → version provenance.
5. Add templates, application/release config, routes, Phoenix pipelines, Ecto
   query shapes, and package-specific semantics through typed providers rather
   than global engine branches.
6. Let signal packs advertise compatible proof actions and required fixtures;
   keep actual cross-tool planning in the external adapter/harness.
7. Add pure JSON/SARIF projections and an evaluation corpus spanning vulnerable,
   fixed, ambiguous, macro-generated, and dependency-misuse Elixir/Erlang cases.

Sobelow-derived checks remain useful coverage. They are one source of security
vocabulary feeding this substrate, not the north-star architecture.
