# RampartSAST

RampartSAST is a deterministic **static reconnaissance and hypothesis-support
primitive** for Elixir and Erlang. It is intentionally not a replacement for
Sobelow, Credo, Semgrep, or a vulnerability verdict engine.

The default posture is high recall and high noise. RampartSAST inventories
ordinary program structure and package relationships that may become relevant
to security or abuse, then lets focused signal rules add security-specific
annotations. A Lemieux-style external agent can query those facts, construct a
narrow hypothesis, and drive Rampart's deterministic validators to confirm or
refute it.

```text
Elixir/Erlang source + manifests + host package inventory
                         │
                         ▼
       broad facts: modules · functions · calls · directives
                    dependency declarations · exact locks
                    package-use edges · argument shapes
                         │
             optional narrow rule signals
                         │
                         ▼
       external reasoning builds one concrete hypothesis
                         │
                         ▼
      SAST replay / IAST / Havoc / Foray / Portico validation
```

Sobelow's rule knowledge can become one optional signal pack. It is not the
shape of the engine or the limit of what the inventory records.

## Two deliberately different outputs

Rules are optional: pass `[]` to build only the broad inventory. Every scan
returns:

1. `result.inventory` — noisy `RampartSAST.Fact` relationships for deterministic
   search and graph-like slicing; and
2. `result.observations` — matches from explicit, host-selected rules.

Inventory facts currently include:

- Elixir and Erlang module and function definitions;
- normalized static/dynamic remote calls and explicitly ambiguous unqualified
  calls, with enclosing function/module, arity, pipeline shape,
  literal/dynamic argument shapes, and exact source spans;
- Elixir `alias`, `import`, `require`, `use`, protocol, behaviour, callback, and
  protocol-implementation relationships, including qualified or explicitly
  ambiguous unqualified calls and syntactic callback implementation edges;
- Erlang behaviour and callback declarations;
- Mix and Rebar dependency declarations plus exact Hex/Rebar lock versions;
- checksummed target/dependency component provenance;
- package-use edges derived from dependency source modules, bounded BEAM
  artifacts, or a host-supplied module inventory; and
- noisy typed behavior facts for process messages, OTP requests, shared/process
  state, filesystem/network/process/native-code effects, dynamic code,
  configuration/environment reads, deserialization, cryptography, randomness,
  authorization/authentication boundaries, and resource amplification.

These are facts about syntax in an exact source snapshot. A call fact is not a
claim that the call executes. A package-use edge is not a vulnerability. A
rule signal is not proof of attacker control, reachability, a broken control,
an abuse chain, or exploitability.

## Scan and query

```elixir
rules = RampartSAST.default_rules()

result =
  RampartSAST.scan("/path/to/project", rules,
    module_owners: %{
      "Plug" => "plug",
      "Phoenix" => "phoenix",
      "cowboy_req" => "cowboy"
    }
  )

# All normalized calls into Plug.Conn, including source-alias resolution.
plug_calls = RampartSAST.query(result,
  kind: :call,
  object_prefix: "Plug.Conn."
)

# References deterministically attributed to the package by host inventory.
plug_usage = RampartSAST.Inventory.package_usage(result.inventory, "plug")

# Exact resolved versions observed in Mix or Rebar lock data.
locks = RampartSAST.query(result, relation: :locks_dependency)

# A bounded page carries stable inventory identity and continuation metadata.
page = RampartSAST.Inventory.query_page(result.inventory,
  kind: :behavior,
  limit: 50,
  offset: 0
)
```

`module_owners` is host authority, not model-supplied executable configuration.
Its keys are module names or prefixes and its values are package identities.
Longest-prefix matching correlates calls/directives with packages. This lets a
host build the map from inspected dependency artifacts rather than guessing
that a module prefix always equals a Hex name. `RampartSAST.ModuleOwners`
extracts names directly from bounded BEAM atom-table chunks without loading the
modules. Ambiguous ownership is omitted instead of guessed.

`RampartSAST.scan_sources/3` accepts in-memory `{relative_path, source}` pairs.
`RampartSAST.scan/3` is the authorized-filesystem convenience API. It discovers
ordinary and umbrella `lib`, `src`, `include`, `test`, `config`, Mix, and Rebar
Elixir/Erlang inputs beneath a selected root. It supports explicit
include/exclude globs, rejects parent traversal, and does not traverse symbolic
links.

The scanner bounds file count, individual and total bytes, parser time,
context-provider time, behavior-classifier time, rule time, and concurrency.
Parse, context, inventory, rule, and
limit failures become diagnostics and make the scan incomplete; they never
become findings or a false clean result. Output order is deterministic.

## Signal rules are annotations, not the product

A rule exposes a versioned `RampartSAST.Rule.Descriptor` and implements either
`run_source/3` or `run_project/3`. The built-in starter pack identifies dynamic
atom creation, shell-parsed execution, Erlang term deserialization, and runtime
code evaluation. Those rules exist to exercise the signal/revalidation seam and
to provide useful sink hints. Growing a second hard-coded Sobelow catalog is not
the north star.

The built-in `RampartSAST.Behavior.BEAM` classifier already emits deliberately
noisy typed facts for broad API families and boundary-shaped function names.
Additional packs can cover trust-boundary candidates, parser transitions,
secret handling, framework configuration, and package-specific API misuse.
Each classification must still state its syntactic basis and classifier version.

Context providers receive parsed sources and return namespaced facts. The
default Elixir provider records modules, aliases, imports, `use` targets, and
common Phoenix roles without assigning trust. Framework and ecosystem knowledge
belongs in providers and packs, not branches in a global scanner.

Rule/provider modules are selected by the current host. Source text, reports,
and transcripts never become module names or atoms.

## Package and exploit-chain workflow

The intended dependency workflow is broader than CVE matching:

1. inventory direct and locked dependencies;
2. inspect dependency source or BEAM artifacts and supply authoritative module
   ownership;
3. identify which dependency APIs the target actually references and from which
   application functions;
4. query configuration, data-boundary, and effect facts around those uses;
5. let the external agent form a concrete misuse or exploit-chain hypothesis;
6. select the least-powerful deterministic validation action that can refute or
   confirm the claim; and
7. retain an exact replay seed for reporting and patch verification.

`RampartSAST.Component` and `RampartSAST.Workspace` now assemble checksummed
target and dependency sources under collision-free paths. Module definitions in
dependency components automatically provide package ownership. Explicit imports
and local definitions resolve when supported; unresolved or conflicting imports
remain candidate lists.

`RampartSAST.Graph` provides finite caller/callee/effect slices, syntactic
callback edges, same-control-region candidates, and a deliberately weak
shared-variable slice. Shared variables and shared control regions are candidate
neighborhoods, not data/control-flow proof. `RampartSAST.Inventory.Artifact`
creates a content-addressed, size-bounded full inventory payload for host-owned
storage while normal query pages remain bounded for agent context.

Macro-expansion provenance, complete lexical import/alias semantics, runtime
protocol/callback dispatch, assignment-aware interprocedural data/control flow,
debug-info call indexing, package archive ingestion, and pure SARIF remain
roadmap items. Uncertainty must remain explicit rather than hidden behind a
confidence score.

## Cross-package and graph examples

```elixir
target = RampartSAST.Component.new!(
  id: "target",
  kind: :target,
  sources: [{"lib/app.ex", target_source}]
)

dependency = RampartSAST.Component.new!(
  id: "parser-dependency",
  kind: :dependency,
  package: "parser_dependency",
  version: "1.2.3",
  sources: [{"lib/parser.ex", dependency_source}]
)

result = RampartSAST.Workspace.inventory([target, dependency])

slice = RampartSAST.Graph.callees(
  result.inventory,
  "App.decode/1",
  max_depth: 3,
  max_nodes: 200
)

artifact = RampartSAST.Inventory.Artifact.encode(result.inventory)
manifest = RampartSAST.Inventory.Artifact.manifest(artifact)
```

The payload is intentionally absent from `manifest`; a Lemieux adapter stores it
under host authority and returns the content-addressed reference plus bounded
query pages.

## Suppressions and CI

The optional rule-suppression syntax is local, versioned, and reason carrying:

```elixir
# rampart:suppress-next-line sast.unsafe-atom.v1 -- bounded internal enum
String.to_atom(value)
```

Erlang uses the same directive with `%`. Malformed attempts produce diagnostics;
suppressed signals remain in `result.suppressed`, and validation ignores the
reporting suppression.

The Mix task treats rule matches as expected reconnaissance, not build failures:

```sh
mix rampart.sast --exit
```

`--exit` fails an incomplete scan. Add `--fail-on-signals` only for a repository
that has deliberately adopted the selected starter rules as policy.

## Exact static replay

A rule observation can be projected into `%Core.Finding{}` with an exact source
snapshot and re-run through `RampartSAST.validate/2`. Validation confirms only
that the same host-selected rule, file, metadata-free AST anchor, and occurrence
remain. It refutes only after a complete re-scan. Parse errors, crashes, missing
project sources, and deadlines are inconclusive.

That verdict means **the static signal is present or absent**. It does not
confirm or refute the security bug the external workflow is investigating.
Dynamic claims belong to the appropriate IAST, mutation, property, HTTP, or
network validator.

See [RESEARCH.md](RESEARCH.md) for the pinned Sobelow/Credo review, the pivot
away from scanner cloning, and the next deterministic capabilities.
