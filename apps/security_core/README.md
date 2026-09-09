# Security Core

`security_core` is Rampart's minimal shared contract and cross-cutting runtime. It carries no scanning, fuzzing, or tool-specific logic and depends on no other Rampart application.

The Hex package/application is named `security_core`; its public modules use the `Core.*` namespace.

## Contracts

- `%Core.Finding{}` — normalized cross-tool observation
- `%Core.Seed{}` — corpus, payload, target, promoted-finding, and counterexample interchange
- `%Core.Hypothesis{}` — structured pre-finding claims, including IAST taint claims
- `Core.Validation` / `Core.Validator` — discoverable hypothesis-in, verdict-and-proof-out actions
- `Core.Validation.Binding` — host-owned authority behind inert subject references
- `Core.Validation.Wire` — transcript-safe, versioned JSON projections for tool transports
- `Core.Scope` / `Core.Scope.Policy` — deny-by-default authorization dispatch
- `Core.Telemetry` — suite event naming and span helpers
- `Core.Runner` — swappable process seam, backed by Exile by default

## Findings

A finding is a projection, not a replacement for a tool's native model. `raw` remains an opaque native record.

```elixir
%Core.Finding{
  id: Core.Finding.dedupe_id(:portico, ["endpoint", "192.0.2.10", :tcp, 443]),
  source: :portico,
  category: :exposed_service,
  locus: %{ip: "192.0.2.10", port: 443, protocol: :tcp, service: "https"},
  confidence: :high,
  evidence: "443/tcp open (https)",
  raw: port,
  observed_at: DateTime.utc_now()
}
```

Dedupe identities contain ordered stable scalar values. Mutable hostname and service fingerprint data belongs in `locus` but not in the identity.

### v0.1 lock decisions

- Core owns `dedupe_id/2`; tools supply an ordered, source-specific identity.
  A fixed-arity helper would overfit Core to Portico's IP/protocol/port tuple.
- `locus` remains a source-shaped map. Portico populates scalar `ip`,
  `hostname`, `port`, `protocol`, `service`, `product`, and `version` values;
  future tools can add joinable HTTP/code fields without a premature typed
  union.
- The severity and confidence enums are sufficient interchange labels. CVSS or
  another scoring system remains tool-/triage-owned until two consumers need a
  common numeric contract.
- Core does not derive `Jason.Encoder` or define persistence for findings in
  v0.1 because `raw` intentionally contains arbitrary tool structs. The
  deliberately lossy `Core.Validation.Wire` projection is for tool and audit
  interchange, not a replacement persistence schema: it omits `raw` and seed
  values by default. The transport still applies its configured byte limit.

## Seeds

`%Core.Seed{}` is the corpus unit that carries target values, wordlist entries,
promoted findings, and counterexamples between Rampart tools. `classes` is a
list of tags such as `[:target]` or `[:sqli]`; `origin` joins a promoted seed
back to `{source_tool, finding_id}`. Core transports seeds but does not interpret
payload semantics.

## Observe and validate

Rampart tools expose observations as `%Core.Finding{}` streams and advertise
versioned validation actions through `Core.Validator`. Validation is a tool
operation, not an agent prompt: the same request produces a verdict from the
same declared procedure whether a human, CI job, or agent harness invokes it.

```elixir
[action] = Portico.validation_actions()
request = Core.Validation.request(action, candidate_finding)
result = Core.Validation.run(Portico.Validator, request, scope: scope)

case result.verdict do
  :confirmed -> result.findings
  :refuted -> []
  :inconclusive -> inspect(result.evidence.facts)
end
```

The contract is:

- inputs are an identified `%Core.Finding{}`, concrete `%Core.Seed{}`, or
  `%Core.Hypothesis{}`;
- action IDs end in an explicit semantic version such as `.v1`;
- verdicts are exactly `:confirmed | :refuted | :inconclusive`;
- evidence has a human summary plus structured facts and optional artifacts;
- every result carries a concrete replay seed;
- confirmed results carry at least one normalized finding with its own proof
  seed; and
- `Core.Validation.run/3` emits
  `[:core, tool, :validation, :start | :stop | :exception]` and finding events.

`Core.Hypothesis` handles claims that are not findings yet. Its source-shaped
locus is intentionally suitable for future IAST claims such as a Phoenix param,
OTP message, or Nerves input reaching a named sink. Choosing which action to
invoke and chaining results belongs to a consumer; Core performs no reasoning.

### Host bindings and wire results

An agent or RPC adapter must not accept scope policies, scanner engines, target
functions, or originating scan plans from its caller. Bind those capabilities
on the host and resolve only inert subject references:

```elixir
binding =
  Core.Validation.Binding.new!(Foray.Validator, "foray.http-match-reproduces.v1",
    resolver: fn :finding, id -> findings.fetch(id) end,
    validator_options: [scan: authorized_scan]
  )

{:ok, result} =
  Core.Validation.Binding.invoke(binding, %{
    "subject_type" => "finding",
    "subject_id" => finding_id
  })

model_text = Core.Validation.Wire.model_text(result)
structured_result = Core.Validation.Wire.result(result)
```

Bindings intentionally contain executable state and are not serializable. A
host must recreate them under current authority after a session resumes.
Unknown invocation fields are rejected so a caller cannot smuggle a replacement
scope or target into validator options.

`Core.Validation.Wire.input_schema/1` describes the two-field input above.
`Wire.result/2` returns a string-keyed, SHA-256-sealed JSON object suitable for a
structured tool result. It excludes native `raw` values and the concrete replay
payload by default; large proof belongs in content-addressed artifacts. Setting
`include_seed_value: true` is an explicit host disclosure decision, and invalid
UTF-8 binaries are represented by size and digest rather than written as broken
JSON.

See the repository-level `LEMIEUX_INTEGRATION.md` for the reviewed Lemieux
adapter direction and the distinction between harness discovery confirmation
and security validation.

## Scope

No policy authorizes nothing:

```elixir
Core.Scope.authorized?(target, nil)
#=> false
```

Policies implement `Core.Scope.Policy` and may be passed as a state struct, `{module, state}`, or module. `Core.Scope.guarded_launch/4` checks authorization, emits `[:core, tool, :launch]`, and only then invokes the launch function.

Tools must re-check targets derived during execution.

## Telemetry

```elixir
Core.Telemetry.span(:portico, :enrichment, %{target: target}, fn ->
  result = enrich(target)
  {result, %{target: target, outcome: :ok}}
end)
```

Events use `[:core, tool, stage, :start | :stop | :exception]`. Findings emit `[:core, tool, :finding]`; authorized binary launches emit `[:core, tool, :launch]`. Validation dispatch uses the `:validation` stage and reports its verdict and finding count on stop. This gives every analysis mode one event namespace without making Core depend on a tool.

Manual span tokens support lazy enumerables whose execution crosses suspended continuations.

## Runner

```elixir
Core.Runner.stream(["scanner", "--json"], stderr: :consume)
Core.Runner.run(["scanner", "--version"], timeout: 2_000)
```

`stream/2` emits bounded chunks; scanner-specific record parsing stays in the tool. `run/2` is bounded and returns `{output, exit_status}`.

Override the backend globally:

```elixir
config :security_core, runner: MyCgroupRunner
```

Or per invocation:

```elixir
Core.Runner.stream(argv, backend: MyRunner)
```

The Exile backend intentionally uses owner-death cleanup and bounded `await_exit`. Core does not expose Exile's direct signal API. A hard SIGKILL of the whole BEAM remains outside an in-process backend's cleanup envelope.

## Development

From the umbrella root:

```sh
mix test apps/security_core/test
mix precommit
```
