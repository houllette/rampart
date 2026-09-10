# Havoc

Havoc is Rampart's in-process security-property library for Elixir. It adds
adversarial StreamData generators, conservative security oracles, durable
counterexample replay, and normalized `%Core.Finding{}` output to ordinary
ExUnit suites.

Havoc builds on StreamData rather than replacing it: StreamData owns random
generation, shrink trees, and property checking. Havoc owns only the security
layer that is missing from correctness-oriented property testing.

> Havoc tests code in your own test VM. It starts no external binary, sends no
> network traffic itself, and intentionally does not use `Core.Runner` or
> `Core.Scope`.

## Installation

Add Havoc in the environment where security properties compile and run:

```elixir
def deps do
  [
    {:havoc, "~> 0.2", only: [:dev, :test]}
  ]
end
```

Havoc depends on `security_core ~> 0.1` and StreamData. StreamData is a regular
Havoc package dependency—not an `only: [:test, :dev]` internal dependency—so a
published Havoc package can compile its public generators and macros when it is
itself selected by the consumer.

## A security property

```elixir
defmodule MyAppWeb.SearchSecurityTest do
  use MyAppWeb.ConnCase
  use Havoc.Case

  security_property "search resists injection",
    generator: Havoc.Gen.injection([:sqli, :xss, :path_traversal]),
    classes: [:search_input],
    locus: %{endpoint: "/search", param: "q"},
    oracles: [:no_500, :no_reflection, :no_injection_signal],
    runs: 200 do
    conn = get(build_conn(), "/search?q=#{URI.encode_www_form(payload)}")
    havoc_assert(conn, payload)
  end
end
```

`payload` is bound by `security_property/3`. The final body value is evaluated
automatically, so the last line may also be just `conn`. `havoc_assert/2` is
useful when the block performs more than one check or should make the assertion
point explicit.

On a violation Havoc:

1. lets StreamData shrink the generated input;
2. persists the concrete shrunk value, not StreamData's random seed;
3. emits one `%Core.Finding{source: :havoc}` per oracle violation;
4. emits `[:core, :havoc, :finding]` telemetry; and
5. raises `Havoc.PropertyError` so ExUnit reports a failed property.

On later runs, matching counterexamples replay in stable order before random
generation. Known cases therefore survive changes to generators and fail fast.

## Validate one concrete hypothesis

Property search discovers candidates; `Havoc.validate/3` performs no generation
or shrinking and evaluates exactly one seed through the declared target and
oracles:

```elixir
result =
  Havoc.validate(counterexample_seed, &MyParser.parse/1,
    property_id: "MyParser:untrusted-input",
    property_name: "parser rejects unsafe terms",
    module: MyParserSecurityTest,
    oracles: [:no_crash]
  )
```

A reproduced oracle violation returns `:confirmed`, persists the exact payload,
and emits normalized findings. A completed execution returns `:refuted` only
when **every** configured oracle actually passes. If an oracle skips because its
required observation is absent, the exact result is `:inconclusive`; missing
evidence is never a false refutation. Broken fixtures or oracle implementations
are likewise inconclusive rather than laundering a test failure into a security
finding. Every result has structured evidence and a replay seed.

Reusable observations and contracts cover more than response matching:

```elixir
alias Havoc.Observation.{Cache, Codec, Differential, FieldPolicy, HTTPParameter, State}

canonical =
  Havoc.validate(seed, fn input ->
    decoded = MyCodec.decode!(input)
    Codec.accepted(input, decoded, MyCodec.encode(decoded))
  end,
    property_id: "MyCodec:canonical",
    property_name: "accepted identifiers have one encoding",
    module: MyCodecSecurityTest,
    oracles: [:canonical_encoding]
  )

policy_oracle =
  Havoc.Oracle.differential(
    :protected_data_noninterference,
    fn control, treatment, _case ->
      control.protected_fields == [] and treatment.protected_fields == []
    end,
    category: :authz_bypass
  )

state_oracle =
  Havoc.Oracle.bounded_state_growth(
    max_delta: 5,
    require_reclaimed: true,
    reclaimed_tolerance: 0
  )

header_observation =
  HTTPParameter.authentication(header, "resource_metadata", intended_url,
    input: tenant,
    scheme: "Bearer"
  )

cache_observation = Cache.new!(two_tenant_measurements)
field_observation = FieldPolicy.new!(actor_paired_path_measurements)
```

`%Differential{}` and `%State{}` normalize paired and lifecycle observations.
`%HTTPParameter{}`, `%Cache{}`, and `%FieldPolicy{}` add bounded parsed-header,
shared-cache replay, and actor/path visibility evidence. The application fixture
still owns independent actors, tenants, effects, controls, cache behavior,
counters, cleanup, and preconditions. `:terminal_safety` accepts captured
terminal output, and `:canonical_encoding` accepts `%Codec{}`. These actions
confirm only their precisely stated effect/invariant—not a generic claim of
exploitability.

`Havoc.validation_actions/0` advertises
`havoc.security-property-reproduces.v1` for transport-independent clients. The
action is ordinary deterministic Elixir code; an agent harness is optional and
owns only the decision to invoke it.

## Resource contracts and fragmented inputs

Havoc also provides explicit-unit length and incremental parser budget checks:

```elixir
length_oracle = Havoc.Oracle.bounded_length(unit: :bytes, max_length: 4096)
generator = Havoc.Gen.unicode_length(max_bytes: 8192, max_marks: 2048)

partitions = Havoc.Gen.byte_partitions(response_bytes, max_chunks: 32)
buffer_oracle = Havoc.Oracle.incremental_buffer_budget(max_bytes: 4096)
work_oracle = Havoc.Oracle.incremental_work_budget(unit: :digit_folds, max_work: 16)

target = fn chunks ->
  Havoc.Observation.Incremental.capture(chunks, initial_state,
    fn chunk, state -> MyParser.step(chunk, state) end,
    fn state -> MyFixture.measure(state) end,
    work_unit: :digit_folds, max_input_bytes: 65_536, max_chunks: 32
  )
end
```

The step returns `{:incomplete | :accepted | :rejected, next_state}`. The
measurement adapter supplies `:retained_bytes` and/or a monotonic cumulative
`:work` counter. Use the resulting target and oracle with `security_property`
or replay an exact chunk-list seed through `Havoc.validate/3`. StreamData owns
generation and shrinking. `Length.accepted(input, actual_output)` separately
records a length-policy boundary; the oracle independently counts that output.
See [oracle semantics](ORACLES.md) for unknown measurements, counter attribution,
positive controls, callback deadlines and limits on the conclusions.

## Tiered CI

Run replay plus random generation with ordinary ExUnit:

```sh
mix test
```

Run only deterministic persisted regressions on every fast CI pass:

```sh
MIX_ENV=test mix havoc.replay
```

`mix havoc.replay` forwards paths and filters to `mix test`. Nightly or
on-demand jobs can increase `:runs` and `:max_run_time` per property.

## Dynamic targets

Havoc 0.2 can conservatively derive text-input targets from public function
`@spec`s and Phoenix dynamic route paths:

```elixir
targets = Havoc.Target.Function.derive(MyApp.Parser, only: [{:parse, 2}])

security_targets "specified parsers resist hostile text",
  targets: targets do
  Havoc.Target.Function.invoke(target, payload,
    arguments: ["replaced", [mode: :strict]]
  )
end
```

`Havoc.Target.Phoenix` has no Phoenix dependency; it calls
`Phoenix.Router.routes/1` only when Phoenix is present in the consumer. Router
data can derive path parameters, but not query/body schemas or authentication
fixtures. Read [TARGETS.md](TARGETS.md) for the fail-closed derivation rules.

## Optional coverage-guided backend

The separate `havoc_proper` package uses PropEr targeted PBT with OTP line
coverage as fitness. It is separate because ordinary Havoc generators remain
StreamData generators and because PropEr/PropCheck are GPL-3.0 dependencies.
Use it for serialized (`async: false`) research/nightly properties; standard
Havoc remains the default deterministic/shrinking path.

## Generators

```elixir
Havoc.Gen.injection([:sqli, :xss])
Havoc.Gen.injection([:http_parameter_injection])
Havoc.Gen.malformed()
Havoc.Gen.boundary(max_length: 16_384)
Havoc.Gen.all()
```

The compact built-in corpus is original to Havoc and intentionally inert. It
uses marker payloads, `.invalid` SSRF destinations, and non-destructive command
probes. Havoc does not vendor SecLists; reviewed external lists can be converted
to `%Core.Seed{}` values with `Havoc.Corpus.export/2` and imported explicitly.

## Suite interchange

```elixir
seed = Havoc.promote(foray_finding, failing_payload, classes: [:sqli])
{:ok, 1} = Havoc.Corpus.import([seed], property_id: "MyTest:search")

payload_seeds =
  Havoc.Gen.injection([:xss])
  |> Enum.take(500)
  |> Havoc.Corpus.export(classes: [:xss])
```

The exported seeds can become a Foray wordlist. Portico and Foray are not Havoc
dependencies; all interchange goes through Core.

Imports merge seeds by ID once, retaining the last occurrence of an ID in the
batch and preserving other stored seeds. The complete encoded corpus must fit
16,777,216 bytes. An oversized update raises `Havoc.Corpus.Error` with
`:corpus_too_large` before replacing the existing file, so accepted durable
proof remains reloadable.

## Important oracle posture

Havoc reports invariant violations and high-value signals, not automatic exploit
confirmation. Raw reflection can be legitimate application behavior, and a
database error proves disclosure rather than injection by itself. The defaults
are intentionally conservative:

- `:no_reflection` checks exact raw reflection only in known HTML responses and
  skips unknown content types;
- `:no_injection_signal` uses specific database-error signatures;
- missing status/body fields are skipped unless the oracle is configured to
  fail closed, and a skipped oracle makes exact validation inconclusive;
- `:authz_invariant` cannot be named as a bare atom—it requires an independent
  policy/result predicate rather than trusting the implementation under test;
- `:terminal_safety` classifies captured bytes rather than guessing data origin;
- `:canonical_encoding` requires an explicit decode/re-encode observation;
- `:quoted_parameter_integrity` parses the emitted authentication header and
  checks one independently intended value;
- `:cache_partition_noninterference` confirms only exact first-partition replay
  against a differing uncached second control;
- `:field_policy_noninterference` requires privileged controls for every paired
  restricted actor/path observation; and
- differential and state-growth contracts require fixture-owned controls,
  counters, cleanup, and security thresholds.

Read [ORACLES.md](ORACLES.md) before treating a signal as a vulnerability.

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Oracle semantics and false-positive posture](ORACLES.md)
- [Corpus schema, replay, and interchange](CORPUS.md)
- [Dynamic target derivation](TARGETS.md)
