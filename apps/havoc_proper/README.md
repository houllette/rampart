# HavocProper

HavocProper is the optional search-guided backend for Havoc. It combines
PropEr/PropCheck targeted property-based testing with OTP Cover line coverage
and optional bounded semantic-state features as fitness, while reusing Havoc's
oracles, Core findings, and persistent concrete corpus.

It is a separate package for two reasons:

1. ordinary Havoc generators remain StreamData generators and keep their normal
   shrinking semantics; and
2. PropEr and PropCheck are GPL-3.0 dependencies. Keeping the adapter separate
   avoids imposing that dependency/license choice on every Havoc consumer.

Add it only to test environments:

```elixir
{:havoc_proper, "~> 0.1", only: [:dev, :test]}
```

## Use

Guided properties must run in an `async: false` ExUnit module because OTP Cover
instrumentation is node-global:

```elixir
defmodule MyParserGuidedSecurityTest do
  use ExUnit.Case, async: false
  use HavocProper.Case

  guided_security_property "parser explores deep paths",
    generator: HavocProper.Gen.injection([:sqli, :template_injection]),
    coverage_modules: [MyParser],
    oracles: [:no_crash, :no_injection_signal],
    search_steps: 2_000 do
    MyParser.parse(payload)
  end
end
```

The execution order is:

1. replay Havoc's persisted concrete corpus;
2. temporarily Cover-compile the explicitly listed modules;
3. let PropEr's simulated-annealing or hill-climbing strategy propose inputs;
4. reset and measure distinct covered lines for each input;
5. optionally project stable, non-sensitive state-transition IDs with
   `:features` and an explicit `:feedback_id`;
6. maximize line count plus feature count, optionally plus a numeric
   `:fitness_bonus`;
7. retain bounded line- or feature-novel `%Core.Seed{provenance: :generated}`
   values; and
8. normalize any oracle violation through Havoc and persist its exact payload.

A host can set `:manifest_path` to atomically retain the property/search
configuration, feedback identity, runtime versions, and covered BEAM SHA-256.
The manifest identifies executable configuration, not a random trajectory.
PropEr's locked public API exposes no portable initial RNG seed, so evaluations
must retain exact generated inputs and concrete counterexamples separately.

```elixir
HavocProper.Guided.check!(generator,
  property_options ++ [
    coverage_modules: [MyProtocol],
    feedback_id: "protocol-state-v1",
    manifest_path: "tmp/protocol-guided-manifest.json",
    features: fn sample ->
      depth =
        case sample.evaluation do
          {:ok, observation} -> observation.depth
          {:error, failure} -> failure.observation.depth
        end

      for reached <- 0..depth, do: "state-depth:#{reached}"
    end
  ],
  target
)
```

Use `HavocProper.Guided.check!/3` directly for non-macro assembly. Guided search
is an execution driver and candidate-discovery path, not a validation verdict.
Recheck a retained or failing concrete seed with `Havoc.validate/3` when a
consumer needs Rampart's proof/refutation contract.

## Important limits

- OTP Cover is search fitness, not taint tracking or the future IAST sensor.
- OTP Cover is global and has no per-process coverage. The adapter serializes its
  own sessions and refuses to overwrite an existing non-empty Cover session,
  but unrelated async code can still contaminate measurements.
- A monitored session owner restores code after callback exceptions or caller
  death before releasing the lock. Nested sessions are refused while the
  outer session remains usable. The callback still executes in its caller.
- Cover measures executable lines, not true branches. Equal-length alternate
  paths may have equal fitness.
- Targeted PropEr properties do not have StreamData's shrink-tree guarantees.
  Havoc persists the concrete candidate that fired the oracle.
- Coverage alone is sparse feedback. `:features` can add at most 128 stable
  string IDs (256 bytes each and 8,192 bytes total) per candidate; the labels
  can be persisted and therefore must not contain secrets. `:fitness_bonus` can
  add a numeric branch-distance or progress signal without replacing coverage.
- Feature callbacks are host code. Invalid output or callback failure aborts the
  search and cannot become a security confirmation.
- Instrumented modules must have debuggable BEAM files on the code path.
- Work spawned by the target must finish before the target returns to appear in
  that candidate's measurement.

Read [RESEARCH.md](RESEARCH.md) before using the backend as a CI gate.
