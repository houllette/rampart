# Foray

Foray is Rampart's embeddable, scope-safe web-fuzzing orchestration library. It
runs whole ffuf jobs through `Core.Runner`, streams each job's v2.2 NDJSON
matches into `%Core.Finding{}` values, and bounds aggregate pressure across
multiple jobs.

Foray is a library, not a CLI and not a native HTTP fuzzer. ffuf remains
responsible for request execution, matchers, filters, calibration, and
request-level concurrency.

## Properties

- Typed jobs, fuzz points, oracles, matches, and normalized Core findings
- Lazy streams with bounded match delivery and no unbounded result mailbox
- Small, explicit whole-process concurrency—never one BEAM task per payload
- A conservative aggregate HTTP request ceiling divided among active ffuf jobs
- Fail-closed URL scope checks before any process launch
- Derived result URL checks before findings leave the library
- Cancellable Core.Runner-owned processes and bounded ffuf `-maxtime`
- A native Stream API and a supervised Broadway topology
- Pluggable fuzz engines and synchronous audit/result hooks
- Versioned Foray finding persistence

## Installation

```elixir
def deps do
  [
    {:foray, "~> 0.1"}
  ]
end
```

Install ffuf separately. Foray rejects versions below **2.2.0** by default. The
minimum exists because older builds include a known decompression-bomb OOM
issue; operators should normally deploy the latest v2.2 patch release.

## Quick start

A scope policy is mandatory:

```elixir
scope = Foray.Scope.Allowlist.new!(["https://app.example.internal/"])

Foray.target("https://app.example.internal", scope: scope)
|> Foray.fuzz_path(wordlist: "content-discovery.txt")
|> Foray.match(codes: [200, 301, 403], size: :auto)
|> Foray.filter(size: 42)
|> Foray.rate(requests_per_second: 50, threads: 40, max_jobs: 2)
|> Foray.stream()
|> Stream.each(&MyFindingBus.publish/1)
|> Stream.run()
```

Nothing starts until the stream is enumerated. With no explicit or configured
policy, `Core.Scope.DenyAll` rejects the scan.

Parameter fuzzing uses the same plan:

```elixir
Foray.target("https://api.example.internal/search", scope: scope)
|> Foray.fuzz_param("q", wordlist: "injection/sqli.txt", class: :sqli)
|> Foray.match(regex: ~r/SQL syntax|ORA-\d+/, mode: :and)
|> Foray.mode(:clusterbomb)
|> Foray.stream()
```

`fuzz_header/3`, `fuzz_cookie/3`, and `fuzz_body/3` cover other ffuf input
positions. A fuzzed `Host` header maps to `category: :vhost`; query/body/cookie
positions map to `:param_injection`; URL positions map to `:exposed_path`.

## Corpus interchange

A non-empty list of `%Core.Seed{}` values can replace a file wordlist. Foray
materializes it lazily into a temporary, owner-lifetime corpus and removes the
file when the job stream closes. When ffuf reports the matching payload, the
original seed is attached to `%Core.Finding.seed`.

```elixir
seeds = [
  %Core.Seed{
    id: "havoc-counterexample-1",
    value: "' OR 1=1 --",
    classes: [:sqli],
    provenance: :counterexample,
    origin: {:havoc, "havoc:finding-id"}
  }
]

Foray.fuzz_param(scan, "q", wordlist: seeds, class: :sqli)
```

`Foray.promote/3` converts a finding-derived value back into a promoted Core
seed, preserving `{source, finding_id}` as its origin. `Foray.target/2` also
accepts URL-valued `%Core.Seed{classes: [:target]}` values, which is the direct
Portico-to-Foray handoff seam.

## Observe and validate

`Foray.observe/1` is the explicit observe-action alias for the lazy finding
stream. For a specific hypothesis, Foray advertises
`foray.http-match-reproduces.v1`:

```elixir
result = Foray.validate(candidate_finding, originating_scan)

case result.verdict do
  :confirmed -> result.findings
  :refuted -> []
  :inconclusive -> result.evidence
end
```

Validation replaces each plan wordlist with the exact recorded ffuf input,
disables recursion, limits execution to one whole ffuf job at a time, preserves
the original scope/rate/request configuration, and confirms only if the same
stable finding identity appears. A replayed matcher result proves that the HTTP
observation reproduced; it does not upgrade an error signal into exploitability
that the matcher did not establish. The result carries a concrete input-map
seed. `Foray.validation_actions/0` exposes the machine-discoverable action.

## Rate governance: two different controls

A Broadway job rate is **not** an HTTP request rate. Foray deliberately keeps
them separate:

- `Foray.rate/2` defines the aggregate HTTP ceiling, ffuf threads, whole-job
  concurrency, delay, and maximum job duration.
- Foray computes `floor(aggregate_rate / effective_job_concurrency)` and passes
  that conservative share as each process's ffuf `-rate`.
- Effective process concurrency never exceeds the aggregate numeric rate, so
  rounding cannot exceed the requested ceiling.
- `Foray.job_rate_limit/2` controls how quickly coarse jobs enter Broadway. It
  is useful for launch pacing but must not be presented as request governance.

This static allocation may underuse the ceiling when fewer jobs are active. v1
chooses a verifiable safety bound over a dynamic controller that cannot observe
ffuf's individual requests.

## Scope model

`Foray.Scope.Allowlist` matches scheme, normalized host, effective port, and
segment-bounded path prefix. `https://*.example.internal/` explicitly permits
subdomains but not the apex. Userinfo and URL fragments are rejected.

Every concrete job is authorized as a collection before runtime checks or ffuf
launches. A denied target prevents all jobs from starting. Each matched URL is
normalized and rechecked before it is emitted.

ffuf-native recursion is available through `Foray.recurse/2` and is constrained
to its documented clusterbomb/URL-ending-in-`FUZZ` mode. See
[SECURITY.md](SECURITY.md) for the unavoidable scope limits of payload
substitution and native recursion.

## Oracle

Matchers and filters are first-class `%Foray.Oracle{}` data, not arbitrary ffuf
arguments. Supported criteria map to ffuf's code, line, regex, size, first-byte
time, and word-count flags. `size: :auto` enables auto-calibration.

```elixir
scan
|> Foray.match(codes: [200, 300..399], regex: "admin", mode: :and)
|> Foray.filter(size: [0, 42], time: {:gt, 5_000}, mode: :or)
|> Foray.auto_calibrate(strings: ["not-found-probe"])
```

## Multi-input modes

- `:clusterbomb` is ffuf's Cartesian-product default.
- `:pitchfork` advances inputs in lockstep.
- `:sniper` accepts one input source and transforms configured positions into
  ffuf's paired `§...§` templates.

Custom keywords are validated and wordlist conflicts fail while building the
plan.

## Input-command bridge

The explicit wordlist form `{:input_command, command, count}` exposes ffuf's
`-input-cmd` seam for future Havoc integration:

```elixir
Foray.fuzz_path(scan,
  wordlist: {:input_command, "payload-generator $FFUF_NUM", 100}
)
```

ffuf executes this value through a shell. Treat it as trusted operator code;
never populate it from scanner output or untrusted user input. Foray itself does
not generate or mutate payloads. ffuf reserves `:` as its command/keyword
separator, so Foray rejects input-command strings containing a colon rather than
silently executing a truncated command.

## Supervised Broadway topology

Use `Foray.Pipeline` directly when a fuzz run belongs in an application's
supervision tree. The finding sink is synchronous and remains in the
backpressure path.

```elixir
children = [
  {Foray.Pipeline,
   name: MyApp.WebFuzz,
   scan: scan,
   on_finding: &MyApp.FindingBus.publish/1,
   on_complete: &MyApp.WebFuzz.finished/1}
]
```

Processor concurrency is whole ffuf-process concurrency. Each processor runs
one job and streams its findings synchronously; it never fans payloads into
additional tasks. The producer implements `prepare_for_draining/1` and drops
queued jobs while in-flight processes finish or reach their bounded `-maxtime`.

## Custom engines

A custom engine implements `Foray.Fuzz.Engine`, validates its own namespaced
options, and returns a lazy enumerable of `%Core.Finding{}` values for one
`%Foray.Job{}`. Register aliases with:

```elixir
config :foray, :engines, %{feroxbuster: MyApp.FeroxbusterEngine}
```

All external commands still belong behind `Core.Runner`.

## Persistence and telemetry

`Foray.Result` owns a versioned JSON projection of Foray findings:

```elixir
json = Foray.Result.encode!(finding)
{:ok, %Core.Finding{} = restored} = Foray.Result.decode(json)
```

See [TELEMETRY.md](TELEMETRY.md) for the shared
`[:core, :foray, ...]` contract.

## Development

From the Rampart umbrella root:

```sh
mix test apps/foray/test
mix precommit
mix dialyzer
```
