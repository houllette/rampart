# Foray architecture

## Architecture gates

1. ffuf output becomes validated domain data and normalized Core findings.
2. Backpressure reaches each ffuf stdout stream without buffering match floods.
3. Orchestration concurrency counts whole ffuf processes, never payloads.
4. Match/filter oracles and engines are typed, validated, and replaceable.
5. Scope, request-rate bounds, cancellation, and drain are load-bearing safety
   controls.
6. A concrete HTTP match can be replayed through a versioned validation action
   without changing what its matcher proves.

## Plan and job boundary

The fluent API builds an immutable `%Foray.Scan{}`. `Foray.JobBuilder` projects
one concrete `%Foray.Job{}` per target only when execution starts. All jobs are
scope-checked as a collection before runtime preflight, preventing an input list
from partially launching before a later denial.

A job is exactly one external fuzzer process. Its request template contains all
configured fuzz points and corpus sources. ffuf owns input iteration, HTTP
workers, match/filter evaluation, and optional native recursion.

## Rate model

The product brief proposed Broadway rate limiting as an aggregate request
governor. That is not technically true for coarse job messages: once Broadway
starts a process it cannot observe or meter ffuf's individual HTTP requests.
Foray v1 separates the controls:

```text
aggregate HTTP ceiling
  / effective concurrent ffuf processes
  = conservative per-process ffuf -rate

Broadway rate_limiting
  = whole-job launch pacing only
```

Effective process concurrency is capped by configured `max_jobs`, target count,
and the numeric aggregate rate. Integer division therefore cannot cause the sum
of process rates to exceed the configured ceiling. The tradeoff is deliberate
underutilization when fewer jobs remain.

Threads (`ffuf -t`) are workers, not a rate. They are configured independently
while `-rate` remains authoritative.

## Native stream path

`Foray.stream/1` builds a lazy `Stream.resource/3`. Enumeration starts:

```text
Foray.Stream.Bridge
  ↕ synchronous demand/delivery pairing
Foray.Pipeline (Broadway)
  JobProducer -> N processors -> one ffuf process per processor
```

Each processor enumerates one engine stream. A finding delivery is a synchronous
call into `Foray.Stream.Bridge`. If the consumer has not requested an item, that
processor blocks after one finding. With `N` processors, at most `N` findings
can wait at the bridge, and every blocked processor stops reading its
`Core.Runner` stream. The OS stdout pipe then provides the final backpressure
boundary to ffuf.

Consumer halt cancels the bridge, releases blocked processors with `:stop`, and
calls Broadway's graceful stop. Halting the engine enumerable closes the Exile
owner stream. If a job has not produced a match at the time of cancellation,
Broadway's configured shutdown and ffuf `-maxtime` provide the hard bound; owner
process death then triggers Core.Runner cleanup.

## Broadway topology

`Foray.JobProducer` owns a finite in-memory queue of coarse jobs and emits only
on demand. Each processor has `max_demand: 1`. `prepare_for_draining/1` clears
queued jobs so drain does not launch new attack-shaped work.

`handle_message/3`:

1. opens a `[:core, :foray, :job, ...]` telemetry span;
2. rechecks the concrete target;
3. emits the authorized launch audit event;
4. runs one engine stream;
5. validates and reauthorizes every finding URL;
6. synchronously delivers and emits each finding;
7. completes the job span with outcome and finding count.

Engine or sink failures fail the Broadway message and notify the native stream
bridge. `max_restarts: 0` avoids silently replaying process launches at the
topology level.

## NDJSON contract

ffuf v2.2 `-json` writes one marshaled `ffuf.Result` per stdout line. The pinned
fields are:

```text
input position status length words lines content-type redirectlocation
url duration scraper resultfile host
```

Go marshals `input` byte slices as Base64 and `duration` as nanoseconds.
`Foray.NDJSON` validates every required field, decodes input payloads, handles
partial lines and CRLF, and raises on non-JSON stdout. stderr is consumed as a
separate tagged stream so banners cannot corrupt JSON boundaries.

`-of json` is intentionally not used; it is a whole-file output format and
cannot satisfy streaming.

## Corpus lifecycle

File inputs are passed directly as argv values. `%Core.Seed{}` collections are
materialized during engine enumeration, not plan construction. The temporary
path exists only for the stream owner lifetime and is removed in the resource
finalizer. The original, non-materialized wordlist remains attached to the job
used by `Foray.Finding`, allowing a decoded ffuf input value to recover its
provenance seed.

Input commands are explicit trusted-code sources. They are represented in the
domain model and mapped to ffuf flags, but Foray never builds the command from a
finding or untrusted response.

## Scope boundary

The built-in allowlist normalizes scheme, host/IP, effective port, and decoded
path. Wildcards are suffix rules requiring at least one subdomain. Path
containment uses segment boundaries after encoded traversal normalization.

Every job template is checked before any runtime/version binary or fuzzer
launch. Every emitted ffuf result URL is checked again. Native recursion can
issue descendant requests inside one already-authorized ffuf process, so it is
only exposed with bounded depth and ffuf's strict URL-ending-in-`FUZZ`
constraint. A policy requiring per-request authorization cannot use an external
black-box engine; it needs a future native engine or a prevalidated finite seed
corpus.

## Finding identity

Foray uses Core's source-scoped helper with stable ordered fields:

```text
method + normalized result URL + category + fuzz-point identity + sorted inputs
```

Status, response length, and other mutable response observations are excluded
from dedupe identity. They remain in `locus`, evidence, and raw output.

## Observe and validate boundary

The lazy finding stream is Foray's observe path. The versioned
`foray.http-match-reproduces.v1` validation action takes a finding plus its
originating immutable scan plan. It replaces each wordlist with the exact
recorded input, disables recursion, and runs whole ffuf jobs sequentially while
preserving scope, audit, request-rate, request-template, matcher/filter, and
engine settings.

Only the same stable finding identity confirms the hypothesis. A completed run
without that identity refutes it; known process/preflight failures are
inconclusive. The result proves that the configured HTTP matcher observation
reproduced. It does not promote reflection, error disclosure, or another signal
to exploitability beyond what the original oracle established.

## Version and process boundary

Runtime preflight rejects ffuf below 2.2.0 unless an operator makes the explicit
`allow_unsupported_version` override. The version command and fuzz command both
run through `Core.Runner`; preflight occurs only after the full job collection
passes scope.

The default Exile backend provides streamed reads and owner-death cleanup.
Ordinary cancellation closes the stream and applies Exile's termination
sequence. A hard SIGKILL of the whole BEAM remains outside any in-process
cleanup envelope; deployments needing that guarantee must configure a
shepherd/cgroup-backed Core runner.
