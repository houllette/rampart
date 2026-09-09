# Portico architecture

## Architecture gates

Every v1 feature must preserve these properties:

1. Results are structured domain values, never scanner text, and project to Core findings at the suite boundary.
2. Backpressure reaches the external discovery process.
3. Common operations compose as an Elixir `Stream`; advanced users can supervise
   a Broadway topology.
4. Scanner implementations are replaceable behaviours and all binaries use `Core.Runner`.
5. Scope authorization, cancellation, and supervision prevent unauthorized traffic and ordinary orphaned children.
6. A specific endpoint finding can be rechecked through a versioned, deterministic validation action with proof memory.

## Domain and persistence boundary

`Portico.Host` is the top-level result. Services, scripts, script nodes,
hostnames, ports, and OS matches are separate structs. Scanner-provided names,
states, and keys remain strings; Portico never creates atoms from scanner
output.

`Portico.Result` owns the native persistence boundary. The top-level JSON object
has an integer `schema_version`. Consumers should persist this representation
rather than `:erlang.term_to_binary/1`, which couples data to struct and module
changes. Schema v1 is decoded explicitly and unknown versions fail.

`Portico.Finding` separately projects each open port to `%Core.Finding{}` for
Rampart's finding bus. The projection is one finding per endpoint, preserves the
native `%Portico.Port{}` in `raw`, and uses IP/protocol/port—not mutable
fingerprinting—as its dedupe identity. Core does not define a JSON persistence
schema for arbitrary `raw` terms in v0.1.

## Scan plan

The fluent API builds an immutable `%Portico.Scan{}`:

```text
scan(targets, scope)
  -> discovery engine + validated discovery options
  -> enrichment engine + validated enrichment/pipeline options
  -> lazy execution
```

The plan keeps engine options namespaced in `%Portico.Scan.Stage{}` values. Core
pipeline options cannot leak into an engine, and unknown engine options fail at
plan construction through NimbleOptions.

Before execution, the runtime preflight invokes each engine's optional
`validate_runtime/1` callback. Built-in engines check that their executable is
available. Capability declarations are introspection data, while
`required_privileges/1` reports requirements for a concrete configuration.

## Native Stream path

The native stream implementation is the default embedded path:

```text
all requested targets authorized
  -> lazy discovery source
  -> fixed-window demand rate limiter
  -> bounded compatible host batches
  -> Task.Supervisor.async_stream_nolink
  -> typed Host stream
```

`Task.Supervisor.async_stream_nolink/4` pulls only enough input to keep
`max_concurrency` tasks active. RustScan output is a `Core.Runner` enumerable backed by Exile, so a new
stdout chunk is read only when the downstream task stream asks for another
discovery result. One read may contain multiple lines, but read-ahead is bounded
by `max_chunk_size` (65,535 bytes by default), not by the size of the target
range.

The task stream is unordered so a slow host does not block completed results.
Halting the consumer shuts down all outstanding tasks. Nmap runs in a further
bounded owner task to enforce its per-invocation timeout; killing that owner
causes Exile process cleanup.

The native path batches immediately by count. `batch_timeout` is a Broadway
topology setting; use `host_batch_size: 1` for low-latency native streams.

## Broadway path

`Portico.Pipeline` is the supervised path:

```text
Portico.Discovery.Producer (concurrency 1)
  -> Broadway processor (validation and batch key)
  -> Broadway batcher (bounded nmap concurrency)
  -> synchronous Portico.Sink
```

### Demand-driven producer

The Broadway producer never drains a scanner into its mailbox. A linked reader
owns the lazy discovery enumerable and keeps a suspended `Enumerable.reduce/3`
continuation. It advances that continuation only after receiving an exact
demand credit from the producer. At most Broadway's bounded outstanding demand can be in the producer
mailbox.

When processor demand reaches zero:

1. the producer sends no credit to the reader;
2. the reader does not resume the enumerable;
3. the `Core.Runner` backend does not request another stdout chunk;
4. the OS stdout pipe fills;
5. RustScan blocks in its own write.

This is the end-to-end backpressure mechanism.

### Batching

Broadway messages use `{protocol, ports}` as their batch key. A batch therefore
contains only hosts with identical discovered ports. Using the union of
unrelated host port sets would silently broaden the enrichment scan and is
forbidden by `Portico.Enrichment.Nmap` as a second invariant check.

The synchronous result sink executes in the batch processor. Persistence
latency therefore reduces batch-processor availability and propagates demand
backward instead of accumulating an unbounded result mailbox. Automatic
producer restarts are disabled: replaying a scanner with a no-op acknowledger
could duplicate network traffic and results, so a producer failure terminates
the topology for the embedding supervisor to handle explicitly.

## Lifecycle and supervision

The Portico application supervises `Portico.TaskSupervisor`. An embedding
application supervises each optional `Portico.Pipeline` Broadway topology.
Broadway supervises the producer, processors, and batchers.

### Native stream cancellation

- Consumer halt terminates outstanding async-stream tasks.
- Each nmap timeout owner is started with `Task.Supervisor.async_nolink/3`.
- Timeout uses `Task.yield/2` followed by `Task.shutdown/2` with
  `:brutal_kill`.
- The owner of the Exile stream dies with that task, closing pipes and reaping
  nmap through Exile's termination sequence.

### Broadway drain

`Portico.Discovery.Producer.prepare_for_draining/1` is mandatory. It stops
issuing credits and asks the discovery reader to halt its enumerable. If the
reader is blocked in an external read, the producer force-stops it after two
seconds. The reader is linked to the producer, so producer failure also kills
the Exile owner immediately.

Queued, not-yet-dispatched discovery work is dropped during drain. In-flight
Broadway batches are allowed to finish within the topology's `shutdown` grace.
The default child specification sets grace to enrichment timeout plus five
seconds. Operators overriding one value must keep this invariant:

```text
supervisor shutdown >= enrichment timeout + external-process exit grace
```

### Exile failure envelope

The shared Core conformance test verifies owner-death cleanup. Exile also
installs a watcher under its application supervisor for ordinary VM
shutdown/SIGTERM. No in-process library can guarantee cleanup after a hard
SIGKILL of the whole BEAM before an independent shepherd/cgroup acts.
Deployments that require that guarantee should configure a cgroup-backed
`Core.Runner` implementation. This known boundary is centralized in Core so
Portico and future external Rampart tools share one cleanup policy.

## Engine contracts

### Discovery

A `Portico.Discovery.Engine`:

- declares and validates options;
- optionally reports capabilities and runtime readiness;
- returns a **lazy** enumerable;
- emits `%Portico.Discovery.Result{ip, ports, protocol}`;
- does not invoke enrichment itself.

The contract fits line-oriented RustScan, masscan, and naabu adapters. An adapter
for a push-based source must introduce its own bounded demand bridge rather than
sending all results into a mailbox.

### Enrichment

A `Portico.Enrichment.Engine`:

- accepts a non-empty list of compatible discovery results;
- returns `{:ok, hosts}` or `{:error, reason}`;
- returns exactly one host per input, in input order;
- declares privilege and protocol capabilities;
- owns scanner-specific parsing.

This accommodates nmap as well as TLS, banner, or application-specific
fingerprinters. Pipeline code does not inspect engine-specific options.

## Parsing contracts

### RustScan

The built-in adapter launches RustScan without its `--` nmap passthrough and
uses:

```text
IP -> [22,80,443]
```

The line transformer retains trailing fragments across chunk boundaries. Lines
that do not resemble results (for example a banner) are ignored. A line
containing `->` that violates the pinned contract raises
`Portico.Engine.OutputError`, making output drift visible.

Stdout and stderr are consumed as separate tagged streams. Redirecting stderr
into structured stdout is deliberately avoided because Exile documents that the
two byte streams may interleave at arbitrary boundaries.

### nmap

Nmap runs with `-oX -`. `Portico.NmapXML` passes the `Core.Runner` stdout enumerable
directly to `Saxy.parse_stream/4`. The SAX state machine materializes a host on
`</host>` and supports a callback mode that does not retain completed hosts.
External entities are not expanded by Saxy.

## Observe and validate boundary

The native host/finding streams are Portico's observe path. The versioned
`portico.endpoint-reachable.v1` validation action accepts one Portico finding,
skips discovery, and invokes the configured enrichment engine for exactly its
IP/protocol/port tuple. It shares `Portico.Enrichment.Stage`, so scope, audit,
telemetry, engine validation, timeout, and process cleanup cannot diverge from
the normal pipeline.

An open observation confirms and emits a fresh finding with an exact replay
seed. A completed scan that no longer reports the port refutes the point-in-time
hypothesis. Timeout or engine failure is inconclusive. Network state remains
mutable; deterministic here means a fixed procedure and evidence-backed verdict
for the observed execution, not eternal stability of the endpoint.

## Distribution growth path

v1 runs on one BEAM node. No scanner process or continuation is transferred
between nodes. A future coordinator can partition authorized targets and start
one `Portico.Pipeline` per worker node; `%Portico.Host{}` crosses the boundary
through its versioned JSON schema. This adds coordination around the existing
pipeline rather than changing either engine behaviour.
