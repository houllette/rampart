# Portico telemetry contract

Portico emits machine-consumable events through Rampart's `Core.Telemetry`
namespace. Applications choose handlers, aggregation, and logging policy.
Targets are security-sensitive metadata and must be routed only to approved
observability systems.

## Required cross-tool events

### `[:core, :portico, :scan, :start]`

Emitted when a lazy native scan begins enumeration or a supervised Broadway
producer starts.

Measurements follow the `:telemetry.span/3` convention and include
`monotonic_time` and `system_time`. Metadata includes:

- `target` — one target string or a list of target strings
- `telemetry_span_context` — an opaque correlation reference for manually
  managed stream spans

### `[:core, :portico, :scan, :stop]`

Emitted on completed or deliberately halted enumeration and on graceful
Broadway termination.

Measurements:

- `duration` — native monotonic duration
- `monotonic_time` — stop time

Metadata:

- `target`
- `outcome` — `:ok` or `:cancelled`
- `finding_count` — number of emitted `%Core.Finding{}` values
- `telemetry_span_context`

### `[:core, :portico, :scan, :exception]`

Emitted when native enumeration raises, exits, or throws, or when the Broadway
producer terminates abnormally. Measurements are the same as `:stop`.

Metadata includes `target`, `outcome: :error`, `finding_count`, `kind`,
`reason`, `stacktrace`, and `telemetry_span_context`.

### `[:core, :portico, :finding]`

Emitted once for every open-port observation at the Portico boundary.
Measurements are `%{}`. Metadata is exactly:

```elixir
%{finding: %Core.Finding{}}
```

Portico emits one finding per open port, not one per host. This granularity lets
downstream Rampart consumers independently correlate, triage, and promote an
exposed endpoint.

### `[:core, :portico, :launch]`

Emitted after scope authorization and immediately before each discovery or
enrichment engine call that may launch an external binary. Measurements are
`%{}` and metadata is `%{target: target}`. A denied target never emits this
event.

The discovery target is a string. Batched enrichment uses one string or a list
of strings.

## Validation spans

`Core.Validation.run/3` emits:

- `[:core, :portico, :validation, :start]`
- `[:core, :portico, :validation, :stop]`
- `[:core, :portico, :validation, :exception]`

Metadata identifies the versioned `action`, `validation_id`, and subject type.
Stop metadata adds `verdict`/`outcome` and `finding_count`. A confirmed endpoint
also emits the normalized finding event. The nested enrichment call retains its
ordinary launch audit and stage span.

## Portico stage spans

Portico additionally emits conventional enrichment spans:

- `[:core, :portico, :enrichment, :start]`
- `[:core, :portico, :enrichment, :stop]`
- `[:core, :portico, :enrichment, :exception]`

Metadata includes `scan_id`, `target`, engine module, `host_count`, and
`port_count`. Stop metadata adds `outcome` (`:ok`, `:error`, or `:invalid`).
These events refine the shared scan span without creating a Portico-only root
namespace.

## Synchronous audit hook

The optional `Portico.Audit` hook is separate from telemetry. It receives the
`:scanner_launch` event and launch metadata synchronously. A hook that raises or
returns anything other than `:ok` aborts the engine call. Use it when an audit
record must be accepted before traffic is allowed; use telemetry for
observability.

## Compatibility

The `[:core, :portico, ...]` names and finding/launch metadata are part of the
`security_core ~> 0.1` suite contract. New metadata keys may be added to stage
spans. Consumers should match required keys rather than asserting whole-map
equality outside the finding and launch events documented as exact.
