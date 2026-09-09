# Foray telemetry contract

Foray uses Rampart's shared Core namespace and emits no machine-consumable
signal through application-specific logging.

## Job spans

Each whole fuzzer process emits:

- `[:core, :foray, :job, :start]`
- `[:core, :foray, :job, :stop]`
- `[:core, :foray, :job, :exception]`

Start metadata:

- `job_id`
- `target`
- `engine`
- `telemetry_span_context`

Stop metadata adds:

- `outcome` — `:ok` or `:cancelled`
- `finding_count`

Stop measurements follow `:telemetry.span/3` and include native `duration` and
`monotonic_time`. Exception metadata adds `kind`, `reason`, and `stacktrace`.

A job is an ffuf process, not an HTTP request. These events must not be
interpreted as per-request telemetry.

## Findings

`[:core, :foray, :finding]` is emitted once after a finding passes derived URL
scope authorization and its synchronous sink accepts it.

Measurements are `%{}` and metadata is exactly:

```elixir
%{finding: %Core.Finding{source: :foray}}
```

## Launch audit

`[:core, :foray, :launch]` is emitted only after the entire initial job set has
passed scope authorization.

For a fuzz job, metadata is:

```elixir
%{target: "https://app.example/FUZZ"}
```

The ffuf safety/version preflight also uses Core.Runner and emits:

```elixir
%{target: %{kind: :runtime_check, executable: "/path/to/ffuf"}}
```

Measurements are `%{}`. Denied job sets emit no launch events.

## Validation spans

`Core.Validation.run/3` emits
`[:core, :foray, :validation, :start | :stop | :exception]`. Metadata identifies
the versioned action, validation ID, and subject type. Stop metadata adds the
verdict and finding count. Exact-replay ffuf launches retain the normal launch
and synchronous audit events; confirmed replay emits a finding event.

## Synchronous audit hook

`Foray.Audit` is separate from telemetry and receives `:job_launch` immediately
before the engine call. It can enforce durable audit acceptance by raising or
returning something other than `:ok`, which aborts the job.

## Sensitive metadata

Targets may identify non-public systems. Core findings contain tested payloads,
URLs, response metadata, and raw ffuf records. Attach only approved handlers and
apply the embedding system's redaction and retention requirements.
