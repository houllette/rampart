# Portico

Portico is an embeddable Elixir library for authorized, two-tier port scanning.
A fast discovery engine feeds a bounded enrichment tier while demand propagates
back to the discovery process's stdout pipe. Results are typed, versioned, and
streamed as `%Portico.Host{}` structs.

Portico is an orchestration library, not a scanner and not a CLI. The built-in
engines execute RustScan and nmap; custom engines can replace either tier.

## Properties

- Lazy, end-to-end backpressure with bounded enrichment concurrency
- Fail-closed scope authorization before discovery and before each enrichment
- Structured host, port, service, NSE script, and OS-fingerprint results
- Versioned JSON persistence through `Portico.Result`
- Cancellable external processes through Rampart's shared `Core.Runner` seam
- Pluggable discovery, enrichment, runner-backend, audit, and result-sink behaviours
- A native `Stream` API and a supervised Broadway topology
- Telemetry rather than application-specific logging

## Installation

Add Portico to `mix.exs`:

```elixir
def deps do
  [
    {:portico, "~> 0.1.0"}
  ]
end
```

Install these external binaries separately:

- RustScan 2.4.x for the built-in discovery engine
- nmap 7.95 or newer for the built-in enrichment engine

Portico uses RustScan's `--greppable` contract and nmap's `-oX -` XML contract.
External versions are intentionally operator-managed; pin them in the image or
host configuration that deploys the embedding application.

## Quick start

A scope policy is required. The built-in allowlist supports IPv4 and IPv6 hosts
and CIDRs and rejects unresolved hostnames by default.

```elixir
scope = Portico.Scope.Allowlist.new!(["10.20.0.0/16"])

Portico.scan("10.20.4.0/24", scope: scope)
|> Portico.discover(
  engine: :rustscan,
  ports: :full,
  batch_size: 4_500
)
|> Portico.enrich(
  engine: :nmap,
  service_detection: true,
  scripts: ["default"],
  max_concurrency: 4,
  host_batch_size: 1,
  rate_limit: [allowed_messages: 20, interval: 1_000]
)
|> Portico.stream()
|> Stream.each(&persist/1)
|> Stream.run()
```

Nothing runs until the stream is enumerated. Stopping enumeration shuts down
outstanding enrichment tasks. Each task owns its nmap process, so task death
causes Exile to close and reap that process.

A policy can also be configured once for an embedding application:

```elixir
config :portico,
  scope: Portico.Scope.Allowlist.new!(["10.20.0.0/16"])
```

With no explicit or configured policy, Portico uses
`Core.Scope.DenyAll` and refuses to scan.

## Resource budgets

Nmap enrichment accepts host-owned `xml_limits: [...]` options. Defaults bound
each document to 16 MiB, depth 64, 100,000 elements, 1,024 hosts, 65,536 ports,
16,384 scripts, 65,536 script nodes, 8 MiB of decoded attribute/character text,
and 64 KiB per attribute or accumulated text value. See
`Portico.NmapXML.Limits.schema/0` for exact option names. Direct parser calls
use `limits: [...]`. Limits remain cumulative with `collect: false`.

An exceeded XML budget returns an explicit error and makes endpoint validation
inconclusive. Host callbacks are provisional until parsing completes. These
input/model budgets do not promise a hard VM memory limit.

RustScan lines are limited to 1,048,576 raw bytes, excluding LF and including
CR, before parsing both complete and unfinished lines. Output errors retain
only a copied 1,024-byte line preview. Early parser termination reaps the
native process; ordinary nonzero completion remains an error.

## Result serialization

```elixir
{:ok, json} = Portico.Result.encode(host)
{:ok, %Portico.Host{} = restored} = Portico.Result.decode(json)
```

The top-level persisted object contains `"schema_version": 1`. Decoding rejects
unknown versions rather than guessing. Caller and engine metadata must contain
JSON-compatible values.

NSE output is represented by `%Portico.Script{}`. Its `data` field contains a
list of `%Portico.Script.Node{type: :table | :element}` nodes, preserving nested
nmap XML without turning scanner-provided keys into atoms.

## Rampart interchange boundary

Portico keeps its native domain model and projects open ports into one
`%Core.Finding{}` per independently triageable endpoint. Mutable fingerprints
are present in `locus` and `raw` but excluded from the stable dedupe identity.

```elixir
finding_stream =
  scan
  |> Portico.findings()
  |> Stream.each(&MyFindingBus.publish/1)
```

Use `Portico.to_findings/1` to project an already available `%Portico.Host{}`.
`Portico.observe/1` is the explicit observe-action alias for
`Portico.findings/1`. The native host stream also emits
`[:core, :portico, :finding]` for each observation, so embedding systems can
subscribe without replacing the result sink. See
[TELEMETRY.md](TELEMETRY.md).

## Validate one endpoint hypothesis

Portico advertises the versioned `portico.endpoint-reachable.v1` action. It
skips broad discovery and rechecks exactly the candidate finding's IP, protocol,
and port with an enrichment engine:

```elixir
case Portico.validate(candidate_finding, scope: scope) do
  %Core.Validation.Result{verdict: :confirmed} = proof -> proof.findings
  %Core.Validation.Result{verdict: :refuted} -> []
  %Core.Validation.Result{verdict: :inconclusive} = result -> result.evidence
end
```

The validation path remains fail-closed and emits the normal launch audit before
nmap starts. Its result is a point-in-time network observation, not a promise
that the endpoint remains open. It includes an exact endpoint `%Core.Seed{}` for
replay. Use `Portico.validation_actions/0` for machine discovery and the
lower-level `Core.Validation` API when constructing transport-independent tool
calls.

## Supervised Broadway topology

Use `Portico.Pipeline` when the scan should live in an application's supervision
tree. The sink is synchronous and therefore remains part of the backpressure
path.

```elixir
children = [
  {Portico.Pipeline,
   name: MyApp.InventoryScan,
   scan: scan,
   on_result: fn host -> MyApp.Inventory.persist(host) end,
   shutdown: 125_000}
]
```

`host_batch_size` groups only hosts with identical protocol and port sets. This
prevents batching from broadening a discovery result by scanning a union of
ports that was not discovered on every host.

The configured supervisor shutdown must be at least the enrichment timeout plus
process-exit grace. `Portico.Pipeline.child_spec/1` derives that value by default.

## Custom engines

A discovery engine implements `Portico.Discovery.Engine` and returns a lazy
enumerable of `%Portico.Discovery.Result{}` values. An enrichment engine
implements `Portico.Enrichment.Engine` and returns one `%Portico.Host{}` for each
input result, in input order.

Engine-specific options are validated using each engine's
`option_schema/0`. Register aliases without changing pipeline code:

```elixir
config :portico, :engines, %{
  discovery: %{naabu: MyApp.NaabuDiscovery},
  enrichment: %{tls: MyApp.TLSEnricher}
}
```

Use modules directly during development:

```elixir
Portico.discover(scan, engine: MyApp.NaabuDiscovery, observer: self())
```

All external processes go through the shared `Core.Runner` seam. Its default
backend is `Core.Runner.Exile`; configure an alternative once for every
external Rampart tool with `config :security_core, :runner, MyRunner`.

## Privileges

The default nmap scan type is TCP connect (`-sT`) and does not require running
the BEAM as root. SYN scans, UDP scans, and OS detection may require
`CAP_NET_RAW`. Query this before deployment:

```elixir
Portico.Enrichment.Nmap.required_privileges(scan_type: :syn)
#=> [:net_raw]
```

Prefer assigning narrowly-scoped capabilities to scanner binaries over running
the VM as root. See [SECURITY.md](SECURITY.md).

## Compatibility and drift

The conformance and parser fixtures exercise:

- partial RustScan greppable lines across arbitrary output chunks
- separate stderr consumption
- nmap XML split into very small chunks
- nested service, NSE, host-script, and OS data
- Exile owner-death process cleanup

RustScan 2.4.x does **not** provide the `-oJ` option described by some third-party
examples; Portico deliberately relies on `--greppable`. A parser-conformance
failure is fatal rather than silently dropping a line that resembles discovery
output.

## Development

From the Rampart umbrella root:

```sh
mix deps.get
mix test
mix precommit
mix dialyzer
```

`mix precommit` runs the same compilation, formatting, lint, documentation,
audit, xref, and test checks used by CI.

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and
[TELEMETRY.md](TELEMETRY.md) for the supported low-level contracts.
