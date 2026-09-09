# Security and deployment

Portico is intended only for targets the embedding system is authorized to
scan. Authorization is a runtime invariant, not caller documentation.

## Fail-closed scope enforcement

A scope policy is mandatory. With no explicit or application-configured policy,
`Core.Scope.DenyAll` rejects enumeration.

Portico checks scope at two boundaries:

1. **Before discovery:** every requested target is authorized before any
   discovery engine is invoked. If a list contains one denied target, none of
   the list is launched.
2. **Before enrichment:** every discovery result is parsed as a target and
   authorized again before an enrichment engine is invoked. A buggy or hostile
   discovery adapter therefore cannot make nmap scan an address outside the
   configured scope.

Every authorized binary launch emits the shared
`[:core, :portico, :launch]` audit event immediately before the engine call. An
embedding system can also inject a synchronous `Portico.Audit` hook. The hook
must return `:ok`; failure aborts launch rather than silently losing the audit
record. Denials raise `Core.Scope.Error` and never emit a launch event.

### CIDR policy

`Portico.Scope.Allowlist` supports IPv4 and IPv6 and applies subnet containment,
not string-prefix matching. A candidate CIDR must be at least as specific as an
allowed CIDR. For example, an allowed `/24` permits a host or `/28` inside it but
not a broader `/16`.

Unresolved hostnames are rejected by default. An exact hostname can be enabled
explicitly, but this does not prevent DNS rebinding between authorization and a
scanner's own resolution. Systems requiring hostname targets should implement a
custom policy/engine pair that resolves once, authorizes every address, and
passes pinned IP literals to scanners.

Custom policies implement `Core.Scope.Policy`. Policy state may be supplied as
a struct or `{module, state}`. Policies should be deterministic for the
lifetime of a launch and return a boolean. A policy error must fail closed by
returning `false` or raising before any launch occurs.

## Command construction

Built-in engines pass an executable and argument list through `Core.Runner`;
they do not construct shell command strings.

RustScan's nmap passthrough delimiter is never exposed, ensuring enrichment
cannot escape Portico's concurrency boundary. The nmap engine exposes typed
options rather than arbitrary arguments. This prevents options such as target
files from adding targets that bypass the scope guard.

NSE scripts may make their own network requests according to nmap script
semantics. Operators must review enabled script sets and treat them as code.
Portico passes script names but does not sandbox NSE execution.

## Privilege model

Do not run the BEAM as root.

The built-in default is nmap TCP connect scanning (`-sT`). SYN (`-sS`), UDP
(`-sU`), and OS detection can require raw-socket privileges. Query a concrete
configuration with `Portico.Enrichment.Nmap.required_privileges/1`.

On Linux, prefer a narrowly scoped file capability on the scanner binary:

```sh
sudo setcap cap_net_raw+ep "$(command -v nmap)"
getcap "$(command -v nmap)"
```

Package upgrades often replace the inode and remove capabilities; deployment
health checks must verify them again. Restrict ownership and write access on any
capability-bearing binary.

A privileged helper is an alternative when policy forbids file capabilities.
It should accept a typed, minimal request, repeat scope checks, reject arbitrary
arguments, drop privileges before parsing output, and own process cleanup. Such
a helper belongs behind `Core.Runner`; the library does not ship one in v1.

## Process cleanup boundary

The default `Core.Runner.Exile` backend owns child processes and applies pipe
close, SIGTERM, then SIGKILL during ordinary cancellation. Security Core tests
owner-death cleanup; Portico gives Broadway in-flight work a configurable drain
interval.

Hard SIGKILL of the entire BEAM prevents any in-VM cleanup callback. Where this
failure must not leave a scanner alive, run the application in a container or
systemd/cgroup scope configured to kill all members, or supply an independent
shepherd-backed runner. Do not claim the Exile backend alone covers this case.

## Rate and concurrency controls

`max_concurrency` bounds concurrent enrichment invocations.
`host_batch_size` bounds hosts per compatible invocation. `rate_limit` restricts
discovery messages admitted during a fixed interval. These controls reduce
resource and network blast radius but do not replace external engagement rate
limits, network ACLs, or scanner-specific timing settings.

Use conservative defaults per environment and attach telemetry before widening
scope or concurrency.

## Result handling

Scanner output is untrusted input:

- XML external entities are not expanded.
- Scanner-provided keys remain binaries, avoiding atom-table exhaustion.
- Persisted schema versions are checked.
- Arbitrary metadata must be JSON-compatible and should not contain secrets.
- Telemetry metadata contains targets; route it only to approved observability
  systems.

NSE output and service banners may contain terminal escape sequences or hostile
markup. Consumers must escape them before rendering in terminals or HTML.

## Reporting issues

Do not include active credentials, sensitive target inventories, or production
scanner output in public issue reports. Provide minimized synthetic fixtures
that reproduce parser or lifecycle behavior.
