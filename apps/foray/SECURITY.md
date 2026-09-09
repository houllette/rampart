# Foray security and deployment

Foray sends attack-shaped HTTP inputs. Use it only against systems the embedding
application is explicitly authorized to test.

## Fail-closed authorization

No policy authorizes nothing. `Core.Scope.DenyAll` is the default.

Before Broadway or runtime preflight starts, Foray builds every concrete job and
calls `Core.Scope.ensure_all_authorized!/2`. One denial prevents every job from
launching. Processors recheck their job immediately before invoking the engine.
Each normalized result URL is checked again before the finding is emitted.

Authorized process launches emit `[:core, :foray, :launch]`. The optional
synchronous `Foray.Audit` hook runs before each fuzz job and must return `:ok`;
a hook failure aborts the launch.

## Built-in URL policy

`Foray.Scope.Allowlist` uses exact schemes and effective ports. URL userinfo and
fragments are rejected. Hostnames are lowercased, IP literals are canonicalized,
and wildcard rules require an actual subdomain. Paths are URI-decoded,
normalized for traversal, and matched on path-segment boundaries.

Examples:

- `https://app.example/api` permits `/api` and `/api/users`, not `/apix`.
- `https://*.example/` permits `edge.example`, not `example`.
- HTTPS port 443 does not authorize HTTPS port 8443.

## External-engine scope limit

A scope check around a black-box ffuf process cannot intercept every generated
HTTP request. File wordlists may contain encoded traversal, absolute-looking
values, or application-specific routing syntax. Native ffuf recursion also
launches descendant requests internally before Foray can see a matched result.

Foray also keeps ffuf redirect following disabled in v1. A redirect target
cannot be authorized between ffuf receiving the response and issuing its next
request, so exposing `-r` would violate the pre-request scope contract.

Therefore:

- authorize the narrowest safe origin and path envelope;
- use reviewed wordlists;
- keep recursion disabled unless the authorized path includes all descendants;
- prefer `%Core.Seed{}` corpora when payload provenance matters;
- use a future native engine if policy requires authorization before every
  individual payload-expanded request.

Foray rechecks matched URLs to prevent out-of-scope findings from feeding later
suite stages, but that check cannot retroactively prevent the request.

## Aggregate request ceiling

`requests_per_second` is divided conservatively across the maximum active ffuf
processes and passed as each process's `-rate`. `threads` does not override that
rate. `max_jobs` remains small by default.

`Foray.job_rate_limit/2` only paces whole process starts. It is not an HTTP rate
limit and must not be used as one.

Use network ACLs and engagement-level controls in addition to library settings.

## Command construction

Foray passes argv lists through `Core.Runner`; it does not construct a shell
command for normal ffuf execution. Request URLs, headers, methods, matchers, and
filters are typed and validated. Arbitrary ffuf passthrough arguments are not
part of v1.

The explicit `{:input_command, command, count}` corpus source is different:
ffuf intentionally executes it through a shell. It is trusted operator code.
Never derive it from HTTP output, findings, payload files, or untrusted users.
Because ffuf reserves `:` as the input-command keyword separator, Foray rejects
commands containing a colon instead of allowing ffuf to reinterpret them.

Headers, cookies, bodies, and wordlists may contain credentials or sensitive
payloads. Do not place them in telemetry metadata. The shared launch event
contains only the target or runtime-check descriptor.

## ffuf version floor

Foray defaults to a minimum ffuf version of 2.2.0 and checks `ffuf -V` after
scope authorization. Older versions are rejected because of a known
response-decompression memory-exhaustion issue. `allow_unsupported_version` is
an explicit emergency override, not a compatibility default.

Pin the current v2.2 patch release in deployment images and update the NDJSON
conformance fixture when changing major/minor versions.

## Cancellation and cleanup

Every job has a nonzero ffuf `-maxtime`. Broadway drain drops queued work and
allows active jobs to close. Stream consumer cancellation releases blocked
finding deliveries and halts their Core.Runner enumerables.

Exile owner death covers ordinary processor failure and cancellation. Hard
SIGKILL of the whole BEAM requires an external process group, container,
systemd scope, or shepherd-backed runner for guaranteed cleanup.

## Untrusted output

ffuf JSON, response metadata, scraper values, URLs, and reflected inputs are
untrusted:

- NDJSON lines are size-bounded and schema-validated.
- JSON keys are never converted into new atoms.
- Base64 input values may still contain arbitrary bytes.
- Evidence and raw values must be escaped before terminal or HTML rendering.
- Result persistence accepts only the fixed Foray locus-key and enum schema.

## Reporting issues

Do not publish credentials, target inventories, private URLs, wordlists, or
production response data. Use synthetic local fixtures.
