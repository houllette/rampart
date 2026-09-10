# External primitive validation

Run `mix rampart.integration` from the umbrella. This builds all eight Hex
archives, extracts their package contents, and compiles fresh temporary Mix
consumers. No consumer shares the umbrella's dependency directory, build output,
configuration, test helpers, or running VM. Package overrides supply only the
declared Rampart dependency closure until these versions are published. The
gate reads the built Hex metadata, checks suite version requirements and the
expected dependency direction, and derives overrides from those declarations;
it cannot silently supply an undeclared sister tool. Third
party dependencies resolve from the checked-in lockfile. Runtime assertions
reject undeclared sister tools on each consumer's code path.

The gate uses Python's standard library to own external Mix processes, deadlines,
process-group cleanup, archive extraction, logs, hashes, and optional RSS sampling.
All primitive behavior is exercised in Elixir. The integration code is repository
evaluation infrastructure, not another published library or agent harness.

```sh
# Native fixtures: RustScan 2.4.1, nmap 7.99, ffuf release v2.2.0.
# Requires a C/C++ compiler and make. Installs only under the selected prefix.
python3 evaluation/integration/bootstrap.py --prefix tmp/native-tools
export PATH="$PWD/tmp/native-tools/bin:$PATH"
mix rampart.integration --output tmp/rampart-integration.json

# Focused suites; each still builds the exact package archives it will consume.
mix rampart.integration --suite consumers
mix rampart.integration --suite contracts
mix rampart.integration --suite applications
mix rampart.integration --suite native
mix rampart.integration --suite muex
mix rampart.integration --suite search
mix rampart.integration --suite resources
```

Missing prerequisites fail explicitly. Successful workspaces are removed after
logs and proof files are retained beside the report; use `--keep-workspace` for
debugging. Failed workspaces remain available at the reported path. Retained
artifacts use a fresh run directory so repeated output paths cannot mix evidence.
Each report
records package archive checksums, the lockfile checksum, a source snapshot
checksum (including uncommitted implementation), per-suite checks, and artifact
checksums. A commit ID alone is not treated as the identity of a dirty tree.

| Suite | Required evidence |
| --- | --- |
| Consumers | Eight separate compiled consumers, declared dependency isolation, representative APIs; the SAST consumer starts its disposable worker |
| Contracts | Real Havoc/SAST validators through Binding and Wire; three completed verdicts, persisted replay, rebuilt authority, malformed references, option smuggling, scope denial, validator crash, cancellation/deadline, target failure, bounded artifact output |
| Applications | Two complete original Plug/Bandit applications; live loopback HTTP, compiled routing, supervised state, vulnerable/fixed controls, inaccessible application, durable counterexamples, replay, isolated static inventory |
| Native | Actual RustScan→nmap, known open/closed endpoints, endpoint validation, ffuf matching/replay, multiple keywords, binary request bodies, response-backed refutation, inconclusive request timeouts/job deadlines, slow consumers, aggregate request ceilings, consumer/validator cancellation, child/wordlist/audit cleanup |
| Muex | Real isolated mutation test execution: a bypass is killed by a security assertion, survives a happy-path-only test, and timeout/compilation failures remain separate; original source and unrelated code are preserved |
| Search | Seven paired guided/unguided trials on the same four-character domain and 200-step budget, line coverage, concrete sequences, exact independent confirmation/replay, observed latency and target-call counts |
| Resources | Compute, binary, container and disk IO with disabled/targeted sensing at concurrency 1/2/4; repeated latency, reductions, GC, scheduler activity, sampled VM/mailbox/RSS peaks, overflow, 20 caller-death trials and a 51-file Elixir/Erlang scan |

## Full application fixtures

These are original fixture applications, **not reproductions of upstream CVEs**.
They compile unmodified Plug 1.20.3 and Bandit 1.12.5, pinned by version and the
consumer lockfile. They execute complete request routing, authentication,
application state and HTTP responses rather than exposing an adapted private
predicate. They do not establish coverage of Phoenix, Ecto or Ash applications.

`Fixture.TenantCache` demonstrates an authenticated cross-tenant cache boundary.
Independent uncached requests establish distinct private profiles. The vulnerable
cache uses only the path; the fixed cache includes the authenticated tenant.
Havoc's existing cache noninterference oracle evaluates actual HTTP responses.

`Fixture.RouteGateway` mounts the same state-changing router at two prefixes.
The vulnerable application checks authorization at one prefix; the fix applies
the check to both. Privileged requests prove both routes execute. Anonymous
canonical/unknown-path controls and independent state counters prevent missing
routes, failed fixtures, or empty responses from becoming confirmations.

Every case retains its concrete corpus and bounded wire proof. Disabling the
application must yield inconclusive, and replaying the saved payload against the
fixed application must refute the same security hypothesis.

## Native provenance

`native-tools.json` pins official release URLs and SHA-256 digests for macOS
arm64 and Linux amd64. nmap is built from its pinned source archive with the
features required by these TCP fixtures. Broader TLS/NSE/UDP capability is not
claimed by that build.

The official [ffuf v2.2.0 tag](https://github.com/ffuf/ffuf/releases/tag/v2.2.0)
still sets [VERSION to 2.1.0](https://github.com/ffuf/ffuf/blob/0aa36bcfa45c255f0d719f7d5bc58f7cc9c93659/pkg/ffuf/constants.go).
Foray recognizes only the reviewed release executable hashes as 2.2.0. An
arbitrary 2.1.0 binary remains below the security floor; these tests never set
`allow_unsupported_version`. Release labels alone are insufficient provenance.

## Measurement limits

Search quality and timing are observations, not universal pass thresholds. Both
search arms collect line coverage so coverage observations are comparable; the
measured unguided latency includes instrumentation it ordinarily would not need.
PropEr's public API in the locked version does not accept an initial RNG seed.
We retain its exact generated inputs and concrete counterexamples rather than
claiming that a repeated stochastic search reproduces the same trajectory.
Final confirmation can add a small number of target calls beyond search steps;
the actual counts are retained. No custom random/shrink loop is implemented.

RSS samples include the resource consumer's Mix startup and disposable children;
summed RSS may count shared pages more than once. Short peaks between samples may
be missed. VM/mailbox counters are node-wide and sampling adds overhead. These
are measured operating conditions, not hard memory ceilings or production IAST
safety evidence. IAST remains unavailable to agent tools.

The `Primitive integration` workflow runs this gate on pushes and pull requests.
It supplements `mix precommit` and the pinned-runtime evaluation matrix.
