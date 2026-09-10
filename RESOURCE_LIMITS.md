# Resource limits and remaining boundaries

The initial source review used commit
`d34ab53c363ef26bb4628f8b2015ebeb9934091e` on 2026-09-09. This inventory was
updated on 2026-09-10 for the implemented R1–R4 boundaries below. It covers
suite-owned execution, input, query, persistence and output budgets across all
eight packages. The limits are implementation contracts, not a new resource measurement or proof
of peak memory safety. Existing measurements remain in [PERFORMANCE.md](PERFORMANCE.md).

Units matter: bytes are not graphemes, BEAM heap words are not total VM RSS,
and an event count is not a mailbox capacity. A read-chunk size or SAX delivery
threshold does not limit the full document or retained result. Deadlines may
be followed by cleanup time. Configurable values below are defaults unless
described as fixed; third-party engines retain their own version-specific
behavior.

## Core execution and wire boundary

Source: [Core.Runner.Exile](https://github.com/houllette/rampart/blob/main/apps/security_core/lib/core/runner/exile.ex) and
[Core.Validation.Wire](https://github.com/houllette/rampart/blob/main/apps/security_core/lib/core/validation/wire.ex).

| Control | Default and unit | Enforcement and limit of the guarantee |
| --- | --- | --- |
| Collected command execution | `timeout: 5,000` ms; `exit_timeout: 1,000` ms | `run/2` bounds collection and reaps the subprocess. Exit handling can add time after the collection deadline. |
| Collected command output | `max_output_bytes: 1,048,576` bytes; `max_chunk_size: 65,535` bytes | Reads at most the remaining allowance plus one byte before reporting an output-limit error. The chunk size alone is not the total-output cap. |
| Streaming execution | No inherited collected-output/deadline defaults | `stream/2` delegates to Exile. Callers own stream lifecycle, aggregate output and execution policy. |
| Validation wire projection | No intrinsic whole-response byte/depth/term budget | Portable projection excludes native `raw` fields and executable context. The consuming adapter must bound the final encoded envelope and artifact references. |

Core seeds do not impose a universal input-byte budget. The relevant tool,
persistence codec or host must supply one; Core should not acquire tool-specific
resource policies.

## SAST discovery, isolation and queries

Sources: [scanner limits](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/limits.ex),
[discovery](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/discovery.ex),
[scanner](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/scanner.ex),
[isolated limits](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/isolated/limits.ex),
[isolated worker boundary](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/isolated.ex),
[wire decoder](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/isolated/wire.ex),
[graph](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/graph.ex),
[bounded data flow](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/data_flow.ex), and
[module ownership](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/module_owners.ex).

| Control | Default and unit | Enforcement and remaining boundary |
| --- | --- | --- |
| Source inventory | 10,000 files; 1,000,000 bytes/file; 25,000,000 total source bytes | Discovery and scan-entry checks report limit diagnostics. Per-file bytes are checked again before parsing. Directory enumeration and file reads are not OS memory/disk quotas. |
| Task concurrency and deadlines | Online scheduler count; 5,000 ms each for parse, context, behavior and rule work | Task boundaries produce explicit diagnostics on timeout/failure. These are phase/task limits, not one aggregate scan deadline or an atom-table defense. |
| Isolated worker execution | 30,000 ms; 64,000 collected log bytes | Disposable worker uses the collected Core runner. Worker/protocol failure yields an incomplete result. Parent cleanup is additional work. |
| Isolated response | 64,000,000 encoded bytes; 1,000,000 portable terms; depth 64, configurable up to 256 | File-size and wire-byte checks precede portable validation. Term/depth checks happen after JSON decoding, so they do not bound the decoder's initial allocation. Response-file size checks are not a writer disk quota. |
| Worker VM controls | 8,000,000 heap words/process; 262,144 atom-table entries/VM | Worker startup configures heap-kill and atom-table flags. Heap words do not bound all binaries, native allocations or whole-VM RSS. Use `RampartSAST.Isolated` for untrusted repositories. |
| Bounded graph traversal | Depth 3; 200 nodes; 500 edges; 10,000 work visits; 256,000 encoded bytes | Traversal returns truncation and limit reasons. Roots/metadata that cannot fit are rejected. Encoding a candidate and building the inventory index can occur before these query limits apply. |
| Bounded backward syntax dependence | Depth 8; 100 nodes; 200 edges; 2,000 work visits; 256,000 encoded bytes; 8 reaching definitions/variable | Follows possible assignments, parameters, resolved calls and returns and optionally includes guards. Multiple definitions/callers/returns and unresolved boundaries remain explicit. These limits do not turn syntax into branch feasibility, sanitizer knowledge, runtime reachability, taint or exploitability. |
| Inventory/neighbor pagination | 100 results/page | Counts bound returned entries, not serialized bytes or all predicate/index work. Preserve total/continuation information when available. |
| BEAM module provenance | 5,000,000 bytes/BEAM; 25,000 modules; 100,000,000 total bytes | File/aggregate checks bound the intended ownership input set. Stat-then-read is not a hard allocation guarantee for concurrently changing files. |
| Diagnostic message | Fixed 4,096 UTF-8 bytes, including any `...` suffix | Constructor and isolated-failure text normalize only a bounded prefix. Invalid bytes become U+FFFD; direct validation rejects oversized or malformed text without echoing it. Original-message failure hashing remains unchanged. See R1. |

The diagnostic behavior is in
[Diagnostic](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/diagnostic.ex) and
[Isolated.Result](https://github.com/houllette/rampart/blob/main/apps/rampart_sast/lib/rampart_sast/isolated/result.ex).
Neither display truncation nor a paginated list replaces the adapter's final
encoded-response limit.

## Foray job orchestration and output

Sources: [scan](https://github.com/houllette/rampart/blob/main/apps/foray/lib/foray/scan.ex),
[job builder](https://github.com/houllette/rampart/blob/main/apps/foray/lib/foray/job_builder.ex),
[pipeline](https://github.com/houllette/rampart/blob/main/apps/foray/lib/foray/pipeline.ex),
[stream](https://github.com/houllette/rampart/blob/main/apps/foray/lib/foray/stream.ex),
[ffuf engine](https://github.com/houllette/rampart/blob/main/apps/foray/lib/foray/fuzz/ffuf.ex),
[NDJSON framing](https://github.com/houllette/rampart/blob/main/apps/foray/lib/foray/ndjson.ex), and
[completion receipt](https://github.com/houllette/rampart/blob/main/apps/foray/lib/foray/fuzz/ffuf/completion.ex).

| Control | Default and unit | Enforcement and remaining boundary |
| --- | --- | --- |
| HTTP workload | 50 requests/second aggregate; 20 ffuf threads/job; 2 concurrent whole jobs | Effective concurrency is bounded by configured concurrency, target count and aggregate rate. Each ffuf job receives the integer-floor share of the rate; payloads remain inside ffuf. |
| Job admission | Optional job-rate limiter; processor demand 1 | Job/message admission units differ from HTTP requests. Backpressure does not bound all results retained by a downstream collector. |
| Native time budgets | 300 seconds/job; 10 seconds/request | Passed to ffuf. These native controls are not a separate hard host deadline for the complete stream. |
| Process I/O and shutdown | 65,535-byte chunks; 5,000 ms exit handling; 2,000 ms version probe | Pipeline shutdown defaults to job max time plus 10,000 ms; stream teardown uses 5,000 ms. Lifecycle limits are distinct from request and output budgets. |
| NDJSON line | Fixed 1,048,576 raw bytes, excluding LF and including CR | Complete lines, unfinished fragments and direct line parsing are checked before trimming/decoding. Input is split into 16,384-byte pieces; fragments assemble once per line. Error previews copy at most 1,024 bytes. See R3. |
| Completion receipt | Fixed 16,777,216 bytes | Reads at most the allowance plus one byte, then checks the complete audit. Invalid/missing/oversized receipts become output errors; validation cannot treat incomplete negative evidence as refutation. This read limit does not cap ffuf's disk writes. |
| Version fingerprinting | Hash only eligible executables at most 33,554,432 bytes; 65,536-byte hash chunks | A narrow version-identification check, not a general executable trust or runtime resource boundary. |

Wordlist/body materialization uses host-owned inputs and temporary-file cleanup;
it has no universal total input/disk quota. A host must bound the plan and
artifact storage. Early positive validation can stop after sufficient evidence;
it must not be described as an exhaustively completed ffuf job.

## Portico discovery and enrichment

Sources: [scan](https://github.com/houllette/rampart/blob/main/apps/portico/lib/portico/scan.ex),
[stream](https://github.com/houllette/rampart/blob/main/apps/portico/lib/portico/stream.ex),
[pipeline](https://github.com/houllette/rampart/blob/main/apps/portico/lib/portico/pipeline.ex),
[RustScan](https://github.com/houllette/rampart/blob/main/apps/portico/lib/portico/discovery/rust_scan.ex),
[line framing](https://github.com/houllette/rampart/blob/main/apps/portico/lib/portico/discovery/line_stream.ex),
[nmap](https://github.com/houllette/rampart/blob/main/apps/portico/lib/portico/enrichment/nmap.ex), and
[XML parser](https://github.com/houllette/rampart/blob/main/apps/portico/lib/portico/nmap_xml.ex).

| Control | Default and unit | Enforcement and remaining boundary |
| --- | --- | --- |
| Enrichment admission | Online scheduler count; 1 host/batch; 1,000 ms batch wait; optional host/message rate limit | Bounds concurrent batches and admission. It does not count native network probes or total returned hosts. |
| RustScan work | 4,500 native socket batch size; 1,500 ms socket timeout; 1 try | Native socket controls. There is no separate suite-owned deadline for the entire discovery stream. |
| Discovery I/O | 65,535-byte native chunks; 2,000 ms exit handling; fixed 1,048,576-byte raw lines | Complete and unfinished lines are bounded before parsing, including direct RustScan parsing. LF is excluded; CR counts. Internal splitting uses at most 16,384 bytes and error previews copy at most 1,024 bytes. See R3. |
| nmap enrichment | 120,000 ms wrapper timeout; native per-host timeout defaults to infinity | Wrapper covers command consumption and parsing, returning timeout host outcomes on expiry. Validation treats missing timeout evidence as inconclusive. Cleanup can add time. |
| nmap I/O | 65,535-byte chunks; 5,000 ms exit handling | Streaming reduces collection pressure but does not cap the retained native domain result. |
| XML input and structure | 16,777,216 document bytes; depth 64; 100,000 elements | Raw bytes are checked before feeding Saxy. Depth and total elements are checked before updating the model. See R4. |
| XML native result | 1,024 hosts; 65,536 ports; 16,384 scripts; 65,536 table/element nodes | Cumulative per document, including ignored elements and non-collected hosts. Exceeding a limit returns an error, never a successful partial result. |
| XML decoded text | 8,388,608 attribute-value/character bytes total; 65,536 bytes per attribute value or accumulated CPE/element value | Checks precede model updates. Text pieces are joined once per value. These checks occur after the SAX event is decoded, not before all parser allocation. |
| XML character delivery | `character_data_max_length: 16,384`; internal input pieces at most 16,384 bytes | Saxy event delivery threshold only; the independent input/model budgets provide the rejection policy. |

The Saxy interpretation follows the installed dependency's `Saxy.parse_stream/4`
documentation in `deps/saxy/lib/saxy.ex`. Portico must retain its rich host,
port and script model. Limit failures produce native error outcomes, which
endpoint validation reports as inconclusive. A host callback is provisional
until the document completes. Scanner streams permit early reader termination
so process cleanup does not mask the parser error; nonzero exits after EOF
remain failures.

## Havoc, PropEr and Muex

Sources: [property execution](https://github.com/houllette/rampart/blob/main/apps/havoc/lib/havoc/property.ex),
[corpus persistence](https://github.com/houllette/rampart/blob/main/apps/havoc/lib/havoc/corpus.ex),
[term codec](https://github.com/houllette/rampart/blob/main/apps/havoc/lib/havoc/term_codec.ex),
[generators](https://github.com/houllette/rampart/blob/main/apps/havoc/lib/havoc/gen.ex),
[stateful harness](https://github.com/houllette/rampart/blob/main/apps/havoc/lib/havoc/harness.ex),
[guided search](https://github.com/houllette/rampart/blob/main/apps/havoc_proper/lib/havoc_proper/guided.ex), and
[Muex extension](https://github.com/houllette/rampart/blob/main/apps/muex_security/lib/muex_security.ex).

| Control | Default and unit | Enforcement and remaining boundary |
| --- | --- | --- |
| Ordinary properties | 200 runs; 100 shrinking steps; no configured max run time or generation size | Delegated to StreamData. A configured engine time budget does not preempt a target callback that never returns. Replay and shrinking are separate from generated-run counts. |
| Boundary generation | 16,384 maximum length for the boundary generator's repeated-character case | This option is not a byte ceiling for every adversarial generator or caller-provided seed. |
| Unicode unit-disparity generation | 256 bytes; 64 combining marks | `Havoc.Gen.unicode_length/1` bounds generated and shrunk inputs in bytes. It does not cover all Unicode normalization behavior. |
| Byte partitions and incremental capture | 65,536 input bytes; 64 chunks | Generator construction and capture check bounds before execution; capture stores at most 65 counter samples and stops on acceptance/rejection. Callback work, allocations, spawned processes and cleanup remain host-owned. Increasing chunk count may also exceed the separate persisted-term nesting bound. |
| Length oracle measurement | Explicit policy unit/limit; 1,048,576 measurement bytes | Bytes use constant-time `byte_size/1`. Unicode measurement skips invalid UTF-8 or values above the measurement cap. This cap bounds measurement traversal, not creation of the observed binary. |
| Incremental budget oracles | Explicit retained-byte or work-unit limit | Each completed step is measured by the host adapter. Unknown samples skip unless an observed excess already proves the budget violation; counters do not establish whole-VM memory use or formal complexity. |
| Corpus file | Fixed 16,777,216 bytes | Load checks file size; save checks encoded size before atomic replacement. Encoding/decoding and stat-then-read are not hard peak-memory boundaries. |
| Persisted term | Fixed 1,048,576 encoded term bytes; recursive nesting limit 100 | Size is checked after serialization or Base64 decoding; recursive shape is checked before encode and after safe term decode. List tails consume depth too. These checks do not bound initial decode allocations or arbitrary caller terms. |
| Stateful harness plan | 64 steps; 65,536 inert JSON bytes | The plan names reviewed operations and exact payload references but contains no callbacks. Host bindings default to 5,000 ms and 1,048,576 cumulative observation bytes. The deadline is checked between callbacks and cannot preempt a callback that never returns; teardown is attempted after step failure. OS isolation remains external. |
| Guided search | 1,000 search steps; 32 line- or feature-novel archive entries | PropEr owns search; targeted properties do not promise ordinary shrinking. Step count is not a global target-call cap. Cover sessions remain serialized because Cover is node-global. A manifest identifies exact search configuration and covered BEAM bytes, not the stochastic input trajectory. |
| Guided semantic features | 128 unique IDs; 256 bytes/ID; 8,192 aggregate ID bytes/candidate | A host callback returns stable string labels which contribute fitness and novelty. Labels and exact candidates may be persisted, so they must be non-sensitive. Callback failure fails the search rather than becoming a security confirmation. |
| Guided generator neighborhoods | 256 bytes for binary neighborhoods; 1,024 bytes for injection neighborhoods | Candidate mutations are truncated to `max_length`. Initial curated injection values are selected separately and are not truncated by that option. |
| Security mutation | Delegated to Muex configuration | `muex_security` adds operators, not an execution engine or independent process/output budget. The host selects Muex timeout/concurrency/workload options for its installed version. |

The neighborhood controls are in
[HavocProper.Gen](https://github.com/houllette/rampart/blob/main/apps/havoc_proper/lib/havoc_proper/gen.ex).
Target isolation, external side effects, fixture teardown and whole-response
limits remain host responsibilities. A corpus persistence limit must not be
advertised as a general fuzz-input or executing-target memory limit.

## Experimental IAST

Sources: [limits](https://github.com/houllette/rampart/blob/main/apps/rampart_iast/lib/rampart_iast/limits.ex),
[trace session](https://github.com/houllette/rampart/blob/main/apps/rampart_iast/lib/rampart_iast/trace_session.ex), and
[argument inspection](https://github.com/houllette/rampart/blob/main/apps/rampart_iast/lib/rampart_iast/argument.ex).

| Control | Default and unit | Enforcement and remaining boundary |
| --- | --- | --- |
| Session and delivery | 1,000 ms execution; 250 ms trace delivery barrier | Execution and delivery limits are separate from host setup/teardown and the final response deadline. |
| Trace events | 100 recorded events | Overflow stops detailed processing and terminates the controlled execution. An excess event may already have arrived. |
| Argument inspection | 4,096 bytes; depth 64; 4,096 terms | Bounded walk precedes full external-size measurement for compound terms; binary byte length is checked before marker search. It does not prevent trace arguments being copied into messages first. |
| Mailbox pressure | 1,000 queued messages | Reactive queue observation, not a hard mailbox capacity. Overflow cannot establish production memory safety. |

The sensor remains gated and proves only unchanged-marker reachability in one
traced execution process. Resource controls do not expand that semantic claim.

## Host and evaluation budgets

The [bound validation example](https://github.com/houllette/rampart/blob/main/examples/bound_validation.exs) requires a
positive host output limit. It encodes the projection before checking its byte
length, then checks an artifact-reference fallback. This limits returned data,
not the initial encoding allocation. The external adapter must also account
for its final Lemieux envelope and artifact access policy.

The [OS isolation runner](https://github.com/houllette/rampart/blob/main/evaluation/isolation/run.py) copies admitted
source trees (50,000 files and 250,000,000 source bytes maximum), scrubs the
environment, denies network and out-of-workspace data access through
`sandbox-exec` or bubblewrap, applies available POSIX limits, bounds captured
output, and kills the child process group. macOS does not truthfully provide the
address-space or process-count capabilities here; Linux bubblewrap does.
`RLIMIT_FSIZE` is per file rather than a total disk quota. Commands and profiles
remain host-owned, reviewed authority.

The [integration runner](https://github.com/houllette/rampart/blob/main/evaluation/integration/run.py) owns subprocess
deadlines for trusted repository fixtures. The
[evaluation corpus](https://github.com/houllette/rampart/blob/main/evaluation/corpus.exs) also specifies latency and artifact
acceptance thresholds. Acceptance thresholds are measurements evaluated after
work, not primitive runtime enforcement. Neither mechanism supplies a universal
OS memory or disk quota for arbitrary target repositories.

## Implemented priorities — 2026-09-10

### R1 — Diagnostic bytes

SAST now uses a 4,096-byte UTF-8 message limit including the truncation suffix.
The constructor normalizes binary and formatted non-binary messages; direct
validation rejects invalid or oversized messages. The isolated-failure path
uses the same formatter. Malformed input bytes become U+FFFD. Truncation
preserves codepoint boundaries without scanning an oversized string's full
grapheme sequence.

Isolated failure IDs deliberately continue hashing the **original** message.
This preserves existing references and distinguishes failures with the same
display prefix; hashing is still linear in the original input bytes. Formatting
arbitrary non-binary terms also occurs before the message-byte check. These
choices do not constitute a universal diagnostic-generation work bound. Paths,
metadata and the final encoded response still require host output budgets.

Regression cases cover combining sequences, multibyte exact limits, malformed
UTF-8, formatted terms, direct structs and original-message identity. The
upstream motivation remains [CVE-2026-82752](https://cna.erlef.org/cves/CVE-2026-82752.html);
these checks do not demonstrate a Rampart denial of service.

### R2 — Patched runtime pins and component identity

The default in [.tool-versions](https://github.com/houllette/rampart/blob/main/.tool-versions) is now OTP `29.0.6`; the
[compatibility matrix](https://github.com/houllette/rampart/blob/main/.github/workflows/ci.yml) uses `28.5.0.6` and `29.0.6`.
The existing Elixir `1.20.2` pairs remain unchanged. These replace OTP
`28.3.1`/`29.0.2` and include the disclosed inets and ERTS corrections in the
[OTP 28.5.0.6 release](https://github.com/erlang/otp/releases/tag/OTP-28.5.0.6)
and [OTP 29.0.6 release](https://github.com/erlang/otp/releases/tag/OTP-29.0.6).

[evaluation/runtime.exs](https://github.com/houllette/rampart/blob/main/evaluation/runtime.exs) reads the installed
`OTP_VERSION` and inets/SSH application metadata without starting either
service. If Mix prunes an application's code path, the lookup accepts only a
single matching installed application file; missing or ambiguous installations
remain unknown. Evaluation, performance and integration reports now include these
fields alongside existing runtime identity. Unavailable metadata is `nil`,
never inferred from a major release or the repository pin. Old retained
reports remain unchanged.

Local execution uses OTP `29.0.6`, ERTS `17.0.6`, inets `9.7.2`, SSH `6.0.5`,
and Elixir `1.20.4`. The exact pinned Elixir/OTP matrix still requires its CI
runs; local results do not stand in for those profiles. Installed version
metadata does not prove a service is exposed.

### R3 — Complete-line framing

Foray and Portico each implement their own bounded line framer. It counts raw
bytes before whitespace processing, accepts exactly 1,048,576 bytes excluding
one terminating LF, and includes any CR in that allowance. Both direct parser
entry points enforce the same policy. Splitting works on at most 16,384 bytes
at a time; incomplete fragments are assembled once when the line completes.
A supplied binary or converted iodata chunk already exists in caller memory;
this is not a bound on the caller's initial input allocation.

`OutputError.line` is now a copied binary preview of at most 1,024 bytes, not
the entire rejected line. Native exception messages render bounded previews.
Regression cases exercise complete and unfinished lines, several partitions,
exact LF/CRLF boundaries, direct parsing and unchanged valid match data. The
[Mint buffer case](https://cna.erlef.org/cves/CVE-2026-82728.html) informed the
all-states requirement; it is not evidence of a Rampart exploit.

### R4 — XML input and decoded-model budgets

`Portico.NmapXML` accepts `limits: [...]`; the nmap engine exposes the same
positive options as `xml_limits: [...]`. Defaults are in
[Limits](https://github.com/houllette/rampart/blob/main/apps/portico/lib/portico/nmap_xml/limits.ex), with units in the table
above. Counts stay cumulative with `collect: false`. Limit errors return
`{:error, {:xml_limit, key, limit}}`; the engine retains that reason and
validation becomes inconclusive. Already-delivered `on_host` callbacks remain
provisional until the final successful parse result.

The existing rich fixture is 1,417 bytes with 24 elements, one host/port, two
scripts and two nested script nodes. Defaults provide substantial configurable
headroom above this reviewed example; they are not a measured production
capacity or maximum-RSS guarantee. The document cap protects the parser input,
while decoded counters protect model growth. Saxy may allocate a token before
its event reaches the handler.

Regression cases cover each structural budget, entity-decoded and accumulated
text, exact boundaries, nested values, non-collected hosts, input cleanup,
engine propagation and inconclusive validation after a partially parsed host.
A native-process case checks cleanup on parser rejection. Script values use
reversed text chunks joined once, avoiding repeated growing-string copies.

## Validation scope

The change is checked with `mix precommit` and the focused
`mix rampart.integration --suite native` gate. The latter consumes freshly
built package archives and exercises real RustScan 2.4.1, nmap 7.99 and ffuf
2.2.0 against owned loopback fixtures. It includes exact replay, negative and
inconclusive outcomes, rate controls and process/artifact cleanup. These runs
do not execute the eight newly cataloged upstream CVEs or establish performance
SLOs. The OTP 28 and exact pinned Elixir profiles remain CI validation work.
