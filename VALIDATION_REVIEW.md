# Rampart validation review — 2026-09-09

Reviewed commit: `9817fe9`. The working tree was clean at the start. The original
assessment and measurements below describe that baseline. The subsequent
implementation addresses all seven reproduced defects and all six additional
performance opportunities in this review; see [PERFORMANCE.md](PERFORMANCE.md)
for retained before/after evidence and measurement limits.

Implemented: terminate-and-reap isolated workers; corpus write-size enforcement
and map-based imports; Cover serialization and restoration after caller death;
unambiguous Foray identities with persisted versioning and explicit legacy
re-observation; indexed, complete SAST convenience queries and bounded graph
traversal; IAST overflow cancellation and bounded container inspection;
source-rule closure reduction; prepared seed indexes; collected-output limits;
and ffuf consumer cancellation independent of job duration. Regression tests
exercise these changes, including real disposable BEAM and shell children.

Final implementation checks: `RAMPART_REQUIRE_DISTRIBUTED=1 mix precommit`
passed with 278 tests/properties and 345/345 evaluation checks across 14 cases.
`MIX_ENV=test mix dialyzer` passed with zero errors or skips. The performance
workflow passed actionlint 1.7.12, and all 25 retained benchmark case identities
and before/after harness hashes were verified. The final repository integrity
scan was complete with 54,671 facts, four static signals, and zero suppressions.

The broader all-primitives release gates below remain future validation work.
Silent-child lifecycle fixtures do not establish interoperability with actual
RustScan, nmap, or ffuf binaries, and synthetic graph measurements do not replace
full application executions.

**Assessment:** the initial architecture substantially matches `NORTH_STAR.md`.
The next milestone should establish reliable lifecycle handling, complete and
bounded queries, durable replay, and representative performance. The current
evidence supports a useful experimental foundation, but does not establish that
all primitives are ready for independent release or operating at their full
performance potential.

The strongest architectural choices are already implemented: tools retain their
own domain models; Core contains shared contracts and process/scope machinery;
Havoc delegates generation/shrinking to StreamData; Foray schedules whole jobs;
MuexSecurity delegates execution to Muex; and static facts, runtime reachability,
and vulnerability claims remain distinct. The dependency declarations preserve
the intended direction, including the optional HavocProper extension. Host
bindings keep executable authority outside model inputs.

**Validation performed**

| Check | Result |
| --- | --- |
| `mix precommit` | Passed: compile, formatting, Credo, audits, SAST, evaluation, usage rules, xref, docs, and tests |
| ExUnit | 253 passing tests/properties across eight applications |
| Repository SAST | Complete; 51,823 facts, four rule signals, zero suppressions. Signals are not vulnerability verdicts. |
| `RAMPART_REQUIRE_DISTRIBUTED=1 mix rampart.eval --json` | 14 cases, 345/345 checks, zero reported false confirmations, 14 replay successes; distributed execution required and passed |
| `MIX_ENV=test mix dialyzer --force-check` | Passed, zero errors and zero skips after repairing an incomplete local PLT build |
| `mix hex.build` in every child | All eight packages built |
| Additional review probes | Seven gaps reproduced below |

Local runtime: Elixir 1.20.4, OTP 29 / ERTS 17.0.6, Apple ARM64, ten online
schedulers. This differs from `.tool-versions` (Elixir 1.20.2 / OTP 29.0.2).
These results do not replace the pinned OTP 28/29 CI comparison. RustScan, nmap,
and ffuf were unavailable locally, so no live binary interoperability claim is
made. Building a Hex archive also does not prove that an unpacked package works
in a separate consumer project.

Dependencies were initially absent; installing the existing lockfile resolved
the initial precommit dependency check. Initial Dialyzer attempts had an
incomplete dependency PLT; the forced check rebuilt it and passed. Neither is
counted as an application defect. Dependency compilation emitted upstream
warnings; the repository's warnings-as-errors gates passed.

**Reproduced findings, in recommended fix order**

1. **P1 — An isolated scanner timeout does not establish child termination.**
   `apps/rampart_sast/lib/rampart_sast/isolated.ex:283` handles timeout/log overflow
   by calling `Port.close/1` at line 306. A controlled silent child substituted
   through the supported executable option remained alive after a one-second
   timeout returned an incomplete result. The probe explicitly terminated its
   child afterward. Closing the communication port is insufficient lifecycle
   evidence: repeated timed-out scans can leave work running outside the claimed
   deadline. Use the existing Core/Exile process ownership mechanism or an
   equivalent monitored worker owner with terminate-and-reap behavior. Preserve
   the string-keyed protocol and never move target AST decoding into the parent.
   **Done when:** timeout, log overflow, caller death, and protocol failure all
   produce incomplete results and leave no worker or late response files after
   bounded cleanup; include an actual disposable BEAM worker in the regression.

2. **P1 — Havoc can successfully write a corpus that it cannot load.**
   `apps/havoc/lib/havoc/corpus.ex:234` rejects files above 16,777,216 bytes, but
   `write_seeds!/2` at line 278 does not enforce that limit before replacing the
   corpus. Importing fourteen individually valid 950,000-byte payloads returned
   `{:ok, 14}`, wrote 17,738,119 bytes, and immediately failed to load with
   `:corpus_too_large`. This breaks the durable replay contract. Validate the
   complete encoded size before atomic replacement and preserve the previous
   corpus on rejection. **Done when:** every successful import is reloadable,
   oversized updates fail explicitly without replacing existing proof, and
   concurrent imports retain all accepted seeds.

3. **P1 — HavocProper's Cover lock does not serialize distinct callers.**
   `apps/havoc_proper/lib/havoc_proper/coverage.ex:19` uses
   `:global.trans({__MODULE__, :session}, ...)`. The second tuple element is the
   lock requester identity; every caller supplies the same one. While one
   invocation held an instrumented session, a second invocation entered and
   raised “OTP Cover already instruments modules” before the first was released.
   The existing tests only exercise sequential use. Use a distinct requester
   identity such as `self()` and scope the resource consistently with node-global
   Cover. **Done when:** overlapping callers wait, each measures its own session,
   exceptions restore original code, and an unrelated existing Cover session is
   still refused without destruction. The probe demonstrates failed
   serialization, not observed corruption of coverage results.

4. **P1 — Distinct Foray inputs can produce the same finding identity.**
   `apps/foray/lib/foray/finding.ex:89` serializes sorted input pairs using `=` and
   NUL delimiters without escaping or length framing. The accepted input maps
   `%{"A" => "x\0B=y", "B" => "z"}` and
   `%{"A" => "x", "B" => "y\0B=z"}` generated identical finding IDs through
   the NDJSON parser and finding projection. This is an encoding collision,
   independent of SHA-256, and can conflate observations during deduplication.
   Encode the sorted pairs unambiguously, then hash that representation; account
   for existing identities when changing the contract. **Done when:** distinct
   accepted binary inputs remain distinct, ordering does not change identity,
   and exact replay still joins the originating observation. This probe did not
   demonstrate a false vulnerability confirmation or execute HTTP traffic.

5. **P1 — `Inventory.calls_to/3` can report no calls when a call exists.**
   `apps/rampart_sast/lib/rampart_sast/inventory.ex:156` first takes the default
   100-result module query, then filters by function. A source with 120
   `String.trim/1` calls followed by `String.upcase/1` yielded one exact
   `String.upcase/1` fact but zero `calls_to(inventory, "String", "upcase")`
   results. Apply the complete predicate before pagination and expose
   continuation/completeness in bounded convenience APIs. Review
   `package_usage/2` and other list-returning helpers for similar hidden limits.
   **Done when:** a match beyond the first module page is found, multi-page
   results can be exhausted deterministically, and an empty page cannot be
   confused with an exhaustive absence claim.

6. **P2 — Graph node limits do not bound edge/evidence volume.**
   `apps/rampart_sast/lib/rampart_sast/graph.ex:121` retains each distinct fact
   connecting already-seen nodes. A two-node slice returned 2,000 edges with
   `max_nodes: 3` and `truncated: false`. Add explicit edge and output budgets,
   report why traversal stopped, and retain a continuation or artifact route for
   omitted evidence. Keep parallel source facts available; collapsing them into
   one edge would discard provenance. **Done when:** dense, cyclic, multi-root,
   exact-capacity, and depth-limited graphs respect independently tested bounds
   and have accurate completeness metadata.

7. **P2 — IAST limits stop evidence retention but not event-processing work.**
   `apps/rampart_iast/lib/rampart_iast/trace_session.ex:357` continues inspecting
   arguments after recording event/mailbox overflow. With `max_events: 1`, a
   5,000-call probe processed all 5,000 events and retained one observation. It
   correctly returned an incomplete envelope with event/mailbox failures, so the
   verdict fails closed; the remaining issue is resource enforcement.
   `argument_size/1` at line 486 also traverses non-binary terms before the
   bounded marker walk. Notify the owner on overflow, disable tracing or cancel
   the controlled execution, and stop detailed inspection. Bound nested-term
   traversal without first walking the entire oversized value. **Done when:**
   sustained sink floods and oversized containers have bounded extra work,
   bounded memory, explicit incomplete evidence, and verified teardown.

**Performance evidence and improvements**

The current evaluation's largest static fixture produced 716 facts; Rampart's
own integrity scan produced 51,823. Existing fixture timing gates therefore
leave a substantial scale gap.

An additional synthetic chain benchmark used five samples per combination and
the existing graph implementation. These are local medians, not release SLOs:

| Inventory facts | Depth 5 | Depth 50 | Depth 150 |
| --- | ---: | ---: | ---: |
| 5,000 | 0.46 ms | 3.08 ms | 8.96 ms |
| 20,000 | 1.93 ms | 12.26 ms | 34.90 ms |
| 50,000 | 5.56 ms | 30.44 ms | 87.90 ms |

`Graph.walk/7` filters the entire edge collection for each expanded node and
appends to a list queue. Its work grows approximately with facts multiplied by
visited nodes; the default shallow query is cheaper than the depth-150 case.
Build adjacency indexes once per inventory and use `:queue`. Preserve stable
fact ordering, duplicate provenance, and artifact identity. This is the best
measured optimization opportunity, and should accompany the query correctness
work rather than precede it.

The required-distributed evaluation measured a 7.12 ms disabled median versus
13.48 ms targeted median for the seven-sample IAST fixture: +6.36 ms, 1.89×,
with a 14.50 ms targeted p95. The earlier precommit sample reported 3.04×.
The variability reinforces the research notes: this measures complete validation
on one small workload, including setup, teardown, and result construction. It
does not isolate tracer overhead or establish production suitability.

Additional opportunities identified from code, whose speedups remain unmeasured:

| Opportunity | Why it matters | Smallest useful change |
| --- | --- | --- |
| Avoid capturing every source in every source-rule task (`scanner.ex:162`) | The callback closes over all parsed sources although source rules ignore that argument; large AST collections can be copied into many tasks | Split source and project jobs; give source jobs only the data their contract requires |
| Index inventory queries (`inventory.ex:134`, `isolated.ex:97`) | Every page filters the whole fact collection and materializes all matches | Build invocation-local indexes; preserve totals and deterministic pagination |
| Index Foray seed provenance (`wordlist.ex:21`) | Each emitted match linearly searches its seed corpus | Prepare a value-to-seed lookup once per job, with explicit duplicate-value behavior |
| Merge Havoc imports by ID (`corpus.ex:185`) | Repeated list upserts rescan the growing corpus, producing quadratic batch work | Build one ID map, merge once, sort once, encode once |
| Bound collected process output (`core/runner/exile.ex:45`) | `run/2` has time/chunk limits but accumulates all output before returning | Add a total-byte limit and explicit failure; preserve stream semantics |
| Separate cancellation latency from ffuf job duration (`foray/stream.ex:68`) | A silent job can make graceful cancellation depend on its long configured shutdown/maxtime | Add a controlled owner-cancellation path and test it with a silent real child |

Do not increase concurrency first. It would amplify copying, trace pressure,
and process-lifecycle defects. Keep Portico's compatible-port batching, Foray's
aggregate request ceiling, and synchronous sink backpressure intact. Adding a
database, another task framework, or a custom PBT engine is unnecessary for
these improvements.

**Completion gates for the first implementation of every primitive**

| Primitive | What is supported today | Remaining evidence required for initial sign-off |
| --- | --- | --- |
| Core | Validation actions/verdicts, host bindings, JSON projection, deny-by-default scope, telemetry, process seam | Contract tests in an independent consumer; bounded collected output; adversarial result sizes and malformed values; cancellation/crash/scope outcomes stay distinguishable |
| Portico | Native host model, replaceable engines, lazy/Broadway paths, compatible batching, endpoint recheck | Pinned RustScan→nmap loopback test against known open/closed endpoints; stalled discovery, partial/malformed XML, timeout, slow sink, consumer death, and child cleanup; explicitly classify down/filtered/incomplete evidence |
| Foray | Whole-job orchestration, request-rate allocation, bounded delivery, scope checks, NDJSON, exact match replay | Fix input identity; pinned ffuf against a local HTTP fixture; multiple inputs, binary payloads, match floods, no-match/stalled jobs, cancellation, recursion constraints, and measured request ceiling |
| Havoc | StreamData generation/shrinking, conservative pass/skip/violation oracles, exact validation, durable seeds, derived targets | Fix corpus size handling; vulnerable/fixed/failure/replay controls for each oracle family; add IP-policy, route-topology, and lifecycle examples; larger corpus/import and crash-recovery tests |
| HavocProper | Optional PropEr search, line-coverage fitness, Havoc-owned verdicts/corpus | Fix session serialization; verify restoration on concurrent/failing/killed owners; demonstrate coverage gain over unguided search on a nontrivial target with comparable budgets; never relabel line coverage as taint or branch proof |
| MuexSecurity | Five focused operators, registry/configuration, Muex AST traversal integration | Run real Muex execution on a small test project: security tests kill meaningful bypass mutants, missing controls yield survivors, unrelated code is untouched, compilation/timeouts remain distinct results; keep the future Core adapter outside the operator pack |
| RampartSAST | Parse-once Elixir/Erlang snapshots, provenance-backed packages, callbacks/protocol facts, classifiers, queries, static replay, disposable scanner | Fix lifecycle/query bounds; representative 50k–250k-fact workloads and declared input-limit cases; macro, callback/protocol, Erlang/Rebar and dependency-misuse examples; independent package ownership/ambiguity and replay controls |
| RampartIAST | Gated single-process unchanged-marker proof, provider-owned declarations, qualified localization, fail-closed verdicts | Enforce resource stops; representative compute, binary/container, IO and concurrent-session workloads; scheduler/reduction/memory measurements; repeat teardown/fault probes; actual framework execution drivers while preserving explicit cross-process refusal |

For all eight packages, unpack the built archives into clean temporary consumer
projects and compile/run representative APIs with only declared dependencies.
This is a stronger independence gate than building archives inside the umbrella.

For performance sign-off, record fixture/source hashes, runtime, scheduler
count, input sizes, warmup policy, repeated latency distributions, reductions,
GC/memory peaks, queue depths, and cancellation latency. Keep broad CI smoke
budgets, then add a separate repeatable performance job with baseline comparison.
Missing platform metrics should remain absent/unknown rather than zero. Choose
regression thresholds from those baselines and the documented operating envelope;
the current measurements do not justify a universal “fast enough” threshold.

**Recommended implementation sequence**

1. Land focused regression/fix changes for isolated-worker cleanup, corpus write
   limits, Cover locking, Foray identity, and SAST query correctness. Account for
   identity compatibility before publishing the Foray change.
2. Add graph edge/work/output bounds and IAST overflow termination, then measure
   adjacency indexing, source-task copying, seed lookups, and corpus merging.
   Run `mix rampart.eval` for every graph, evidence, or replay change and keep
   `mix precommit` green.
3. Add an all-primitives integration gate: real local RustScan/nmap/ffuf,
   complete Muex execution, guided-search comparison, and archive-consumer tests.
   Retain logs and exact replay evidence for failures.
4. Graduate the current adapted historical predicates to at least a small set of
   full pinned package/application executions. Prioritize Phoenix/Ecto/Ash,
   macro/callback/protocol dispatch, Erlang, IP policy, route topology, and
   state lifecycle. Require independent expectations and negative/failure
   controls; candidate count is not an accuracy target.
5. Exercise one deterministic cross-tool observe→hypothesis→validate→replay
   workflow through a separate adapter or integration application. Persist large
   evidence as host-authorized artifacts; test binding reconstruction after
   resume and enforce the consumer's wire-output limit. Keep Lemieux outside
   Rampart and keep experimental IAST unavailable as an agent tool until its
   existing research gates pass.

The initial milestone is complete when the declared proof levels survive these
tests within a measured operating envelope. General cross-process taint,
transformed-value tracking, production instrumentation, and a larger static rule
catalog remain subsequent work. The existing boundary probes are useful research
evidence; they do not make those broader capabilities prerequisites for finishing
the current primitives.

**Local evidence artifacts**

- `tmp/rampart-review-evaluation.json`: complete required-distributed evaluation.
- `/tmp/rampart-review-precommit.log`: initial successful repository gate.
- `/tmp/rampart-review-dialyzer-final.log`: successful forced PLT check/type analysis.
- `/tmp/rampart-review-packages.log`: eight successful archive builds.
- `/tmp/rampart-review-probes.exs` and `.log`: query, graph, Cover, and trace probes.
- `/tmp/rampart-review-worker-probe.exs` and `.log`, with
  `/tmp/rampart-review-worker.sh`: isolated process lifecycle probe.
- `/tmp/rampart-review-corpus-probe.exs` and `.log`: corpus write/read limit probe.
- `/tmp/rampart-review-foray-probe.exs` and `.log`: input identity collision probe.

The temporary probes are investigation artifacts, not committed regression tests.
Promote each into its owning application's test suite with its corresponding fix.
