# Performance validation — 2026-09-09

The review fixes improve repeated graph traversal, seed provenance lookup, and
corpus import while enforcing previously incomplete resource boundaries. The
architecture remains deterministic and independent of an LLM. This comparison
does not complete the broader release-validation gates in `VALIDATION_REVIEW.md`.

The same harness ran against reviewed commit `9817fe9` in an isolated checkout
and the updated implementation, sequentially on Apple ARM64 with Elixir 1.20.4,
OTP 29 / ERTS 17.0.6 and ten schedulers. Each case used two warmups and seven
measured samples. Inputs, runtime, harness hashes, latency distributions,
reductions, GC counts, and memory endpoints are retained under
`evaluation/baselines/2026-09-09/` in `before.json`, `after.json`, and
`comparison.json`.

| Workload | Before median | After median | Observed speedup |
| --- | ---: | ---: | ---: |
| 50,000 facts, graph depth 150 | 87.746 ms | 0.644 ms | 136× |
| 250,000 facts, graph depth 150 | 605.475 ms | 0.710 ms | 853× |
| 1,000 finding projections, 10,000 seeds | 119.272 ms | 6.637 ms | 18× |
| Import and reload 5,000 seeds | 389.001 ms | 50.530 ms | 7.7× |
| Source-rule scan, 50 files / 5,000 calls | 259.906 ms | 208.925 ms | 1.24× |

Graph measurements exclude the upfront index build, which is recorded
separately in each case: about 228 ms for 50,000 facts and 1.61 s for 250,000
facts. Indexes trade construction time and memory for repeated queries; a
single shallow query may not recover that cost. The source-rule
measurement includes the complete scan and index build, so it does not isolate
closure-copy savings. Finding projections use prepared jobs and exclude seed
index construction. The large graph inputs are synthetic chains, not full
250,000-fact application scans. Dense, cyclic, multi-root, byte/work/edge limits,
and portable pagination are covered by regression tests.

Targeted IAST sessions took roughly 7.3–8.0 ms on compute, binary, container,
and in-memory IO workloads. Several increased by 4–9% relative to this baseline;
no IAST speedup is claimed. This includes session setup, teardown, and result
construction. The change stops detailed argument processing after overflow and
cancels the controlled execution. Trace messages may have copied arguments or
entered the mailbox before a limit is noticed, so these tests do not establish
a hard VM memory ceiling or production safety.

Memory values are process/VM endpoints, not peak RSS. Node reductions and GC
counts include background VM activity. Sub-microsecond disabled cases can round
to zero and have no meaningful ratio. These local observations are not release
thresholds and do not replace the pinned OTP 28/29 CI matrix.

Reproduce with `mix rampart.perf`; compare compatible reports with
`mix rampart.perf.compare before.json after.json`. The manually dispatched
Performance comparison workflow retains both revisions' measurements. Native
scanner interoperability, independent archive consumers, full Muex execution,
guided-search effectiveness, and full pinned application fixtures remain the
next validation milestone described in the review.
