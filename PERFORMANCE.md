# Performance validation — 2026-09-09

The review fixes improve repeated graph traversal, seed provenance lookup, and
corpus import while enforcing previously incomplete resource boundaries. The
architecture remains deterministic and independent of an LLM. This comparison
describes the first implementation pass. The external integration follow-up
below records the subsequent package, native, search and resource validation.

For current limit units, enforcement points and source-review follow-ups, see
[RESOURCE_LIMITS.md](RESOURCE_LIMITS.md). That inventory adds no measurements
and does not expand the operating profile demonstrated here.

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
guided-search comparison and complete original application fixtures are now
covered by the external gate below.

## External execution and resource follow-up

The [final integration report](evaluation/baselines/2026-09-09/integration.json)
retains the passing archive-based run, fixture/package hashes, raw measurements
and proof/log checksums. It ran on the same local Elixir 1.20.4/OTP 29 ARM64
runtime with ten schedulers. `mix rampart.integration` reproduces the workload;
these timings are observations, not cross-platform CI thresholds.

The real ffuf fixture issued twenty requests across two concurrent jobs under
an aggregate ten-request/second configuration. First-to-last elapsed time was
1,799 ms; the largest sliding one-second window contained twelve requests,
within the explicit two-request burst tolerance. Consumer cancellation reaped
native children in 810 ms; validator cancellation and temporary audit/wordlist
cleanup took 133 ms. All nineteen observed child processes were gone afterward.
ffuf's own job deadline can leave an in-flight request pending; host deadlines
and cancellation remain distinct from a completed probe's inconclusive result.

Seven paired 200-step trials on the same four-character domain produced an
independently confirmed/replayed counterexample in 2/7 guided trials and 1/7
unguided trials. Median covered lines were seven versus five, and median search
latency was 15.454 ms versus 9.488 ms. Both arms collected line coverage. This
small sample supports no general success-rate claim; a larger, varied corpus is
needed before preferring guided search by default. PropEr does not expose a
public initial RNG seed in the locked version, so the exact generated input
sequences and successful corpora are retained for inspection and replay.

The resource suite measures disabled and targeted sensing at concurrency 1/2/4
on compute, binary, container and actual temporary-file IO workloads. Each case
uses two warmups and seven timed batches; the report retains latency samples,
node reductions/GC, scheduler activity and sampled VM/mailbox peaks. Twenty
caller-death trials and an event flood completed with verified teardown.
Targeted batch medians ranged from 7.186–7.526 ms at concurrency one and
26.253–28.323 ms at concurrency four, including session setup and teardown.
The largest sampled VM memory and mailbox observations across these cases
were 50.6 MiB and sixteen messages respectively; these are node-wide metrics.

The isolated static workload parsed fifty Elixir files plus one Erlang file,
producing 15,054 facts and 5,001 calls in 1,254 ms, then exercised bounded query
pagination. It used an explicit 32,000,000-word per-worker heap profile and a
5,000,000-term wire limit. A 1,024-word heap profile correctly returned incomplete
with no facts. Defaults were not raised to accommodate this fixture.

Process-tree RSS peaked at a sampled 562.4 MiB over the complete resource suite,
including Mix startup and disposable workers. Summing child RSS can double-count
shared pages and samples can miss short peaks. These measurements establish a
tested operating profile, not a hard VM memory ceiling or production IAST safety.
