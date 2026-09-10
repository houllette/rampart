# Resource-contract evaluation

`resource-contracts.json` is an unmodified report from:

```sh
mix rampart.eval --output evaluation/baselines/2026-09-10/resource-contracts.json
```

All 17 cases passed 421 checks, with zero false confirmations in the declared
controls and 17 successful replay checks. The report records the actual local
runtime, including OTP/ERTS and Elixir patch versions. It does not represent an
execution of both CI runtime profiles.

The three new historical cases exercise original reduced length, incremental
buffer, and numeric-work models. No upstream Ash/Mint package pair was executed.
Exact inputs, configured oracle budgets, and valid/boundary/rejection controls
are in `evaluation/corpus.exs`; each case also fingerprints its fixture source.
Replay checks compare verdicts, seed identities, and confirmed finding identity
and evidence text.

`resource-contracts.sources.json` separately fingerprints the report and 250
library/configuration/evaluation source files. `base_commit` identifies the
starting commit; the source hashes identify the actual modified worktree used
for this run. The source-snapshot digest hashes the path-to-SHA-256 map as
sorted-key JSON with comma/colon separators and no whitespace. The manifest is
separate so the evaluator's original report bytes remain intact.

The implementation also passed `mix precommit` (317 tests/properties) and all
eight isolated package consumers (30 checks), including Havoc's 10 package,
resource-budget, generator and durable replay checks. Those transient logs are
under `tmp/resource-contracts-*`; they are not part of this retained report.
