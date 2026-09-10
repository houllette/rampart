# Evaluation lab

This directory contains trusted, repository-local fixtures and the composed
Rampart evaluation runner. It is not a publishable application and must not gain
production authority or agent reasoning.

See [`../EVALUATION.md`](../EVALUATION.md) for the contracts, metrics, safety
boundary, and corpus roadmap. The
[recent ecosystem CVE primitive review](HISTORICAL_CVE_FRONTIER.md) maps a
patch-informed advisory frontier to missing reusable static and validation
capabilities without proposing CVE-specific rules. Run `mix rampart.eval` from
the repository root.
Set `RAMPART_REQUIRE_DISTRIBUTED=1` only where local node sockets are available;
CI does so for both pinned runtime profiles. Compare retained reports with
`mix rampart.eval.compare REPORT REPORT`.
