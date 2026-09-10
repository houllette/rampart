# Evaluation lab

This directory contains trusted, repository-local fixtures and the composed
Rampart evaluation runner. It is not a publishable application and must not gain
production authority or agent reasoning.

See [`../EVALUATION.md`](../EVALUATION.md) for the contracts, metrics, safety
boundary, and corpus roadmap. The
[recent ecosystem CVE primitive review](HISTORICAL_CVE_FRONTIER.md) maps a
patch-informed advisory frontier to missing reusable static and validation
capabilities without proposing CVE-specific rules. The
[additional CVE capability catalog](CVE_CAPABILITY_CATALOG.md) adds eight
advisories with [structured provenance and proposed contracts](CVE_CAPABILITY_CATALOG.json);
three entries now have reduced Havoc contract evaluations; the two Mint entries
also have exact complete-package vulnerable/fixed execution through
`mix rampart.upstream`. The
[resource-limit inventory](../RESOURCE_LIMITS.md) records current enforcement
boundaries and concrete local follow-ups.

Run `mix rampart.eval` from the repository root. Use `mix rampart.blind` for the
checked-in blind-evaluator calibration, `mix rampart.upstream` for exact Mint
revision pairs, and `mix rampart.sandbox` for the OS-isolation self-test. A true
blind discovery study must keep private cases outside this checkout.
Set `RAMPART_REQUIRE_DISTRIBUTED=1` only where local node sockets are available;
CI does so for both pinned runtime profiles. Compare retained reports with
`mix rampart.eval.compare REPORT REPORT`.
