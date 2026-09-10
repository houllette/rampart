# Zero-day discovery readiness

## Question

> Would these tools, if steered by an LLM agent, have been able to identify **and**
> validate newly discovered vulnerabilities in open-source Erlang/Elixir
> libraries and applications for responsible disclosure?

## Current answer

**For bounded vulnerability classes with a reviewed executable fixture and an
independent oracle: plausibly yes, end to end. For open-ended autonomous
zero-day discovery across the Erlang/Elixir ecosystem: not yet demonstrated.**

Rampart now has the mechanical chain needed for a serious experiment:
checksummed source reconnaissance, bounded candidate slices, StreamData and
PropEr search, stateful host-owned harnesses, exact vulnerable/fixed replay,
three-way validation verdicts, an action-scoped external Lemieux adapter,
disposable OS isolation, and a scrubbed human-review disclosure draft. The
trust anchor remains deterministic validation, not an LLM's explanation.

The strongest positive repository evidence is still retrospective. The
upstream gate builds and executes complete public Mint revisions around
CVE-2026-82728 and CVE-2026-82729 and proves vulnerable/fixed separation with
the same input identity. The external adapter's opt-in `mix live.zai` gate
additionally proves that a real Z.AI-steered Lemieux session can invoke
`RampartSAST.Validator` and ground its answer in confirmed, refuted, and
inconclusive controls without receiving source bodies or validator authority.
A first prospective, answer-key-free Plug pilot completed with a correct
`NO_CREDIBLE_CANDIDATE` abstention and an isolated 689-test target baseline; it
produced no candidate to validate or disclose. Together these results show
that the primitives can survive a real model/tool loop and safely decline weak
hypotheses. They do **not** yet show successful prospective identification and
validation of a new defect.

## P0–P7 implementation status

| Priority | Implemented result | What it establishes | What it does not establish |
| --- | --- | --- | --- |
| **P0 — blind evaluation** | `evaluation/blind/run.py`, strict inert submission schema, public/private split, source hash, leak audit, fresh vulnerable/fixed/benign/failure executions, exact replay checks | An evaluator can score candidate localization plus confirmation/refutation without giving a submission callbacks, commands, options, or the answer key | The checked-in case is calibration. A credible discovery claim still requires evaluator-owned holdouts outside the participant checkout |
| **P1 — exact upstream execution** | `mix rampart.upstream` fetches pinned Mint commits, verifies Git trees and license, builds fresh consumers, and runs actual Mint HTTP1/parser paths | Full-package vulnerable/fixed evidence for the incremental response-line buffer and chunk-size numeric-work classes | Only two already-disclosed Mint cases; no broad package/application coverage and no prospective rediscovery result |
| **P2 — LLM adapter** | External sibling `rampart_lemieux` binds one `Core.Validation.Binding` per Lemieux descriptor, exposes inert IDs only, preserves three verdicts, bounds the complete result, requires host rebind on resume, and provides an opt-in real Z.AI/SAST three-verdict gate | A live LLM can invoke a narrow current capability and ground its final answer without receiving scope, source, resolver, callbacks, validator options, replay values, or artifact authority | The adapter is a companion checkout, not a Rampart dependency or a published integration package; only explicit calibration routing has been evaluated, not open-ended candidate selection or research strategy |
| **P3 — SAST hypothesis support** | `RampartSAST.DataFlow.backward/3` plus Elixir/Erlang parameter, guard, binding, return, and call-argument facts | Bounded, ambiguity-preserving syntax dependence can reduce a sink candidate to possible lexical/interprocedural contributors | It is not SSA, branch feasibility, sanitizer modeling, runtime reachability, taint, or exploitability |
| **P4 — stateful validation harness** | `Havoc.Harness.Plan`, `Binding`, and executor implement finite setup/control/candidate/cleanup/observation sequences with payload references, replay identity, teardown, deadlines between callbacks, and observation limits | StreamData can search reviewed protocol/state machines while executable authority stays host-owned; fixture/budget failure is inconclusive | It cannot preempt a stuck callback or provide OS isolation; the host must supply correct independent controls and cleanup |
| **P5 — isolation** | `evaluation/isolation/run.py` copies admitted source, scrubs identity, denies network and outside filesystem access, admits only concrete runtime prefixes needed by relocatable Python, applies available OS/POSIX limits, bounds output, kills the process group, and emits a hashed report | Reviewed target execution can be separated from acquisition and run networkless in a disposable workspace | macOS cannot advertise address-space/process-count limits; Mix's TCP filesystem lock requires a reviewed direct runtime test entry point under complete network denial; per-file size is not a disk quota; hostile native code still requires platform hardening and human review |
| **P6 — search feedback** | HavocProper accepts bounded stable feature IDs, archives line- or feature-novel candidates, emits deterministic configuration/BEAM manifests, and the integration search uses explicit depth transitions | PropEr search can use protocol/state progress rather than line coverage alone without replacing PropEr with a custom loop | PropEr's public API still lacks a portable initial RNG seed; exact generated inputs must be retained because the stochastic trajectory is not replayable from the manifest alone |
| **P7 — disclosure handoff** | External `RampartLemieux.Disclosure.Bundle` accepts confirmed evidence, optional same-action fixed refutation, exact source/runtime identity, scrubbed text artifacts, resealed redacted proof digests, and creates a local draft atomically | Validated evidence can become a structured responsible-disclosure draft without native `raw` terms or concrete seed values; both source-projection and disclosure-projection identities remain explicit | Secret scrubbing is a backstop, and nothing is sent automatically. A human must replay, assess impact/versions, inspect redactions, identify maintainers, and choose timing |

## Identification versus validation

The two halves of the question need different evidence.

### Identification

Rampart can now provide an agent with:

1. exact package/dependency/source ownership;
2. calls, argument shapes, assignments, returns, parameters, guards, effects, and
   package-specific syntax facts;
3. bounded backward slices that preserve multiple definitions and callers;
4. durable candidate and corpus identities;
5. ordinary StreamData generation/shrinking; and
6. opt-in coverage plus host-defined semantic-state feedback.

This is enough to form and search concrete hypotheses in classes such as parser
budgets, canonicalization, authorization topology, cache partitioning,
state-machine effects, terminal safety, and explicit resource units. It is not
evidence that the agent will choose good hypotheses across unfamiliar code. The
current static layer deliberately reports uncertainty rather than inventing
reachability, attacker control, sanitizer semantics, or exploitability.

### Validation

For a candidate with an independently specified claim, Rampart can:

1. bind the exact source revision, subject, fixture, scope, oracle, and limits on
   the host;
2. replay one concrete seed without generation;
3. require positive, negative, exact-boundary, benign-neighbor, fixed, and
   injected-failure controls as appropriate;
4. return `confirmed`, `refuted`, or `inconclusive` without converting missing
   evidence or harness failure into a finding;
5. retain source/runtime/action/result/seed/proof identities; and
6. independently replay the retained counterexample.

That is a meaningful validation capability. It confirms only the declared
security invariant in that fixture. Severity, affected-version range, remote
preconditions, exploit reliability, and disclosure language still need separate
technical and human review.

## Evidence you can run

```sh
# Ordinary deterministic corpus, SAST, docs, and package tests.
mix precommit

# Calibration of the blind evaluator. This is not a true hidden holdout.
mix rampart.blind

# Exact complete upstream Mint revision pairs; network needed for acquisition.
mix rampart.upstream

# OS backend self-test. Some development sandboxes cannot nest sandbox-exec.
mix rampart.sandbox

# Fresh package consumers, contracts, applications, native tools, search, and resources.
mix rampart.integration

# Companion adapter/disclosure package, kept outside the Rampart umbrella.
(cd ../rampart_lemieux && mix precommit)

# Opt-in paid-provider calibration: real Z.AI → Lemieux → Rampart SAST loop.
# Requires ZAI_API_KEY in the environment and writes only gitignored local evidence.
(cd ../rampart_lemieux && RAMPART_LEMIEUX_APPROVE_LIVE=1 mix live.zai)
```

Acquisition and execution should remain separate: fetch and verify pinned source
under an authorized network policy, then execute the copied snapshot with
network denied. On macOS, Mix's local TCP filesystem lock is also blocked by
that policy; use a reviewed direct runtime/ExUnit entry point in the execution
snapshot rather than silently allowing local networking. Do not give a model a
shell command, module name, callback, scope object, oracle list, corpus path,
sandbox profile, or artifact resolver.

## What would change the answer to an unqualified “yes”

A defensible prospective claim needs all of the following:

1. **Externally owned blind cases.** Answer keys, fixed controls, and private
   literals must never enter the participant checkout or model context.
2. **Time-sliced package studies.** Give the system only source and ecosystem
   information available before a public fix/advisory, then score the sealed
   prediction against later-disclosed truth.
3. **More complete applications and classes.** Include Phoenix/LiveView,
   Ecto/Ash, OTP/inets/SSH, Rebar projects, macros, protocols/callbacks, native
   boundaries, lifecycle cleanup, and authorization state machines.
4. **Independent controls.** Every confirmation must survive benign neighbors,
   positive fixture controls, a fixed revision, injected harness failures, and
   independent exact replay.
5. **Measured agent performance.** Report candidate recall, false confirmation,
   abstention/inconclusive rate, time/cost, evidence bytes, attempts, and
   successful replay—not persuasive narratives.
6. **Hardened execution on the deployment platform.** Add cgroup/job-object
   memory/process controls, quota-backed disk, syscall policy, no identity,
   network denial, and audited acquisition/build separation.
7. **Human disclosure governance.** Confirm maintainer routing, version scope,
   impact, embargo/timing, data minimization, and artifact safety before contact.

The deterministic, isolated machinery and the real agent/tool loop are now
ready for **controlled prospective pilot attempts**. Start with one pinned,
reviewed public target at a time, acquisition separated from networkless
execution, explicit resource budgets, no maintainer contact, and a predeclared
confirmation matrix. This is readiness to begin measuring—not evidence that the
measurements will succeed and not approval for unattended ecosystem-wide runs.

Until the broader program succeeds, the accurate statement is:

> Rampart now contains credible primitives for an LLM-directed vulnerability
> research workflow and can deterministically validate selected real defect
> classes. The repository has not yet proved reliable autonomous discovery of
> new zero-days across open-source Erlang/Elixir software.
