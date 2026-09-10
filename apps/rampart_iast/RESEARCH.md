# RampartIAST research status

## Implemented spike boundary

The experimental `iast.exact-marker-reaches-sink.v1` action establishes the
smallest useful runtime proof:

- one host-selected context provider;
- one versioned source declaration;
- one versioned sink declaration;
- one non-empty binary replay marker, matched unchanged directly or within
  bounded list, tuple, and map arguments;
- one controlled execution process, with incompatible process scopes rejected
  before execution;
- one isolated OTP trace session;
- optional analyzer-independent static candidates with bounded source spans and
  reproducible provenance; and
- one exact-marker reachability verdict that static qualifications cannot
  override.

The trace collector records only sink identity, argument positions and sizes,
matched positions, timestamps, counts, and limit state. Native execution errors
and observations remain in `Core.Validation.Evidence.raw`, which
`Core.Validation.Wire` excludes from transcript projections.

## Not implemented

The action does not provide:

- derived-value propagation;
- child-process inheritance;
- send/receive, GenServer, Task, ETS, or process-dictionary provenance;
- source extraction from a framework request;
- exploitability or sanitizer-effect validation;
- a Phoenix/Sobelow context provider;
- a RampartSAST-to-IAST adapter for reviewed sink observations;
- a version-pinned Reach adapter that emits reviewed static candidates;
- artifact persistence for full path evidence; or
- production-safety guarantees.

A sink call in a descendant process is deliberately outside the observation
envelope. Equality between values in different processes must never be used to
invent a provenance edge.

The repository evaluation now has non-load-bearing feasibility evidence for
several boundaries. Explicit direct-message IDs and GenServer call aliases join
exactly. GenServer casts require an existing application request ID. The tested
`Task.async/3` protocol can join its work/result messages using the task
reference and spawn lineage. ETS additionally requires a unique key and an
ordered interval without overwrite or delete. Adversarial cases prove that
casts without IDs remain ambiguous, Task failure/timeout yields no value edge,
concurrent ETS overwrite needs a stored write version, delete terminates an edge,
and an injected missing event remains incomplete despite a delivery barrier. An
ordinary supervisor replacement terminates process-local state at the old PID.
A separate restart can restore an externally owned ETS record only with an
explicit key and write version; this does not imply PID continuity. A pressure
case joins 64 envelopes from 16 senders while 512 unrelated messages remain
queued, but 4,096 value-only pairings remain ambiguous. A two-node probe joins
four explicit distributed envelopes using separate node-local trace sessions and
barriers without comparing cross-node clocks. A targeted process-dictionary read
is not call-trace visible on the pinned runtime; tracing full dictionary
snapshots is intentionally rejected as overbroad. These results do not enable
cross-process validation in this package.

## Next gates

1. Expand the current real command, deserialization, filesystem, Plug response,
   ambiguous-localization, upstream-source historical, and OTP-refusal fixtures
   into full pinned package and application executions.
2. Add structured Phoenix/Ecto providers from versioned rule knowledge rather
   than report strings, then evaluate a separately publishable, version-pinned
   Reach adapter against them.
3. Replace the initial seven-sample disabled/targeted fixed-cost measurement with
   representative workloads, scheduler/memory metrics, and stable trend history.
4. Extend the bounded external-state, distributed-node, and mailbox-pressure
   frontier cases into sustained workloads and less cooperative topologies.
   Review the retained OTP 28/29 observations and repeat the adversarial cases at
   higher concurrency before considering any result load-bearing.
5. Add host-authorized artifact persistence before exposing full trace evidence
   through an external adapter.

The package remains experimental and must not be registered as an agent tool
until the repository-level trust gates pass.
