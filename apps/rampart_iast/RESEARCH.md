# RampartIAST research status

## Implemented spike boundary

The experimental `iast.exact-marker-reaches-sink.v1` action establishes the
smallest useful runtime proof:

- one host-selected context provider;
- one versioned source declaration;
- one versioned sink declaration;
- one non-empty binary replay marker;
- one controlled execution process;
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

## Next gates

1. Build independently reviewed vulnerable, fixed, and ambiguous fixtures for
   at least three sink classes.
2. Add a structured Phoenix provider from versioned rule knowledge rather than
   report strings, then evaluate a separately publishable, version-pinned Reach
   adapter against it.
3. Measure disabled and targeted tracing overhead and reject broad
   configurations.
4. Run the dedicated cross-process feasibility experiments in the root
   `IAST_RESEARCH.md` without making their results load-bearing.
5. Add host-authorized artifact persistence before exposing full trace evidence
   through an external adapter.

The package remains experimental and must not be registered as an agent tool
until the repository-level trust gates pass.
