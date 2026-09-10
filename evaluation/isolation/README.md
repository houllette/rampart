# Disposable OS isolation

`run.py` is host-owned evaluation infrastructure for executing a reviewed command
against a copied source tree. It is deliberately **not** `Core.Runner`, a generic
agent shell, or a substitute for reviewing the target and harness.

It establishes the following boundaries when the selected backend reports them:

- a fresh copied workspace with symlinks and oversized source trees rejected;
- an allowlisted environment with fresh HOME, Mix, Hex, and temporary paths;
- filesystem and network denial through macOS `sandbox-exec`, or mount/user/network
  namespaces through Linux bubblewrap (`bwrap`);
- wall-clock and CPU limits, per-file output limits, descriptor limits, bounded
  captured output, and process-group cleanup;
- address-space and process-count limits on the Linux backend; and
- source, output, backend, capability, command, and limit evidence in a JSON report.

The command array is supplied by the evaluator. An LLM-facing descriptor must
never be allowed to choose it, add arguments, alter the sandbox profile, or pass
environment values.

## Validation

```sh
# macOS sandbox-exec cannot be nested inside some development sandboxes. Run
# this from a host context that is allowed to establish an OS sandbox.
python3 evaluation/isolation/run.py --self-test

# Run a reviewed command against a source snapshot. Network remains denied.
python3 evaluation/isolation/run.py \
  --source /path/to/reviewed/source \
  --output tmp/rampart-sandbox.json \
  --wall-seconds 60 \
  --cpu-seconds 30 \
  -- /absolute/path/to/reviewed-program fixed argument
```

The self-test requires explicit permission-denied errors for an out-of-workspace
secret and a network connection, verifies an in-workspace write, rejects any
`TOKEN`/`KEY` environment names, and separately proves the wall-time and bounded-
output failure paths. `--require CAPABILITY` adds a fail-closed
capability requirement. The defaults require a filesystem boundary and network
denial.

## Honest limitations

- `sandbox-exec` is deprecated by Apple. The macOS backend cannot enforce or
  truthfully advertise address-space or per-user process-count limits. Linux
  bubblewrap is required for those two capabilities.
- `RLIMIT_FSIZE` limits each file, not total disk use. The copied workspace also
  has admission limits, but a production executor should add a quota-backed
  filesystem/cgroup boundary.
- POSIX CPU limits are per process and RSS is not measured here. Wall timeout and
  process-group cleanup are independent backstops, not a proof against every
  kernel or child-process failure mode.
- Runtime system paths are readable on macOS so reviewed interpreters and the
  BEAM can start. The disposable workspace is writable; other data paths and
  network operations are denied.
- This utility does not install dependencies, grant registry credentials, or
  fetch source. Acquisition and build should be separate, pinned, reviewed
  phases; execute the resulting snapshot with network denied.
- A passing report establishes the tested containment controls for one run. It
  does not establish that untrusted native code is harmless or that a candidate
  is a vulnerability.
