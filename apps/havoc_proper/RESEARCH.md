# Coverage-guided research notes

The adapter was validated against PropEr 1.5.0, PropCheck 1.5.0, and OTP Cover.

## Why PropEr targeted PBT

PropEr already implements targeted generators and simulated-annealing /
hill-climbing search. Its `proper_target.update_uv/2` feedback is exactly the
seam needed to report a numeric coverage fitness. Reimplementing an AFL-style
mutation scheduler inside Havoc would duplicate search machinery and violate
Havoc's backend boundaries.

HavocProper constructs the same `proper:exists` form used by PropCheck's
`forall_targeted` macro and asks PropCheck for a long-result counterexample.
The candidate is then evaluated again by Havoc so normal oracle failure,
finding, telemetry, and corpus semantics remain centralized.

## Coverage model

OTP Cover reports module-global executable-line coverage. Before each candidate,
HavocProper resets only the configured modules; after the target returns it
counts the distinct executed `{module, line}` identities. That count is the
base fitness. Inputs that add previously unseen lines to the session are stored
as bounded generated seeds, even when they do not violate an oracle.

This is a useful hill-climbing signal, not full greybox edge coverage. Cover does
not expose per-PID data or every branch edge, and maximizing line count can miss
equal-length alternate paths. A caller can add a numeric branch-distance signal
with `:fitness_bonus`.

## PropEr binary compatibility finding

During the spike, PropEr 1.5.0's default targeted neighbourhood for a fixed-size
binary raised on OTP 29 after passing an internal `$used` wrapper to
`binary_to_list/1`. `HavocProper.Gen.binary/1` and `injection/2` install an
explicit user neighbourhood and do not exercise that path. Arbitrary third-party
PropEr binary generators may still hit the upstream issue.

## Isolation decision

Running each candidate in a fresh peer VM would provide clean process isolation
and uncontaminated coverage, but would make in-process ExUnit fixtures, database
sandboxes, and application state inaccessible. This first adapter uses a
serialized local Cover session and documents `async: false`. A peer-node backend
can be added later as a distinct isolation mode.
