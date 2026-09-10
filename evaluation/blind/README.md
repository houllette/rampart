# Blind vulnerability-discovery evaluation

This gate separates **candidate identification** from deterministic validation.
A participant or agent receives only a `public/` directory containing a pre-fix
source snapshot, objective, allowed action/contract IDs, and budgets. It returns
an inert JSON submission. The evaluator separately supplies an answer key,
reviewed driver, vulnerable snapshot, fixed snapshot, benign near-neighbours,
and injected harness failures.

```sh
mix rampart.blind

# A real held-out challenge uses evaluator-owned paths that are not present in
# the participant checkout:
mix rampart.blind --public /participant/challenge \
  --submission /participant/submission.json \
  --answer-key /evaluator/private/answer-key.json \
  --output tmp/held-out-report.json
```

The runner rejects unknown submission fields and never accepts commands,
modules, callbacks, scope, artifact authority, or validator options from the
submission. The private key binds those values. Every variant runs in a fresh
process. Passing requires the reviewed hypothesis class and locus, confirmation
on the pre-fix source, refutation on the fixed source, no confirmation on benign
or failed controls, and an identical replay shape.

`calibration/` is deliberately checked in so CI can test the protocol. Its
answer key is therefore **not blind evidence** and `calibration_only` remains
true in the report. Defensible recall/precision claims require evaluator-owned
holdouts whose private trees, advisory IDs, patches, bad inputs, and expected
oracles are never mounted in the agent workspace. Reports retain snapshot,
submission, result, and driver-log hashes without exposing private source.

A challenge submission has this exact shape:

```json
{
  "schema_version": 1,
  "challenge_id": "...",
  "hypothesis": {
    "class": "...",
    "statement": "...",
    "locus": ["source/file.ex:line"]
  },
  "validation": {
    "action_id": "havoc.security-property-reproduces.v1",
    "contract_id": "host.reviewed-contract.v1",
    "seed": {},
    "replay_nonce": "..."
  }
}
```

The benchmark is intentionally an evaluation protocol, not a reasoning engine
or a new Rampart package. Lemieux or another harness may produce the submission;
only deterministic host-bound Rampart actions decide the security verdict.
