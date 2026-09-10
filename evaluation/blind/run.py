#!/usr/bin/env python3
"""Evaluate an inert Rampart blind-challenge submission with a private host key.

The participant receives only the public challenge tree.  This runner belongs to
an evaluator host: it verifies the public snapshot, validates the model's inert
submission, binds a reviewed driver from the private key, executes vulnerable,
fixed, and near-neighbour controls in fresh processes, and scores replay.  It
never accepts a command, module, scope, or validator callback from the
submission.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
MAX_SUBMISSION_BYTES = 64 * 1024
MAX_DRIVER_OUTPUT_BYTES = 256 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path):
    return sha256_bytes(path.read_bytes())


def source_snapshot(source_root):
    rows = {}
    for path in sorted(source_root.rglob("*")):
        if path.is_file():
            rows[path.relative_to(source_root).as_posix()] = sha256_file(path)
    return sha256_bytes(canonical(rows)), rows


def load_json(path, maximum=None):
    size = path.stat().st_size
    if maximum is not None and size > maximum:
        raise ValueError(f"{path} exceeds {maximum} bytes")
    return json.loads(path.read_text())


def require_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f"{label} must contain exactly {sorted(expected)}")


def nonempty(value, label, maximum=4096):
    if not isinstance(value, str) or not value.strip() or len(value.encode()) > maximum:
        raise ValueError(f"{label} must be a non-empty bounded string")
    return value


def validate_submission(submission, public):
    require_keys(submission, ["schema_version", "challenge_id", "hypothesis", "validation"], "submission")
    if submission["schema_version"] != 1 or submission["challenge_id"] != public["challenge_id"]:
        raise ValueError("submission schema/challenge identity mismatch")

    hypothesis = submission["hypothesis"]
    require_keys(hypothesis, ["class", "statement", "locus"], "hypothesis")
    nonempty(hypothesis["class"], "hypothesis.class", 160)
    nonempty(hypothesis["statement"], "hypothesis.statement", 4096)
    if not isinstance(hypothesis["locus"], list) or not hypothesis["locus"]:
        raise ValueError("hypothesis.locus must be a non-empty list")
    for locus in hypothesis["locus"]:
        nonempty(locus, "hypothesis locus", 1024)

    validation = submission["validation"]
    require_keys(validation, ["action_id", "contract_id", "seed", "replay_nonce"], "validation")
    if validation["action_id"] not in public["allowed_action_ids"]:
        raise ValueError("validation action is not enabled for this challenge")
    if validation["contract_id"] not in public["allowed_contract_ids"]:
        raise ValueError("validation contract is not enabled for this challenge")
    if not isinstance(validation["seed"], dict):
        raise ValueError("validation.seed must be inert JSON object data")
    if len(canonical(validation["seed"])) > public["budgets"]["max_seed_bytes"]:
        raise ValueError("validation seed exceeds the public byte budget")
    nonempty(validation["replay_nonce"], "validation.replay_nonce", 160)
    return submission


def leak_audit(public_root, answer_key):
    public_bytes = []
    for path in sorted(public_root.rglob("*")):
        if path.is_file():
            public_bytes.append(path.read_bytes().lower())
    joined = b"\n".join(public_bytes)
    leaked = []
    for literal in answer_key.get("forbidden_public_literals", []):
        encoded = literal.encode().lower()
        if encoded and encoded in joined:
            leaked.append(literal)
    return leaked


def run_driver(driver, source, submission_path, output_path, timeout_ms):
    command = ["mix", "run", str(driver), str(source), str(submission_path), str(output_path)]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout_ms / 1000,
        check=False,
    )
    elapsed_ms = round((time.monotonic() - started) * 1000, 3)
    log = completed.stdout[-64 * 1024 :].decode(errors="replace")
    if completed.returncode != 0:
        raise RuntimeError(f"private driver failed ({completed.returncode}):\n{log}")
    if not output_path.exists() or output_path.stat().st_size > MAX_DRIVER_OUTPUT_BYTES:
        raise RuntimeError("private driver did not produce a bounded result")
    result = load_json(output_path, MAX_DRIVER_OUTPUT_BYTES)
    return result, elapsed_ms, sha256_bytes(completed.stdout)


def replay_shape(result):
    return {
        "action_id": result.get("action", {}).get("id"),
        "verdict": result.get("verdict"),
        "seed_id": result.get("seed", {}).get("id"),
        "finding_ids": sorted(row.get("id") for row in result.get("findings", [])),
        "facts": result.get("evidence", {}).get("facts"),
    }


def check(name, passed, details=None):
    row = {"name": name, "passed": bool(passed)}
    if details is not None:
        row["details"] = details
    return row


def evaluate(public_root, submission_path, answer_key_path):
    public_path = public_root / "challenge.json"
    source_root = public_root / "source"
    public = load_json(public_path)
    answer_key = load_json(answer_key_path)
    submission = validate_submission(load_json(submission_path, MAX_SUBMISSION_BYTES), public)

    require_keys(
        public,
        [
            "schema_version",
            "challenge_id",
            "title",
            "objective",
            "source_snapshot_sha256",
            "allowed_action_ids",
            "allowed_contract_ids",
            "budgets",
        ],
        "public challenge",
    )
    require_keys(
        answer_key,
        [
            "schema_version",
            "challenge_id",
            "calibration_only",
            "expected_hypothesis_classes",
            "expected_locus_fragments",
            "driver",
            "variants",
            "forbidden_public_literals",
        ],
        "private answer key",
    )
    if public["schema_version"] != 1 or answer_key["schema_version"] != 1:
        raise ValueError("unsupported blind challenge schema")
    if public["challenge_id"] != answer_key["challenge_id"]:
        raise ValueError("public/private challenge identity mismatch")

    snapshot, source_hashes = source_snapshot(source_root)
    leaked = leak_audit(public_root, answer_key)
    private_root = answer_key_path.parent
    driver = (private_root / answer_key["driver"]).resolve()
    if not driver.is_file() or private_root.resolve() not in driver.parents:
        raise ValueError("private driver must be a file below the private key root")

    checks = [
        check("public source snapshot is exact", snapshot == public["source_snapshot_sha256"]),
        check("private labels do not occur in participant bundle", leaked == [], leaked),
        check(
            "hypothesis class identifies the reviewed boundary",
            submission["hypothesis"]["class"] in answer_key["expected_hypothesis_classes"],
        ),
        check(
            "hypothesis localizes reviewed source",
            all(
                any(fragment in locus for locus in submission["hypothesis"]["locus"])
                for fragment in answer_key["expected_locus_fragments"]
            ),
        ),
    ]

    outcomes = []
    with tempfile.TemporaryDirectory(prefix="rampart-blind-") as work:
        work = Path(work)
        normalized_submission = work / "submission.json"
        normalized_submission.write_bytes(canonical(submission))

        for variant in answer_key["variants"]:
            require_keys(variant, ["id", "source", "expected_verdict", "role"], "answer variant")
            source = (private_root / variant["source"]).resolve()
            if not source.is_file():
                raise ValueError(f"missing private source variant {variant['id']}")
            output = work / f"{variant['id']}.json"
            result, elapsed_ms, log_sha256 = run_driver(
                driver,
                source,
                normalized_submission,
                output,
                public["budgets"]["max_validation_ms"],
            )
            outcomes.append(
                {
                    "id": variant["id"],
                    "role": variant["role"],
                    "expected_verdict": variant["expected_verdict"],
                    "verdict": result.get("verdict"),
                    "elapsed_ms": elapsed_ms,
                    "result_sha256": sha256_file(output),
                    "driver_log_sha256": log_sha256,
                    "replay_shape": replay_shape(result),
                }
            )

        vulnerable = next(row for row in outcomes if row["role"] == "vulnerable")
        replay_output = work / "vulnerable-replay.json"
        vulnerable_source = next(row for row in answer_key["variants"] if row["role"] == "vulnerable")
        replay_result, replay_ms, replay_log_sha256 = run_driver(
            driver,
            (private_root / vulnerable_source["source"]).resolve(),
            normalized_submission,
            replay_output,
            public["budgets"]["max_validation_ms"],
        )
        replay = {
            "elapsed_ms": replay_ms,
            "result_sha256": sha256_file(replay_output),
            "driver_log_sha256": replay_log_sha256,
            "shape": replay_shape(replay_result),
            "matched": replay_shape(replay_result) == vulnerable["replay_shape"],
        }

    for outcome in outcomes:
        checks.append(
            check(
                f"{outcome['role']} control has the required verdict",
                outcome["verdict"] == outcome["expected_verdict"],
                {"variant": outcome["id"], "actual": outcome["verdict"]},
            )
        )
    checks.append(check("vulnerable proof replays exactly", replay["matched"]))

    false_confirmations = sum(
        1 for row in outcomes if row["role"] != "vulnerable" and row["verdict"] == "confirmed"
    )
    checks.append(check("fixed and near-neighbour controls never confirm", false_confirmations == 0))

    passed = all(row["passed"] for row in checks)
    return {
        "schema_version": 1,
        "status": "passed" if passed else "failed",
        "challenge_id": public["challenge_id"],
        "calibration_only": answer_key["calibration_only"],
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "public_snapshot_sha256": snapshot,
        "public_source_hashes": source_hashes,
        "submission_sha256": sha256_file(submission_path),
        "checks": checks,
        "outcomes": outcomes,
        "replay": replay,
        "metrics": {
            "checks_passed": sum(1 for row in checks if row["passed"]),
            "checks_total": len(checks),
            "false_confirmations": false_confirmations,
            "candidate_identified": checks[2]["passed"] and checks[3]["passed"],
            "vulnerable_confirmed": vulnerable["verdict"] == "confirmed",
            "fixed_refuted": any(
                row["role"] == "fixed" and row["verdict"] == "refuted" for row in outcomes
            ),
            "exact_replay": replay["matched"],
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--answer-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "tmp" / "rampart-blind.json")
    args = parser.parse_args()

    report = evaluate(args.public.resolve(), args.submission.resolve(), args.answer_key.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Blind challenge {report['challenge_id']}: {report['status']} "
        f"({report['metrics']['checks_passed']}/{report['metrics']['checks_total']} checks)"
    )
    print(f"Report: {args.output}")
    if report["status"] != "passed":
        sys.exit(1)


if __name__ == "__main__":
    main()
