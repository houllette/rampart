#!/usr/bin/env python3
"""Run deterministic Rampart contracts against complete pinned upstream packages."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv, cwd, log, timeout=600, env=None):
    process_env = os.environ.copy()
    for key in ("MIX_BUILD_PATH", "MIX_DEPS_PATH", "MIX_APP_PATH", "ERL_LIBS"):
        process_env.pop(key, None)
    process_env.update({"MIX_ENV": "test", "HEX_OFFLINE": "false"})
    process_env.update(env or {})
    started = time.monotonic()
    with log.open("wb") as output:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=process_env,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            status = process.wait(timeout=timeout)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise
    if status:
        tail = log.read_text(errors="replace")[-8000:]
        raise RuntimeError(f"{argv!r} failed ({status}); {log}\n{tail}")
    return round(time.monotonic() - started, 3)


def git_output(checkout, arguments):
    return subprocess.check_output(["git", "-C", str(checkout), *arguments], text=True).strip()


def checkout_revision(repository, revision, expected_tree, destination, log):
    destination.mkdir()
    command(["git", "init", "-q"], destination, log.with_name(log.stem + "-init.log"), timeout=30)
    command(["git", "remote", "add", "origin", repository], destination, log.with_name(log.stem + "-remote.log"), timeout=30)
    command(["git", "fetch", "--quiet", "--depth=1", "origin", revision], destination, log, timeout=180)
    command(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], destination, log.with_name(log.stem + "-checkout.log"), timeout=30)
    actual_revision = git_output(destination, ["rev-parse", "HEAD"])
    actual_tree = git_output(destination, ["rev-parse", "HEAD^{tree}"])
    if actual_revision != revision or actual_tree != expected_tree:
        raise RuntimeError(
            f"upstream identity mismatch for {revision}: revision={actual_revision}, tree={actual_tree}"
        )
    if not (destination / "LICENSE.txt").is_file():
        raise RuntimeError("reviewed Mint Apache license file is missing")
    return {"revision": actual_revision, "tree": actual_tree, "license_sha256": sha256(destination / "LICENSE.txt")}


def mix_project(project, checkout):
    project.mkdir()
    deps = [
        f'{{:security_core, path: "{ROOT / "apps" / "security_core"}", override: true}}',
        f'{{:havoc, path: "{ROOT / "apps" / "havoc"}", override: true}}',
        f'{{:mint, path: "{checkout}", override: true}}',
    ]
    (project / "mix.exs").write_text(
        """defmodule UpstreamConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :upstream_consumer, version: \"0.0.0\", deps: [%s]]
  def application, do: [extra_applications: [:logger, :crypto]]
end
""" % ", ".join(deps)
    )
    shutil.copyfile(ROOT / "mix.lock", project / "mix.lock")


def run_case(project, case, role, revision, artifacts, logs):
    result_path = artifacts / f"{case['id']}-{role}.json"
    elapsed = command(
        ["mix", "run", str(HERE / "check.exs")],
        project,
        logs / f"{case['id']}-{role}.log",
        timeout=120,
        env={
            "RAMPART_UPSTREAM_MODE": case["mode"],
            "RAMPART_UPSTREAM_ROLE": role,
            "RAMPART_UPSTREAM_CONTRACT": case["contract_id"],
            "RAMPART_UPSTREAM_REVISION": revision,
            "RAMPART_UPSTREAM_OUTPUT": str(result_path),
        },
    )
    result = json.loads(result_path.read_text())
    verdict = result["result"]["verdict"]
    expected = "confirmed" if role == "vulnerable" else "refuted"
    if verdict != expected:
        raise RuntimeError(f"{case['id']} {role} returned {verdict}, expected {expected}")
    return {
        "case_id": case["id"],
        "advisory": case["advisory"],
        "contract_id": case["contract_id"],
        "mode": case["mode"],
        "role": role,
        "revision": revision,
        "verdict": verdict,
        "elapsed_seconds": elapsed,
        "result_sha256": sha256(result_path),
        "input_seed_id": result["input_seed_id"],
        "input_fingerprint": result["input_fingerprint"],
        "proof_seed_id": result["result"]["seed"]["id"],
        "finding_ids": [finding["id"] for finding in result["result"]["findings"]],
        "loaded_beam": result["loaded_beam"],
        "loaded_beam_sha256": result["loaded_beam_sha256"],
        "package_version": result["package_version"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "tmp" / "rampart-upstream.json")
    parser.add_argument("--keep-workspace", action="store_true")
    args = parser.parse_args()

    catalog = json.loads((HERE / "cases.json").read_text())
    if catalog["schema_version"] != 1 or not catalog["cases"]:
        raise RuntimeError("upstream catalog must contain versioned cases")

    work = Path(tempfile.mkdtemp(prefix="rampart-upstream-"))
    logs = work / "logs"
    artifacts = work / "artifacts"
    logs.mkdir()
    artifacts.mkdir()
    identities = {}
    projects = {}
    results = []
    tracked = subprocess.check_output(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")
    source_hashes = {
        name: sha256(ROOT / name)
        for name in sorted(set(tracked))
        if name
        and (ROOT / name).is_file()
        and (
            name.startswith(("apps/security_core/", "apps/havoc/", "evaluation/upstream/"))
            or name in ("mix.exs", "mix.lock")
        )
    }
    report = {
        "schema_version": 1,
        "status": "incomplete",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "repository": catalog["repository"],
        "package": catalog["package"],
        "license": catalog["license"],
        "catalog_sha256": sha256(HERE / "cases.json"),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_snapshot_sha256": hashlib.sha256(
            json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }

    try:
        revisions = {}
        for case in catalog["cases"]:
            revisions[case["vulnerable_revision"]] = case["vulnerable_tree"]
            revisions[case["fixed_revision"]] = case["fixed_tree"]

        for index, (revision, tree) in enumerate(sorted(revisions.items()), 1):
            checkout = work / f"source-{index}"
            identities[revision] = checkout_revision(
                catalog["repository"], revision, tree, checkout, logs / f"fetch-{index}.log"
            )
            project = work / f"consumer-{index}"
            mix_project(project, checkout)
            command(["mix", "deps.get"], project, logs / f"deps-{index}.log", timeout=300)
            command(["mix", "compile", "--warnings-as-errors"], project, logs / f"compile-{index}.log", timeout=300)
            projects[revision] = project

        for case in catalog["cases"]:
            results.append(
                run_case(
                    projects[case["vulnerable_revision"]],
                    case,
                    "vulnerable",
                    case["vulnerable_revision"],
                    artifacts,
                    logs,
                )
            )
            results.append(
                run_case(
                    projects[case["fixed_revision"]],
                    case,
                    "fixed",
                    case["fixed_revision"],
                    artifacts,
                    logs,
                )
            )

        for case in catalog["cases"]:
            pair = [row for row in results if row["case_id"] == case["id"]]
            if [row["verdict"] for row in pair] != ["confirmed", "refuted"]:
                raise RuntimeError(f"case pair did not distinguish revisions: {case['id']}")
            if pair[0]["input_seed_id"] != pair[1]["input_seed_id"] or pair[0]["input_fingerprint"] != pair[1]["input_fingerprint"]:
                raise RuntimeError(f"case pair did not execute the same input seed: {case['id']}")

        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        retained = args.output.resolve().with_suffix(".artifacts")
        if retained.exists():
            shutil.rmtree(retained)
        retained.mkdir(parents=True)
        if logs.exists():
            shutil.copytree(logs, retained / "logs")
        if artifacts.exists():
            shutil.copytree(artifacts, retained / "proofs")
        report.update(
            {
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "source_identities": identities,
                "results": results,
                "artifacts": {
                    path.relative_to(retained).as_posix(): sha256(path)
                    for path in sorted(retained.rglob("*"))
                    if path.is_file()
                },
                "artifact_directory": str(retained),
            }
        )
        if report["status"] == "passed" and not args.keep_workspace:
            shutil.rmtree(work)
            report["workspace_retained"] = False
        else:
            report["workspace_retained"] = True
            report["workspace"] = str(work)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Upstream package gate: {report['status']} ({len(results)} revision results)")
        print(f"Report: {args.output}")


if __name__ == "__main__":
    main()
