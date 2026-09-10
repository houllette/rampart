#!/usr/bin/env python3
"""Exercise built Rampart packages outside the umbrella using only the stdlib."""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent
SUITE_DEPS = {
    "security_core": [],
    "portico": ["security_core"],
    "foray": ["security_core"],
    "havoc": ["security_core"],
    "havoc_proper": ["havoc", "security_core"],
    "muex_security": [],
    "rampart_sast": ["security_core"],
    "rampart_iast": ["security_core"],
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv, cwd, log, timeout=600, extra_env=None, rss=None):
    env = os.environ.copy()
    for key in ("MIX_BUILD_PATH", "MIX_DEPS_PATH", "MIX_APP_PATH", "ERL_LIBS", "ELIXIR_ERL_OPTIONS"):
        env.pop(key, None)
    env.update({"MIX_ENV": "test", "HEX_OFFLINE": "false"})
    env.update(extra_env or {})
    started = time.monotonic()
    with log.open("wb") as output:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            if rss is None:
                status = process.wait(timeout=timeout)
            else:
                while process.poll() is None:
                    if time.monotonic() - started > timeout:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    sample_rss(process.pid, rss)
                    time.sleep(0.02)
                status = process.returncode
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
        tail = log.read_text(errors="replace")[-7000:]
        raise RuntimeError(f"{argv!r} failed ({status}); {log}\n{tail}")
    return round(time.monotonic() - started, 3)


def sample_rss(pid, metrics):
    rows = subprocess.check_output(["ps", "-axo", "pid=,ppid=,rss="], text=True)
    rows = [tuple(map(int, line.split())) for line in rows.splitlines() if len(line.split()) == 3]
    descendants = {pid}
    while True:
        expanded = descendants | {child for child, parent, _ in rows if parent in descendants}
        if expanded == descendants:
            break
        descendants = expanded
    rss = sum(size * 1024 for child, _, size in rows if child in descendants)
    metrics["peak_sampled_process_tree_rss_bytes"] = max(metrics.get("peak_sampled_process_tree_rss_bytes", 0), rss)
    metrics["samples"] = metrics.get("samples", 0) + 1
    metrics["minimum_sample_interval_ms"] = 20


def unpack(archive, destination):
    """Hex contents are data: reject links, devices and path traversal."""
    with tarfile.open(archive) as outer:
        contents = outer.extractfile("contents.tar.gz").read()
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(contents), mode="r:gz") as inner:
        for member in inner.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                raise RuntimeError(f"unsupported package entry: {member.name}")
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(inner.extractfile(member).read())
                target.chmod(member.mode & 0o777)


class Gate:
    def __init__(self, work):
        self.work = work
        self.logs = work / "logs"
        self.logs.mkdir()
        self.packages = {}
        self.suite_deps = {}
        self.results = []

    def build(self):
        for app in SUITE_DEPS:
            archive = self.work / f"{app}.tar"
            command(["mix", "hex.build", "--output", str(archive)], ROOT / "apps" / app,
                    self.logs / f"build-{app}.log")
            unpack(archive, self.work / "packages" / app)
            with tarfile.open(archive) as outer:
                (self.work / f"{app}.metadata").write_bytes(outer.extractfile("metadata.config").read())
            self.packages[app] = {"archive_sha256": sha256(archive)}
        metadata = self.work / "metadata.json"
        command(["elixir", str(FIXTURES / "metadata.exs"), str(metadata)] +
                [str(self.work / f"{app}.metadata") for app in SUITE_DEPS], self.work,
                self.logs / "package-metadata.log")
        for app, package in json.loads(metadata.read_text()).items():
            self.packages[app].update(package)
            self.suite_deps[app] = [dep["app"] for dep in package["requirements"] if dep["app"] in SUITE_DEPS]
        for app, expected in SUITE_DEPS.items():
            actual = self.closure([app]) - {app}
            if actual != set(expected):
                raise RuntimeError(f"{app} declares unexpected suite dependency closure: {sorted(actual)}; expected {expected}")

    def closure(self, apps):
        required = set(apps)
        while True:
            expanded = required.union(*(self.suite_deps[app] for app in required))
            if expanded == required:
                return required
            required = expanded

    def project(self, name, apps, extra_deps=(), fixture=None):
        directory = self.work / "consumers" / name
        directory.mkdir(parents=True)
        if fixture:
            shutil.copytree(FIXTURES / fixture, directory, dirs_exist_ok=True)
        required = sorted(self.closure(apps))
        deps = [f'{{:{app}, path: "../../packages/{app}", override: true}}' for app in required]
        deps.extend(extra_deps)
        (directory / "mix.exs").write_text("""defmodule Consumer.MixProject do
  use Mix.Project
  def project, do: [app: :consumer, version: "0.0.0", deps: [%s]]
  def application, do: [extra_applications: [:logger, :inets, :crypto]]
end
""" % ", ".join(deps))
        shutil.copyfile(ROOT / "mix.lock", directory / "mix.lock")
        command(["mix", "deps.get"], directory, self.logs / f"{name}-deps.log")
        command(["mix", "compile", "--warnings-as-errors"], directory,
                self.logs / f"{name}-compile.log")
        return directory

    def exercise(self, name, directory, script, extra_env=None, timeout=300):
        print(f"Checking {name}", flush=True)
        report = directory / f"{name}.json"
        rss = {} if name == "resources" else None
        elapsed = command(["mix", "run", str(script)], directory,
                          self.logs / f"{name}.log", timeout,
                          {"RAMPART_GATE_REPORT": str(report), "RAMPART_GATE_SUPPORT": str(FIXTURES),
                           **(extra_env or {})}, rss=rss)
        details = json.loads(report.read_text())
        if rss is not None:
            details["os_memory"] = rss
        if details.get("status") != "passed":
            raise RuntimeError(f"{name} did not report a completed passing gate")
        self.results.append({"name": name, "seconds": elapsed, **details})

    def consumers(self):
        for app in SUITE_DEPS:
            directory = self.project(app, [app])
            self.exercise(app, directory, FIXTURES / "consumers" / f"{app}.exs",
                          {"RAMPART_EXPECTED_APPS": ",".join(sorted(self.closure([app])))})

    def contracts(self):
        directory = self.project("contracts", ["havoc", "portico", "foray", "rampart_sast"])
        self.exercise("contracts", directory, FIXTURES / "contracts.exs")

    def applications(self):
        directory = self.project("applications", ["havoc", "rampart_sast"],
                                 ['{:plug, "== 1.20.3"}', '{:bandit, "== 1.12.5"}'],
                                 fixture="applications")
        self.exercise("applications", directory, directory / "check.exs")

    def native(self):
        directory = self.project("native", ["portico", "foray"],
                                 ['{:plug, "== 1.20.3"}', '{:bandit, "== 1.12.5"}'],
                                 fixture="native")
        self.exercise("native", directory, directory / "check.exs")

    def muex(self):
        directory = self.project("muex", ["muex_security"], fixture="muex")
        self.exercise("muex", directory, directory / "check.exs", timeout=600)

    def search(self):
        directory = self.project("search", ["havoc_proper"], fixture="search")
        self.exercise("search", directory, directory / "check.exs", timeout=600)

    def resources(self):
        directory = self.project("resources", ["rampart_sast", "rampart_iast"], fixture="resources")
        self.exercise("resources", directory, directory / "check.exs", timeout=600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=["all", "consumers", "contracts", "applications", "native", "muex", "search", "resources"], default="all")
    parser.add_argument("--output", type=Path, default=ROOT / "tmp" / "rampart-integration.json")
    parser.add_argument("--keep-workspace", action="store_true", help="retain successful temporary consumers for debugging")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="rampart-integration-"))
    print(f"Integration workspace: {work}", flush=True)
    gate = Gate(work)
    report = {"schema_version": 1, "status": "incomplete", "workspace": str(work),
              "started_at": datetime.now(timezone.utc).isoformat(),
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "lock_sha256": sha256(ROOT / "mix.lock")}
    paths = subprocess.check_output(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    source_hashes = {name: sha256(ROOT / name) for name in sorted(set(paths)) if name and (ROOT / name).is_file()
                     and (name.startswith(("apps/", "evaluation/integration/", "examples/")) or name in ("mix.exs", "mix.lock"))}
    report["source_snapshot_sha256"] = hashlib.sha256(json.dumps(source_hashes, sort_keys=True).encode()).hexdigest()
    try:
        gate.build()
        suites = ["consumers", "contracts", "applications", "native", "muex", "search", "resources"] if args.suite == "all" else [args.suite]
        for suite in suites:
            getattr(gate, suite)()
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        report.update({"packages": gate.packages, "results": gate.results})
        artifact_root = args.output.resolve().with_suffix(".artifacts")
        artifact_root.mkdir(parents=True, exist_ok=True)
        artifacts = Path(tempfile.mkdtemp(prefix="run-", dir=artifact_root))
        shutil.copytree(gate.logs, artifacts / "logs")
        for proofs in (work / "consumers").glob("*/proofs"):
            shutil.copytree(proofs, artifacts / proofs.parent.name)
        report["artifacts"] = {str(path.relative_to(artifacts)): sha256(path) for path in sorted(artifacts.rglob("*")) if path.is_file()}
        report["artifact_directory"] = str(artifacts)
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        if report["status"] == "passed" and not args.keep_workspace:
            shutil.rmtree(work)
            report["workspace_retained"] = False
        else:
            report["workspace_retained"] = True
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Report: {args.output}", flush=True)


if __name__ == "__main__":
    main()
