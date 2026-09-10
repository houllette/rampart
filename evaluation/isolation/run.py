#!/usr/bin/env python3
"""Run a reviewed command in a disposable, identity-scrubbed OS sandbox.

This host utility is evaluation infrastructure, not Core.Runner. It uses
sandbox-exec on macOS or bubblewrap on Linux, applies POSIX resource limits,
removes credential-bearing environment variables, bounds output and wall time,
and destroys the copied workspace. It fails closed when a requested isolation
capability is unavailable.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
MAX_SOURCE_FILES = 50_000
MAX_SOURCE_BYTES = 250_000_000


def digest(value):
    return hashlib.sha256(value).hexdigest()


def tree_identity(root):
    rows = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"sandbox source may not contain symlinks: {path.relative_to(root)}")
        if path.is_file():
            data = path.read_bytes()
            total += len(data)
            if len(rows) >= MAX_SOURCE_FILES or total > MAX_SOURCE_BYTES:
                raise ValueError("sandbox source exceeds file/byte admission limits")
            rows[path.relative_to(root).as_posix()] = digest(data)
    return digest(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()), len(rows), total


def backend():
    system = platform.system()
    if system == "Darwin" and Path("/usr/bin/sandbox-exec").is_file():
        return "sandbox-exec"
    if system == "Linux" and shutil.which("bwrap"):
        return "bubblewrap"
    return None


def capabilities(selected):
    common = {
        "disposable_workspace": True,
        "environment_scrub": True,
        "wall_time": True,
        "cpu_time": True,
        "file_size": True,
        "open_files": True,
        "output_bytes": True,
        "process_group_cleanup": True,
    }
    if selected in ("sandbox-exec", "bubblewrap"):
        common.update({"filesystem_boundary": True, "network_namespace_or_deny": True})
    else:
        common.update({"filesystem_boundary": False, "network_namespace_or_deny": False})

    # Darwin exposes RLIMIT_AS but rejects useful limits. Do not advertise a
    # memory boundary that this backend cannot actually establish.
    common["address_space"] = selected == "bubblewrap"
    common["process_count"] = selected == "bubblewrap"
    return common


def mac_profile(workspace):
    # The self-test and reviewed commands may use a relocatable Python whose
    # shared library lives beside the interpreter rather than under /usr or
    # Homebrew. Admit only this process's concrete runtime prefixes instead of
    # opening all of /opt (which may contain unrelated developer data).
    runtime_prefixes = [str(Path(sys.prefix).resolve()), str(Path(sys.base_prefix).resolve())]
    allowed_read_roots = [
        "/System",
        "/usr",
        "/bin",
        "/sbin",
        "/Library",
        "/opt/homebrew",
        "/usr/local",
        "/dev",
        "/private/etc",
        "/private/var/db",
        "/private/var/select",
        *runtime_prefixes,
        str(workspace),
    ]
    reads = "\n".join(
        f'(allow file-read* (subpath "{path}"))'
        for path in allowed_read_roots
        if Path(path).exists()
    )
    return f"""(version 1)
(deny default)
(allow process*)
(allow sysctl-read)
(allow mach-lookup)
(allow signal (target same-sandbox))
(allow file-read-metadata)
(allow file-read* (literal "/"))
{reads}
(allow file-write* (subpath "{workspace}"))
(allow file-write* (literal "/dev/null"))
"""


def wrapped_command(selected, workspace, command, profile_path):
    if selected == "sandbox-exec":
        profile_path.write_text(mac_profile(workspace))
        return ["/usr/bin/sandbox-exec", "-f", str(profile_path), *command]
    if selected == "bubblewrap":
        roots = []
        for path in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt"):
            if Path(path).exists():
                roots.extend(["--ro-bind", path, path])
        return [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            *roots,
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--bind",
            str(workspace),
            "/work",
            "--chdir",
            "/work",
            "--setenv",
            "HOME",
            "/work/home",
            "--setenv",
            "TMPDIR",
            "/work/tmp",
            *command,
        ]
    raise RuntimeError("no supported OS isolation backend")


def limited_child(selected, cpu_seconds, memory_bytes, file_bytes, open_files, processes):
    def apply():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (open_files, open_files))
        if selected == "bubblewrap":
            if hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(resource.RLIMIT_NPROC, (processes, processes))
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    return apply


def scrubbed_environment(workspace):
    allowed = {}
    for key in ("PATH", "LANG", "LC_ALL", "TERM"):
        if key in os.environ:
            allowed[key] = os.environ[key]
    allowed.update(
        {
            "HOME": str(workspace / "home"),
            "TMPDIR": str(workspace / "tmp"),
            "MIX_HOME": str(workspace / "home" / ".mix"),
            "HEX_HOME": str(workspace / "home" / ".hex"),
            "MIX_ENV": "test",
            "RAMPART_SANDBOX": "1",
        }
    )
    return allowed


def run(args):
    selected = backend()
    available = capabilities(selected)
    required = set(args.require)
    missing = sorted(name for name in required if not available.get(name, False))
    if selected is None or missing:
        raise RuntimeError(f"required sandbox capabilities unavailable: backend={selected}, missing={missing}")

    source = args.source.resolve()
    if not source.is_dir():
        raise ValueError("--source must identify a directory")
    source_sha256, source_files, source_bytes = tree_identity(source)

    work_root = Path(tempfile.mkdtemp(prefix="rampart-sandbox-")).resolve()
    workspace = work_root / "work"
    shutil.copytree(source, workspace)
    (workspace / "home").mkdir(exist_ok=True)
    (workspace / "tmp").mkdir(exist_ok=True)
    profile = work_root / "sandbox.sb"
    command = wrapped_command(selected, workspace, args.command, profile)
    environment = scrubbed_environment(workspace)
    started = time.monotonic()
    output = bytearray()
    overflow = False
    timed_out = False

    try:
        process = subprocess.Popen(
            command,
            cwd=workspace,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            preexec_fn=limited_child(
                selected,
                args.cpu_seconds,
                args.memory_bytes,
                args.max_file_bytes,
                args.open_files,
                args.processes,
            ),
        )

        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)

        while process.poll() is None:
            chunk = process.stdout.read(16_384)
            if chunk:
                output.extend(chunk)
                if len(output) > args.max_output_bytes:
                    overflow = True
                    os.killpg(process.pid, signal.SIGKILL)
                    break
            if time.monotonic() - started > args.wall_seconds:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(0.01)

        process.wait(timeout=5)
        while True:
            chunk = process.stdout.read(16_384)
            if not chunk:
                break
            output.extend(chunk)
        status = process.returncode
    finally:
        elapsed = round(time.monotonic() - started, 3)

    outcome = "completed"
    if overflow:
        outcome = "output_limit"
    elif timed_out:
        outcome = "timeout"
    elif status != 0:
        outcome = "nonzero_exit"

    retained = bytes(output[: args.max_output_bytes])
    report = {
        "schema_version": 1,
        "status": "passed" if outcome == "completed" else "failed",
        "outcome": outcome,
        "backend": selected,
        "capabilities": available,
        "required_capabilities": sorted(required),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": elapsed,
        "exit_status": status,
        "source_sha256": source_sha256,
        "source_files": source_files,
        "source_bytes": source_bytes,
        "command": args.command,
        "limits": {
            "wall_seconds": args.wall_seconds,
            "cpu_seconds": args.cpu_seconds,
            "memory_bytes": args.memory_bytes,
            "max_file_bytes": args.max_file_bytes,
            "open_files": args.open_files,
            "processes": args.processes,
            "max_output_bytes": args.max_output_bytes,
        },
        "output_bytes_observed": len(output),
        "output_sha256": digest(bytes(output)),
        "output_retained": retained.decode(errors="replace"),
        "environment_keys": sorted(environment),
        "workspace_destroyed": not args.keep_workspace,
    }

    if args.keep_workspace:
        report["workspace"] = str(work_root)
    else:
        shutil.rmtree(work_root)
    return report


def self_test(output):
    root = Path(tempfile.mkdtemp(prefix="rampart-sandbox-self-test-"))
    source = root / "source"
    source.mkdir()
    secret = root / "outside-secret"
    secret.write_text("must-not-be-readable")
    script = source / "probe.py"
    script.write_text(
        """import errno, json, os, pathlib, socket, sys
pathlib.Path('write-ok').write_text('ok')
secret = pathlib.Path(sys.argv[1])
try:
    secret.read_text()
except OSError as error:
    outside_errno = error.errno
    outside_denied = error.errno in (errno.EACCES, errno.EPERM)
else:
    outside_errno = None
    outside_denied = False
sock = socket.socket()
sock.settimeout(0.2)
try:
    sock.connect(('127.0.0.1', 9))
except OSError as error:
    network_errno = error.errno
    network_denied = error.errno in (errno.EACCES, errno.EPERM)
else:
    network_errno = None
    network_denied = False
credential_env = [k for k in os.environ if 'TOKEN' in k or 'KEY' in k]
print(json.dumps({'outside_denied': outside_denied, 'outside_errno': outside_errno, 'network_denied': network_denied, 'network_errno': network_errno, 'credential_env': credential_env}, sort_keys=True))
if not outside_denied or not network_denied or credential_env:
    raise SystemExit(7)
"""
    )
    (source / "limit_probe.py").write_text(
        """import sys, time
if sys.argv[1] == 'sleep':
    time.sleep(10)
elif sys.argv[1] == 'output':
    sys.stdout.write('x' * 100000)
    sys.stdout.flush()
"""
    )

    namespace = argparse.Namespace(
        source=source,
        command=[sys.executable, "probe.py", str(secret)],
        require=["filesystem_boundary", "network_namespace_or_deny", "environment_scrub"],
        wall_seconds=10,
        cpu_seconds=5,
        memory_bytes=512 * 1024 * 1024,
        max_file_bytes=8 * 1024 * 1024,
        open_files=64,
        processes=16,
        max_output_bytes=64 * 1024,
        keep_workspace=False,
    )
    try:
        report = run(namespace)
        if report["status"] != "passed":
            raise RuntimeError("filesystem/network/environment sandbox probe failed")

        timeout_namespace = argparse.Namespace(**vars(namespace))
        timeout_namespace.command = [sys.executable, "limit_probe.py", "sleep"]
        timeout_namespace.wall_seconds = 1
        timeout_report = run(timeout_namespace)
        if timeout_report["outcome"] != "timeout":
            raise RuntimeError(f"wall-time probe did not time out: {timeout_report['outcome']}")

        output_namespace = argparse.Namespace(**vars(namespace))
        output_namespace.command = [sys.executable, "limit_probe.py", "output"]
        output_namespace.max_output_bytes = 256
        output_report = run(output_namespace)
        if output_report["outcome"] != "output_limit":
            raise RuntimeError(f"output probe did not hit its limit: {output_report['outcome']}")

        report["self_test_checks"] = {
            "filesystem_network_environment": "passed",
            "wall_time": timeout_report["outcome"],
            "output_bytes": output_report["outcome"],
            "timeout_output_sha256": timeout_report["output_sha256"],
            "overflow_output_sha256": output_report["output_sha256"],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        shutil.rmtree(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "tmp" / "rampart-sandbox.json")
    parser.add_argument("--require", action="append", default=["filesystem_boundary", "network_namespace_or_deny"])
    parser.add_argument("--wall-seconds", type=int, default=60)
    parser.add_argument("--cpu-seconds", type=int, default=30)
    parser.add_argument("--memory-bytes", type=int, default=2 * 1024 * 1024 * 1024)
    parser.add_argument("--max-file-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--open-files", type=int, default=256)
    parser.add_argument("--processes", type=int, default=128)
    parser.add_argument("--max-output-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--keep-workspace", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.self_test:
        report = self_test(args.output)
    else:
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        if args.source is None or not args.command:
            parser.error("--source and a command after -- are required")
        for name in ("wall_seconds", "cpu_seconds", "memory_bytes", "max_file_bytes", "open_files", "processes", "max_output_bytes"):
            if getattr(args, name) <= 0:
                parser.error(f"--{name.replace('_', '-')} must be positive")
        report = run(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")

    print(f"Sandbox: {report['status']} ({report['backend']}, {report['outcome']})")
    print(f"Report: {args.output}")
    if report["status"] != "passed":
        sys.exit(1)


if __name__ == "__main__":
    main()
