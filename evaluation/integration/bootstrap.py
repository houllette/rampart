#!/usr/bin/env python3
"""Install checksummed native fixtures under a caller-selected directory."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import platform
import tarfile
import urllib.request
import zipfile

from run import command


def download(spec, cache):
    path = cache / spec["sha256"]
    if not path.exists():
        with urllib.request.urlopen(spec["url"], timeout=60) as response:
            path.write_bytes(response.read())
    if hashlib.sha256(path.read_bytes()).hexdigest() != spec["sha256"]:
        raise RuntimeError(f"checksum mismatch for {spec['url']}")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    args = parser.parse_args()
    prefix = args.prefix.resolve()
    cache = prefix / "downloads"
    binary = prefix / "bin"
    cache.mkdir(parents=True, exist_ok=True)
    binary.mkdir(exist_ok=True)
    manifest = json.loads(Path(__file__).with_name("native-tools.json").read_text())
    system = f"{platform.system()}-{platform.machine()}"
    if system not in manifest:
        raise RuntimeError(f"no reviewed native tool hashes for {system}")
    for name, spec in manifest[system].items():
        archive = download(spec, cache).read_bytes()
        if spec["url"].endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
                archive = zipped.read(zipped.namelist()[0])
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            data = tar.extractfile(name).read()
        (binary / name).write_bytes(data)
        (binary / name).chmod(0o755)
        print(f"Installed {name} {spec['version']}", flush=True)

    spec = manifest["nmap"]
    source = prefix / f"nmap-{spec['version']}"
    if not source.exists():
        with tarfile.open(download(spec, cache), mode="r:bz2") as tar:
            for member in tar.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                    raise RuntimeError(f"unsupported source entry: {member.name}")
                target = prefix.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(tar.extractfile(member).read())
                    target.chmod(member.mode & 0o777)
    command(["./configure", f"--prefix={prefix}", "--without-zenmap", "--without-ncat",
             "--without-nping", "--without-openssl", "--without-libssh2"], source,
            prefix / "nmap-configure.log")
    command(["make", "-j4"], source, prefix / "nmap-build.log", timeout=1200)
    command(["make", "install"], source, prefix / "nmap-install.log")
    print(f"Installed nmap {spec['version']}; prepend {binary} to PATH", flush=True)


if __name__ == "__main__":
    main()
