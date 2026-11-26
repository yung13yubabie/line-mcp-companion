#!/usr/bin/env python3
"""Install exact, checksum-verified CI tools into a caller-owned directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
parser.add_argument("--jdk", action="store_true")
args = parser.parse_args()
if platform.system() != "Linux" or platform.machine() != "x86_64":
    parser.error("The pinned CI binaries require Linux x86_64")
root = args.directory.resolve()
root.mkdir(parents=True, exist_ok=True)
tools = [
    ("bun", "https://github.com/oven-sh/bun/releases/download/bun-v1.4.5/bun-linux-x64.zip",
     "94559b3b528995a49452f9f2404cec74f2efd7d06e0a000a8cd214b02c3666eb"),
]
if args.jdk:
    tools.append(("jdk", "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13.1%2B2/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13.1_2.tar.gz",
                  "bb8a93f9ae6e7a693b2b721e85dbeff26ae1a77447985a8d7afcdd9c7cf6222e"))
provenance = []
for name, url, expected in tools:
    archive = root / (name + (".tar.gz" if name == "jdk" else ".zip"))
    subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error", "--proto", "=https",
                    "--tlsv1.2", "--retry", "2", "--max-time", "240", url, "--output", str(archive)], check=True)
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError("Tool checksum mismatch: " + name)
    destination = root / name
    destination.mkdir(exist_ok=True)
    if name == "jdk":
        with tarfile.open(archive) as file:
            file.extractall(destination, filter="data")
    else:
        with zipfile.ZipFile(archive) as file:
            for item in file.infolist():
                path = Path(item.filename)
                if path.is_absolute() or ".." in path.parts:
                    raise RuntimeError("Unexpected ZIP entry")
                file.extract(item, destination)
                mode = item.external_attr >> 16
                if mode:
                    (destination / item.filename).chmod(mode & 0o777)
    provenance.append({"tool": name, "source": url, "sha256": actual})
(root / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
bun = root / "bun/bun-linux-x64"
jdk = root / "jdk/jdk-21.0.13.1+2"
if os.environ.get("GITHUB_PATH"):
    with open(os.environ["GITHUB_PATH"], "a") as file:
        file.write(str(bun) + "\n")
        if args.jdk:
            file.write(str(jdk / "bin") + "\n")
if args.jdk and os.environ.get("GITHUB_ENV"):
    with open(os.environ["GITHUB_ENV"], "a") as file:
        file.write("JAVA_HOME=" + str(jdk) + "\n")
print(json.dumps(provenance, indent=2))
