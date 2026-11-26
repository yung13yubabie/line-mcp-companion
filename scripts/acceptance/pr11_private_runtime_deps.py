"""Non-root, private extraction of libpulse's missing official Ubuntu dependencies.
Uses only the runner's existing apt metadata. No install/update/repo/key/ACL operation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
from urllib.parse import urlparse


def prepare_private_libs(emulator, base_env, out, state, save):
    env = dict(base_env)
    env.pop("GH_TOKEN", None)
    records = []
    deadline = time.monotonic() + 150
    root = Path(os.environ["RUNNER_TEMP"]) / "pr11-private-libs"
    downloads = root / "downloads"
    extracted = root / "root"
    downloads.mkdir(parents=True, exist_ok=True)
    extracted.mkdir(exist_ok=True)

    def write():
        (out / "private-dependencies.json").write_text(json.dumps({
            "mode": "non_root_private_dpkg_extract_only", "euid": os.geteuid(),
            "new_sources_or_keys": False, "package_install_or_maintainer_scripts": False,
            "records": records, "result": state.get("private_dependencies"),
        }, indent=2) + "\n")
        save()

    def run(args, cwd=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("dependency_budget_expired")
        p = subprocess.run(args, cwd=cwd, env=env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=min(40, remaining))
        return p

    try:
        if os.geteuid() == 0:
            raise RuntimeError("non_root_required")
        version = run([str(emulator), "-version"])
        records.append({"probe": "emulator_version_before", "exit": version.returncode,
                        "output": version.stdout[:8000]})
        if version.returncode == 0:
            state["private_dependencies"] = "not_needed_version_already_works"
            write()
            return env
        if "libpulse.so.0" not in version.stdout:
            raise RuntimeError("different_missing_runtime_dependency")
        # Read cached distribution metadata only. No apt update, new source or privilege use.
        depends = run(["apt-cache", "depends", "--recurse", "--important",
                       "--no-recommends", "--no-suggests", "--no-conflicts",
                       "--no-breaks", "--no-replaces", "--no-enhances", "libpulse0"])
        records.append({"probe": "cached_libpulse_dependencies", "exit": depends.returncode,
                        "output": depends.stdout[:12000]})
        if depends.returncode:
            raise RuntimeError("cached_dependency_metadata_unavailable")
        packages = []
        for line in depends.stdout.splitlines():
            if line and not line[0].isspace() and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::amd64)?", line):
                package = line.removesuffix(":amd64")
                if package not in packages:
                    packages.append(package)
        if "libpulse0" not in packages or len(packages) > 80:
            raise RuntimeError("unexpected_dependency_metadata")
        missing = []
        for package in packages:
            status = run(["dpkg-query", "-W", "-f=${Status}", package])
            if status.returncode != 0 or status.stdout.strip() != "install ok installed":
                missing.append(package)
        if not missing or len(missing) > 30:
            raise RuntimeError("unresolved_or_excessive_private_dependencies")
        for package in missing:
            uris = run(["apt-get", "--print-uris", "download", package], cwd=downloads)
            if uris.returncode:
                records.append({"package": package, "stage": "cached_uri", "exit": uris.returncode,
                                "diagnostic": uris.stdout[:4000]})
                raise RuntimeError("cached_official_package_unavailable")
            candidates = []
            for line in uris.stdout.splitlines():
                if line.startswith("'"):
                    parts = shlex.split(line)
                    if len(parts) == 4:
                        candidates.append(parts)
            if len(candidates) != 1:
                raise RuntimeError("ambiguous_cached_package_uri")
            url, filename, size_text, digest_spec = candidates[0]
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if (parsed.scheme not in ("http", "https") or parsed.username or parsed.password
                    or not (host == "ubuntu.com" or host.endswith(".ubuntu.com")
                            or host == "canonical.com" or host.endswith(".canonical.com"))):
                raise RuntimeError("package_origin_not_existing_official_ubuntu")
            if Path(filename).name != filename or not filename.endswith(".deb"):
                raise RuntimeError("unsafe_package_filename")
            algorithm, expected = digest_spec.split(":", 1)
            if algorithm.upper() not in ("SHA256", "SHA512"):
                raise RuntimeError("strong_package_digest_missing")
            size = int(size_text)
            if size <= 0 or size > 100000000:
                raise RuntimeError("package_size_cap")
            downloaded = run(["apt-get", "-o", "Acquire::Retries=0", "-o",
                              "Acquire::http::Timeout=25", "-o", "Acquire::https::Timeout=25",
                              "download", package], cwd=downloads)
            record = {"package": package, "uri": url, "archive": filename,
                      "metadata_bytes": size, "metadata_digest": digest_spec,
                      "download_exit": downloaded.returncode}
            records.append(record)
            if downloaded.returncode:
                record["diagnostic"] = downloaded.stdout[:4000]
                raise RuntimeError("official_package_download_failed")
            path = downloads / filename
            if not path.is_file() or path.stat().st_size != size:
                raise RuntimeError("package_size_mismatch")
            data = path.read_bytes()
            if hashlib.new(algorithm.lower(), data).hexdigest() != expected.lower():
                raise RuntimeError("package_digest_mismatch")
            record["actual_sha256"] = hashlib.sha256(data).hexdigest()
            control = run(["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"])
            record["control_exit"] = control.returncode
            record["control"] = control.stdout[:2000]
            if control.returncode:
                raise RuntimeError("invalid_package_control")
            unpacked = run(["dpkg-deb", "-x", str(path), str(extracted)])
            record["private_extract_exit"] = unpacked.returncode
            if unpacked.returncode:
                raise RuntimeError("private_extract_failed")
            write()
        library_dirs = [extracted / "usr/lib/x86_64-linux-gnu/pulseaudio",
                        extracted / "usr/lib/x86_64-linux-gnu", extracted / "lib/x86_64-linux-gnu"]
        env["LD_LIBRARY_PATH"] = ":".join(str(p) for p in library_dirs if p.is_dir()) + (
            ":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
        after = run([str(emulator), "-version"])
        records.append({"probe": "emulator_version_after", "exit": after.returncode,
                        "output": after.stdout[:8000]})
        if after.returncode:
            raise RuntimeError("emulator_runtime_still_unavailable")
        state["private_dependencies"] = "verified_private_official_libraries"
        write()
        return env
    except Exception as error:
        state["private_dependencies"] = "blocked"
        state["private_dependency_stop"] = (str(error) if isinstance(error, RuntimeError)
                                             else type(error).__name__)[:160]
        write()
        return None
