#!/usr/bin/env python3
"""Capability first, then one normal authorized read of one fixed APK artifact.
No AVD, device, signing, privilege change, fallback download or product test is performed by this phase.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile

REPO = "yung13yubabie/line-mcp-companion"
ARTIFACT_ID = 15103578619
ZIP_SHA256 = "0e62f61cc7fe7b572657110583285a9bcd46e4e73e4e88e727902bfd1542de43"
ZIP_BYTES = 73613578
APK_SHA256 = "cd9d1c39db10d3bcb426881f182fdd2433f1d4c4df99807b9263e16da16f35a4"
APK_NAME = "line-mcp-companion-0.3.1-x86_64-review.apk"
SOURCE = "ec7acc84a1b241976c89778e33313a03514e8dd2"
HEAD = "e1b25d2dd960bf31363b073b92f9108e75f2d300"
OUT = Path("acceptance-results")
OUT.mkdir(exist_ok=True)
state = {
    "fixed_apk_pr_head": HEAD, "fixed_apk_workflow_source": SOURCE, "artifact_id": ARTIFACT_ID,
    "harness_run_id": os.environ.get("GITHUB_RUN_ID"),
    "harness_checkout_merge_sha": os.environ.get("GITHUB_SHA"),
    "harness_head_ref": os.environ.get("GITHUB_HEAD_REF"),
    "expected_apk_sha256": APK_SHA256,
    "capability": "not_attempted", "artifact_download": "not_attempted",
    "fixed_apk_hash": "not_attempted", "fixed_source": "not_attempted", "fixed_input_verification": "not_attempted", "avd_boot": "not_attempted",
    "install": "not_attempted", "cold_start": "not_attempted",
    "background_foreground": "not_attempted", "restart": "not_attempted",
    "android_mcp_readonly": "not_attempted", "physical_device": "not_attempted",
    "phase": "hosted_capability_and_fixed_input_only",
}


def save():
    (OUT / "status.json").write_text(json.dumps(state, indent=2) + "\n")


def command(args, timeout=30):
    try:
        result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
        return {"command": args, "exit": result.returncode, "output": result.stdout[:16000]}
    except subprocess.TimeoutExpired:
        return {"command": args, "exit": 124, "output": "probe_timeout"}
    except FileNotFoundError:
        return {"command": args, "exit": 127, "output": "tool_missing"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download_fixed():
    # github.token is the normal, contents:read-only job token, never a user secret.
    # Do not log it or signed Location. Do not retry a denied call with a different route or identity.
    token = os.environ.pop("GH_TOKEN", "")
    if not token:
        state["artifact_download"] = "blocked_missing_job_token"
        return False
    endpoint = f"https://api.github.com/repos/{REPO}/actions/artifacts/{ARTIFACT_ID}/zip"
    req = urllib.request.Request(endpoint, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "pr11-readonly-hosted-validation",
    })
    token = ""
    response = None
    signed_location = None
    try:
        response = urllib.request.build_opener(NoRedirect()).open(req, timeout=30)
        state["artifact_api_status"] = response.status
    except urllib.error.HTTPError as error:
        state["artifact_api_status"] = error.code
        if error.code == 302:
            signed_location = error.headers.get("Location")
        else:
            # Only the fixed GitHub error message is retained; no headers, credentials or SAS URL.
            try:
                body = json.loads(error.read(4096))
                state["artifact_api_message"] = str(body.get("message", "request_rejected"))[:300]
            except Exception:
                state["artifact_api_message"] = "request_rejected"
            state["artifact_download"] = "blocked_api_permission" if error.code in (401, 403) else "blocked_api_response"
            error.close()
            return False
        error.close()
    except Exception:
        state["artifact_download"] = "blocked_api_network"
        return False
    if signed_location:
        if not signed_location.startswith("https://"):
            state["artifact_download"] = "blocked_non_https_redirect"
            return False
        try:
            # A new request without Authorization follows the API-provided normal signed download.
            response = urllib.request.urlopen(urllib.request.Request(signed_location), timeout=45)
        except Exception:
            state["artifact_download"] = "blocked_archive_network"
            return False
    signed_location = None
    if response is None or response.status != 200:
        if response:
            response.close()
        state["artifact_download"] = "blocked_archive_response"
        return False
    target = Path(os.environ["RUNNER_TEMP"]) / "pr11-fixed-input.zip"
    h = hashlib.sha256()
    count = 0
    try:
        with response, target.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > ZIP_BYTES:
                    raise ValueError("size_cap")
                h.update(chunk)
                output.write(chunk)
    except Exception:
        state["artifact_download"] = "failed_archive_transfer_or_size_limit"
        return False
    state["downloaded_zip_bytes"] = count
    state["downloaded_zip_sha256"] = h.hexdigest()
    if count != ZIP_BYTES or h.hexdigest() != ZIP_SHA256:
        state["artifact_download"] = "failed_zip_identity"
        return False
    state["artifact_download"] = "verified_fixed_zip"
    try:
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("duplicate_zip_entry")
            for name in names:
                p = Path(name)
                if p.is_absolute() or ".." in p.parts:
                    raise ValueError("unsafe_zip_entry")
            if archive.read("source-commit.txt").decode().strip() != SOURCE:
                state["fixed_source"] = "failed_wrong_source"
                raise ValueError("wrong_source")
            state["fixed_source"] = "verified"
            data = archive.read(APK_NAME)
            state["downloaded_apk_bytes"] = len(data)
            state["downloaded_apk_sha256"] = hashlib.sha256(data).hexdigest()
            if state["downloaded_apk_sha256"] != APK_SHA256:
                state["fixed_apk_hash"] = "failed_wrong_apk"
                raise ValueError("wrong_apk")
            (Path(os.environ["RUNNER_TEMP"]) / APK_NAME).write_bytes(data)
        state["fixed_apk_hash"] = "verified"
        state["fixed_input_verification"] = "verified"
        return True
    except Exception:
        state["fixed_input_verification"] = "failed_layout_source_or_apk"
        return False


def main():
    save()
    if os.environ.get("GITHUB_REPOSITORY") != REPO or os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        state["capability"] = "blocked_wrong_execution_scope"
        save()
        return 2
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr = event.get("pull_request", {})
    state["harness_pr_number"] = event.get("number")
    state["harness_pr_head_sha"] = pr.get("head", {}).get("sha")
    if (pr.get("draft") is not True or pr.get("head", {}).get("ref") != "validation/pr11-hosted-20261126"
            or pr.get("head", {}).get("repo", {}).get("full_name") != REPO):
        state["capability"] = "blocked_wrong_draft_scope"
        save()
        return 2
    sdk = Path(os.environ.get("ANDROID_HOME", "/nonexistent"))
    emulator = sdk / "emulator/emulator"
    adb = sdk / "platform-tools/adb"
    kvm = {"exists": Path("/dev/kvm").exists(),
           "readable": os.access("/dev/kvm", os.R_OK),
           "writable": os.access("/dev/kvm", os.W_OK)}
    free = shutil.disk_usage(Path.cwd()).free
    probes = {
        "runner": os.environ.get("RUNNER_OS"), "architecture": os.environ.get("RUNNER_ARCH"),
        "kvm": kvm, "disk_free_bytes": free,
        "minimum_free_bytes": 8 * 1024**3,
        "emulator_version": command([str(emulator), "-version"]),
        "adb_version": command([str(adb), "version"]),
        "accelerator": command([str(emulator), "-accel-check"]),
        "installed_images": sorted(str(p.relative_to(sdk)) for p in (sdk / "system-images").glob("**/source.properties")),
    }
    (OUT / "capabilities.json").write_text(json.dumps(probes, indent=2) + "\n")
    state["capability"] = "verified" if (all(kvm.values()) and free >= 8 * 1024**3
        and probes["accelerator"]["exit"] == 0
        and probes["emulator_version"]["exit"] == 0
        and probes["adb_version"]["exit"] == 0) else "blocked"
    save()
    if state["capability"] != "verified":
        print("Hosted capability gate blocked; APK download and Android stages not attempted.")
        return 2
    ok = download_fixed()
    save()
    if not ok:
        print("Fixed artifact read/identity gate blocked; no alternate permission or download route attempted.")
        return 3
    print("Hosted capability and exact fixed APK bytes verified. Android execution stages not yet attempted in this phase.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        state["probe_error"] = "unexpected_probe_failure"
        save()
        print("Probe failed; see redacted status receipt.")
        sys.exit(4)
