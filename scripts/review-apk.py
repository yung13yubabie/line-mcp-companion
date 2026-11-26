#!/usr/bin/env python3
"""Inspect Review APK signature/metadata; never install or execute APK contents.

Requires caller-specified official Android build-tools. Eligibility is a conservative
metadata prerequisite for a separately authorized isolated test, not an upgrade result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


class Blocked(Exception):
    pass


def unique(pattern, text, reason):
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise Blocked(reason)
    return matches[0]


def decimal(value, reason, maximum=2147483647):
    if not re.fullmatch(r"[0-9]+", value) or not 0 < int(value) <= maximum:
        raise Blocked(reason)
    return int(value)


def parse_inspection(signature, badging):
    for field in ("package", "sdkVersion", "targetSdkVersion", "native-code"):
        if len(re.findall(r"^" + re.escape(field) + r"\b", badging, re.MULTILINE)) != 1:
            raise Blocked("ambiguous_metadata_field")
    for field in ("Number of signers", "Signer #1 certificate SHA-256 digest",
                  "Verified using v2 scheme", "Verified using v3 scheme"):
        if len(re.findall(r"^" + re.escape(field) + r"\b", signature, re.MULTILINE)) != 1:
            raise Blocked("ambiguous_signature_field")
    if any(line.startswith("Signer #") and not line.startswith("Signer #1 ") for line in signature.splitlines()):
        raise Blocked("single_signer_required")
    if len(re.findall(r"^Verifies$", signature, re.MULTILINE)) != 1 or re.search(
        r"DOES NOT VERIFY|proof.of.rotation|lineage", signature, re.IGNORECASE
    ):
        raise Blocked("unverified_or_unsupported_signature")
    if unique(r"^Number of signers: (.*)$", signature, "ambiguous_signer_count") != "1":
        raise Blocked("single_signer_required")
    signer_numbers = re.findall(r"^Signer #(\d+)\b", signature, re.MULTILINE)
    if not signer_numbers or set(signer_numbers) != {"1"}:
        raise Blocked("single_signer_required")
    cert = unique(r"^Signer #1 certificate SHA-256 digest: (.*)$", signature, "ambiguous_certificate")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", cert):
        raise Blocked("invalid_certificate_digest")
    for line in signature.splitlines():
        if line.startswith("Verified using ") and not re.fullmatch(
            r"Verified using (?:v1|v2|v3|v3\.1|v4) scheme \([^\n]*\): (?:true|false)", line
        ):
            raise Blocked("unknown_or_malformed_signature_scheme")
    schemes = {}
    for scheme in ("v1", "v2", "v3", "v3.1", "v4"):
        found = re.findall(r"^Verified using " + re.escape(scheme) + r" scheme \([^\n]*\): (.*)$", signature, re.MULTILINE)
        if (scheme in ("v2", "v3") and len(found) != 1) or len(found) > 1 or any(x not in ("true", "false") for x in found):
            raise Blocked("ambiguous_signature_scheme")
        schemes[scheme] = found[0] == "true" if found else None
    if not (schemes["v2"] or schemes["v3"]):
        raise Blocked("verified_v2_or_v3_required")
    header = unique(r"^package: (.*)$", badging, "ambiguous_package")
    fields = {}
    cursor = 0
    for match in re.finditer(r"([A-Za-z][A-Za-z0-9_]*)='([^']*)'", header):
        if header[cursor:match.start()].strip() or match[1] in fields:
            raise Blocked("ambiguous_package_fields")
        fields[match[1]] = match[2]
        cursor = match.end()
    if header[cursor:].strip() or not {"name", "versionCode", "versionName"} <= fields.keys():
        raise Blocked("incomplete_package_fields")
    if "split" in fields or "versionCodeMajor" in fields or re.search(r"^(?:uses-split|split)(?::|=|\s|$)", badging, re.MULTILINE):
        raise Blocked("split_or_versionCodeMajor_unsupported")
    if fields["name"] != "tw.linemcp.app.review" or not fields["versionName"].endswith("-review"):
        raise Blocked("review_package_and_version_required")
    version = decimal(fields["versionCode"], "invalid_versionCode")
    minimum = decimal(unique(r"^sdkVersion:'([^']*)'$", badging, "ambiguous_minSDK"), "invalid_minSDK")
    target = decimal(unique(r"^targetSdkVersion:'([^']*)'$", badging, "ambiguous_targetSDK"), "invalid_targetSDK")
    if target < minimum:
        raise Blocked("targetSDK_below_minSDK")
    native = unique(r"^native-code: (.*)$", badging, "ambiguous_abi")
    if not re.fullmatch(r"'(?:arm64-v8a|x86_64)'", native):
        raise Blocked("single_supported_abi_required")
    if re.search(r"^application-debuggable(?:\s|:|$)", badging, re.MULTILINE):
        raise Blocked("debuggable_not_allowed")
    return {"package": fields["name"], "versionCode": version, "versionName": fields["versionName"],
            "minSDK": minimum, "targetSDK": target, "abi": native[1:-1], "debuggable": False,
            "certificate_sha256": cert.lower(), "schemes": schemes}


def run_tool(tool, args):
    result = subprocess.run([str(tool), *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors="replace", timeout=30, check=False)
    if len(result.stdout) > 262144:
        raise Blocked("tool_output_too_large")
    return {"exit_code": result.returncode, "output": result.stdout}


def file_fingerprint(path):
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise Blocked("nonempty_regular_apk_required")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if identity(before) != identity(after):
        raise Blocked("file_changed_during_hash")
    return digest.hexdigest(), after.st_size, identity(after)


def inspect_apk(apk, tools):
    apk, tools = Path(apk).absolute(), Path(tools).absolute()
    executables = {name: tools / name for name in ("apksigner", "aapt")}
    for tool in executables.values():
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise Blocked("specified_build_tool_unavailable")
    original = file_fingerprint(apk)
    with tempfile.TemporaryDirectory(prefix="review-apk-") as directory:
        private = Path(directory); private.chmod(0o700)
        snapshot = private / "snapshot.apk"
        shutil.copyfile(apk, snapshot); snapshot.chmod(0o400)
        captured = file_fingerprint(snapshot)
        if captured[:2] != original[:2] or file_fingerprint(apk) != original:
            raise Blocked("original_changed")
        evidence = {}
        for name, arguments in (("apksigner", ["verify", "--verbose", "--print-certs"]),
                                ("aapt", ["dump", "badging"])):
            result = run_tool(executables[name], [*arguments, str(snapshot)])
            if file_fingerprint(snapshot) != captured:
                raise Blocked("snapshot_changed")
            if file_fingerprint(apk) != original:
                raise Blocked("original_changed")
            evidence[name] = {"path": str(executables[name]), **result}
            if result["exit_code"] != 0:
                raise Blocked(name + "_failed")
        item = parse_inspection(evidence["apksigner"]["output"], evidence["aapt"]["output"])
        # Recheck after parsing too. This is bounded detection, not a kernel immutability guarantee.
        if file_fingerprint(snapshot) != captured:
            raise Blocked("snapshot_changed")
        if file_fingerprint(apk) != original:
            raise Blocked("original_changed")
    return {**item, "sha256": original[0], "size_bytes": original[1], "apk": str(apk),
            "signature_verified": True, "tools": evidence,
            "file_identity_checks": {"snapshot_unchanged": True, "original_unchanged": True,
                                     "method": "private_readonly_snapshot_and_before_after_sha256_stat"}}


def compare_conditions(baseline, candidate):
    reasons = []
    for key, reason in (("package", "package_mismatch"), ("abi", "abi_mismatch"),
                        ("certificate_sha256", "signer_mismatch")):
        if baseline[key] != candidate[key]:
            reasons.append(reason)
    if candidate["versionCode"] <= baseline["versionCode"]:
        reasons.append("version_not_advanced")
    return reasons


def safe_report(path, inputs, tools):
    if path.suffix != ".json" or path.is_symlink() or (path.exists() and not path.is_file()):
        raise Blocked("unsafe_report_target")
    resolved = path.resolve()
    if resolved.is_relative_to(tools.resolve()) or not path.parent.is_dir():
        raise Blocked("unsafe_report_target")
    for source in [*inputs, tools / "aapt", tools / "apksigner"]:
        if resolved == source.resolve() or (path.exists() and source.exists() and os.path.samefile(path, source)):
            raise Blocked("report_aliases_input_or_tool")


def write_report(path, value, inputs, tools):
    safe_report(path, inputs, tools)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".review-apk-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, sort_keys=True); stream.write("\n")
        safe_report(path, inputs, tools)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "compare"):
        command = commands.add_parser(name)
        command.add_argument("--build-tools", type=Path, required=True)
        command.add_argument("--report", type=Path, required=True)
        for field in (("apk",) if name == "inspect" else ("baseline", "candidate")):
            command.add_argument("--" + field, type=Path, required=True)
    args = parser.parse_args(argv)
    fields = ("apk",) if args.command == "inspect" else ("baseline", "candidate")
    inputs = [getattr(args, field) for field in fields]
    report = {"schema": 1, "command": args.command, "status": "blocked", "blocked_reasons": [],
              "upgrade_decision": "not_assessed" if args.command == "inspect" else "blocked",
              "scope": {key: "not_tested" for key in ("runtime", "device", "upgrade_runtime", "source_provenance")},
              "limitations": ["Signature and metadata only; no APK execution or installation.",
                              "Eligibility requires separate authorization and does not establish upgrade success.",
                              "Rotation lineage is unsupported; different current signers are blocked.",
                              "Snapshots and repeated hashes detect changes; no kernel immutability guarantee."]}
    try:
        safe_report(args.report, inputs, args.build_tools)
    except (Blocked, OSError, ValueError) as error:
        report["blocked_reasons"] = [str(error)]
        print(json.dumps(report, sort_keys=True))
        return 1
    try:
        # Replace any previous success before starting inspection; failures stay fail-closed.
        write_report(args.report, report, inputs, args.build_tools)
        for field, apk in zip(fields, inputs):
            try:
                report[field] = inspect_apk(apk, args.build_tools)
            except (Blocked, OSError, ValueError, subprocess.SubprocessError) as error:
                report["blocked_reasons"].append(field + ":" + str(error))
        if not report["blocked_reasons"]:
            for field, apk in zip(fields, inputs):
                try:
                    if file_fingerprint(apk)[:2] != (report[field]["sha256"], report[field]["size_bytes"]):
                        raise Blocked("original_changed_after_inspection")
                except (Blocked, OSError) as error:
                    report["blocked_reasons"].append(field + ":" + str(error))
        if not report["blocked_reasons"]:
            if args.command == "compare":
                report["blocked_reasons"] = compare_conditions(report["baseline"], report["candidate"])
                if not report["blocked_reasons"]:
                    report["upgrade_decision"] = "eligible_for_authorized_isolated_upgrade_test"
            if not report["blocked_reasons"]:
                report["status"] = "signature_metadata_verified" if args.command == "inspect" else "metadata_conditions_satisfied"
        write_report(args.report, report, inputs, args.build_tools)
        return int(bool(report["blocked_reasons"]))
    except (Blocked, OSError, ValueError) as error:
        report["status"] = "blocked"; report["blocked_reasons"].append("report_write_failed:" + str(error))
        print(json.dumps(report, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
