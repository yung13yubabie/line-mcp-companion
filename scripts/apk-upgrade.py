#!/usr/bin/env python3
"""Read-only, explicitly profiled APK preflight; never sign, install or execute APKs.

Expected hashes and public signer fingerprint must come from independently identified
inputs. Supplying them is not proof of publisher identity, source or device readiness.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess

SPEC = importlib.util.spec_from_file_location("review_apk", Path(__file__).with_name("review-apk.py"))
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


def digest(value):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError("expected exactly 64 hexadecimal SHA-256 characters")
    return value.lower()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "compare"):
        p = sub.add_parser(name)
        p.add_argument("--package-kind", choices=("review", "release"), required=True)
        p.add_argument("--expected-signer-sha256", type=digest, required=True)
        p.add_argument("--build-tools", type=Path, required=True)
        p.add_argument("--report", type=Path, required=True)
        for field in (("apk",) if name == "inspect" else ("baseline", "candidate")):
            p.add_argument("--" + field, type=Path, required=True)
            p.add_argument("--" + field + "-sha256", type=digest, required=True)
    args = parser.parse_args(argv)
    fields = ("apk",) if args.command == "inspect" else ("baseline", "candidate")
    inputs = [getattr(args, field) for field in fields]
    report = {
        "schema": 1, "command": args.command, "package_kind": args.package_kind,
        "status": "blocked", "blocked_reasons": [],
        "expected_signer_sha256": args.expected_signer_sha256,
        "expected_apk_sha256": {field: getattr(args, field + "_sha256") for field in fields},
        "upgrade_decision": "not_assessed" if args.command == "inspect" else "blocked",
        "scope": {key: "not_tested" for key in ("publisher_identity", "source_provenance", "runtime", "device", "data_preservation", "upgrade_runtime")},
        "limitations": [
            "Caller-supplied public fingerprints and hashes are bindings, not independently authenticated trust.",
            "Only signature/metadata prerequisites; no APK execution, signing, install, uninstall or device action.",
            "Strict versionCode advancement is a conservative test prerequisite, not a claim Android forbids same-version reinstall.",
            "Rotation lineage and split APKs are unsupported and blocked; no signature substitution.",
            "Release profile is an exact package policy, not proof of an actual production release.",
        ],
    }
    try:
        review.safe_report(args.report, inputs, args.build_tools)
    except (review.Blocked, OSError, ValueError) as error:
        report["blocked_reasons"] = [str(error)]
        print(json.dumps(report, sort_keys=True)); return 1
    try:
        # Clear a previous success before any tool invocation; never reuse stale JSON.
        review.write_report(args.report, report, inputs, args.build_tools)
        for field, apk in zip(fields, inputs):
            try:
                expected = getattr(args, field + "_sha256")
                if review.file_fingerprint(apk)[0] != expected:
                    raise review.Blocked("apk_sha256_mismatch")
                item = review.inspect_apk(apk, args.build_tools, package_kind=args.package_kind)
                report[field] = item
                if item["sha256"] != expected:
                    raise review.Blocked("apk_sha256_mismatch")
                if item["certificate_sha256"] != args.expected_signer_sha256:
                    raise review.Blocked("expected_signer_mismatch")
            except (review.Blocked, OSError, ValueError, subprocess.SubprocessError) as error:
                report["blocked_reasons"].append(field + ":" + str(error))
        if all(field in report for field in fields):
            for field, apk in zip(fields, inputs):
                try:
                    if review.file_fingerprint(apk)[:2] != (report[field]["sha256"], report[field]["size_bytes"]):
                        raise review.Blocked("original_changed_after_inspection")
                except (review.Blocked, OSError) as error:
                    report["blocked_reasons"].append(field + ":" + str(error))
        if args.command == "compare" and all(field in report for field in fields):
            report["blocked_reasons"].extend(review.compare_conditions(report["baseline"], report["candidate"]))
            if not report["blocked_reasons"]:
                report["upgrade_decision"] = "eligible_for_authorized_isolated_upgrade_test"
        if not report["blocked_reasons"]:
            report["status"] = "signature_metadata_verified" if args.command == "inspect" else "metadata_conditions_satisfied"
        review.write_report(args.report, report, inputs, args.build_tools)
        return int(bool(report["blocked_reasons"]))
    except (review.Blocked, OSError, ValueError) as error:
        report["status"] = "blocked"
        report["blocked_reasons"].append("report_write_failed:" + str(error))
        print(json.dumps(report, sort_keys=True)); return 1


if __name__ == "__main__":
    raise SystemExit(main())
