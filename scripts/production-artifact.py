#!/usr/bin/env python3
"""Static production/Review packaging boundary. Never executes APK or application JS.
Source closure receipts are consistency evidence, not signatures or device acceptance.
"""
import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import sys
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
MARKERS = ("LMA_MOCK_DATA_v1", "LMA_MOCK_AI_v1", "u_mock_", "c_mock_", "社區住戶交流群", "滷肉",
           "MockSource", "MockAiProvider", "MockSender", "goMockOnline", "seedMockDigests", "mock_seeded",
           "LINE_MCP_MOCK", "LMA_INCLUDE_MOCK", "MockMode", "mock_mode", "src/mock/", "mock-source.ts",
           "mock-ai-stub", "mock-stub", "mock://local", "mock-chat", "mock-image", "Mock 示範資料", "Mock 模式（假聊天資料")


class Blocked(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Blocked(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def scan(data, name):
    for marker in MARKERS:
        require(marker.encode() not in data and marker.encode("utf-16le") not in data,
                "App QA marker in " + name + ": " + marker)


def load_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def verify_bundle(data, receipt_bytes):
    require(bool(data), "Empty JS bundle")
    scan(data, "main.mjs")
    receipt = load_json(receipt_bytes)
    require(receipt.get("schema") == 1 and receipt.get("mode") == "production", "Production source receipt required")
    require(receipt.get("bundle_sha256") == sha(data), "Bundle receipt hash mismatch")
    require(receipt.get("recipe_sha256") == sha((ROOT / "scripts/bundle.ts").read_bytes()), "Stale build recipe")
    inputs = receipt.get("inputs")
    require(isinstance(inputs, dict) and {"src/main.ts", "src/runtime-mode.production.ts"} <= inputs.keys(), "Incomplete source closure")
    for name, digest in inputs.items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts and "\\" not in name, "Unsafe source path")
        require(not name.startswith(("src/mock/", "test/", "review-work/")) and name != "src/runtime-mode.ts", "QA source in closure")
        require(name.startswith(("src/", "node_modules/")), "Unknown source root")
        require(re.fullmatch(r"[0-9a-f]{64}", digest or "") is not None, "Invalid source digest")
        require(sha((ROOT / name).read_bytes()) == digest, "Source changed: " + name)
    return {"bundle_sha256": sha(data), "source_files_checked": len(inputs), "production_policy": "src/runtime-mode.production.ts"}


def dex_strings(data):
    # Standard little-endian DEX string table only; no code is executed or interpreted.
    require(len(data) >= 112 and re.fullmatch(rb"dex\n0(?:35|37|38|39|40)\x00", data[:8]) is not None, "Unsupported DEX header")
    require(struct.unpack_from("<III", data, 32) == (len(data), 112, 0x12345678), "Invalid DEX sizes/endian")
    require(hashlib.sha1(data[32:]).digest() == data[12:32] and zlib.adler32(data[12:]) & 0xffffffff == struct.unpack_from("<I", data, 8)[0], "DEX checksum mismatch")
    count, offset = struct.unpack_from("<II", data, 56)
    require(count > 0 and 112 <= offset <= len(data) - 4 * count, "Invalid DEX string table")
    strings = []
    for i in range(count):
        cursor = struct.unpack_from("<I", data, offset + i * 4)[0]
        require(112 <= cursor < len(data), "Invalid DEX string offset")
        utf16_size = 0
        for shift in range(0, 35, 7):
            require(cursor < len(data), "Truncated DEX string length")
            value = data[cursor]; cursor += 1
            require(shift < 28 or value <= 15, "Overflow DEX string length")
            utf16_size |= (value & 127) << shift
            if value < 128:
                break
        else:
            raise Blocked("Invalid DEX string length")
        end = data.find(b"\0", cursor)
        require(end >= cursor, "Unterminated DEX string")
        raw = data[cursor:end]
        require(all(value < 240 for value in raw), "Invalid modified UTF-8 string")
        decoded = raw.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass")
        require(len(decoded.encode("utf-16le", "surrogatepass")) // 2 == utf16_size, "DEX string length mismatch")
        strings.append(raw)
    return strings


def tool(executable, arguments):
    require(executable.is_file(), "Specified Android tool missing")
    result = subprocess.run([str(executable), *arguments], capture_output=True, timeout=60, check=False)
    require(result.returncode == 0, "Official aapt failed")
    return result.stdout.decode("utf-8", "strict")


def metadata(badging, xml, package, version_code, version_name, abi):
    for field in ("package", "native-code", "sdkVersion", "targetSdkVersion"):
        require(len(re.findall(r"^" + re.escape(field) + r"\b", badging, re.M)) == 1, "Ambiguous metadata field")
    headers = re.findall(r"^package: (.*)$", badging, re.M)
    require(len(headers) == 1, "Ambiguous package metadata")
    matches = list(re.finditer(r"([A-Za-z][A-Za-z0-9_]*)='([^']*)'", headers[0]))
    cursor = 0
    for match in matches:
        require(not headers[0][cursor:match.start()].strip(), "Malformed package metadata")
        cursor = match.end()
    require(not headers[0][cursor:].strip(), "Malformed package metadata")
    fields = [(match[1], match[2]) for match in matches]
    values = dict(fields)
    require(len(values) == len(fields) and not {"split", "versionCodeMajor"} & values.keys(), "Unsupported package metadata")
    require((values.get("name"), values.get("versionCode"), values.get("versionName")) == (package, str(version_code), version_name), "Unexpected package/version")
    require(re.findall(r"^native-code: (.*)$", badging, re.M) == ["'" + abi + "'"], "Unexpected ABI metadata")
    require(re.findall(r"^sdkVersion:'(.*)'$", badging, re.M) == ["29"] and re.findall(r"^targetSdkVersion:'(.*)'$", badging, re.M) == ["35"], "Unexpected SDK metadata")
    require("application-debuggable" not in badging, "Debuggable production candidate")
    require(not re.search(r"^uses-split\b", badging, re.M), "Split candidate unsupported")
    require("E: manifest " in xml and "E: application " in xml, "Manifest inspection incomplete")
    for line in xml.splitlines():
        if re.search(r"android:(?:debuggable|testOnly)\(", line):
            require(re.search(r"=\s*\(type 0x12\)0x0\s*$", line) is not None, "Unsafe manifest debug/test flag")
    scan(xml.encode(), "manifest")
    return {"package": package, "versionCode": version_code, "versionName": version_name, "abi": abi, "minSDK": 29, "targetSDK": 35}


def verify_apk(path, args):
    for field in ("build_tools", "expected_package", "expected_version_code", "expected_version_name", "expected_abi"):
        require(getattr(args, field) is not None, "APK inspection requires explicit tools/package/version/ABI")
    require(args.expected_package in ("tw.linemcp.app", "tw.linemcp.app.review") and args.expected_abi in ("arm64-v8a", "x86_64"), "Unsupported candidate")
    require(0 < args.expected_version_code <= 2147483647, "Invalid expected versionCode")
    snapshot = path.read_bytes()
    lock = load_json((ROOT / "android/native-runtime.lock.json").read_bytes())
    allowed_assets = {"assets/nodeapp/main.mjs", "assets/nodeapp/build-boundary.json", "assets/native-runtime/native-runtime.lock.json", "assets/dexopt/baseline.prof", "assets/dexopt/baseline.profm"}
    allowed_assets |= {"assets/native-runtime/" + name for name in lock["license_outputs"]}
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist(); names = [item.filename for item in entries]
        require(len(names) == len(set(names)), "Duplicate ZIP entry")
        require(sum(item.file_size for item in entries) <= 512 * 1024 * 1024, "Oversize APK contents")
        for item in entries:
            name = item.filename; parts = PurePosixPath(name)
            require(not parts.is_absolute() and ".." not in parts.parts and "\\" not in name and not item.flag_bits & 1, "Unsafe/encrypted ZIP entry")
            require((item.external_attr >> 16) & 0o170000 != 0o120000, "ZIP symlink")
            require(item.file_size <= 160 * 1024 * 1024, "Oversize ZIP entry")
            scan(name.encode(), "ZIP name")
            if item.is_dir():
                continue
            if name.startswith("assets/"):
                require(name in allowed_assets, "Unknown asset: " + name)
            require(name in {"AndroidManifest.xml", "resources.arsc", "DebugProbesKt.bin"} or
                    name.startswith(("assets/", "res/", "lib/", "META-INF/")) or
                    re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex", name), "Unknown APK entry: " + name)
            if not name.startswith(("lib/", "META-INF/")):
                scan(archive.read(item), name)
        require("AndroidManifest.xml" in names and "resources.arsc" in names, "Incomplete APK")
        require(allowed_assets - {"assets/dexopt/baseline.prof", "assets/dexopt/baseline.profm"} <= set(names), "Missing production assets")
        require(load_json(archive.read("assets/native-runtime/native-runtime.lock.json")) == lock, "Packaged native lock differs")
        for name, digest in lock["license_outputs"].items():
            require(sha(archive.read("assets/native-runtime/" + name)) == digest, "License asset differs")
        dex = [name for name in names if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex", name)]
        require(bool(dex), "Missing DEX")
        require(set(dex) == {"classes.dex"} | {f"classes{i}.dex" for i in range(2, len(dex) + 1)}, "Non-contiguous DEX inventory")
        require({name for name in names if name.endswith(".dex")} == set(dex), "Unexpected DEX path")
        total_strings = 0
        for name in dex:
            for value in dex_strings(archive.read(name)):
                scan(value, name); total_strings += 1
        abis = {name.split('/')[1] for name in names if name.startswith("lib/") and not name.endswith('/')}
        require(abis == {args.expected_abi}, "Unexpected native ABI inventory")
        bundle = verify_bundle(archive.read("assets/nodeapp/main.mjs"), archive.read("assets/nodeapp/build-boundary.json"))
    badging = tool(args.build_tools / "aapt", ["dump", "badging", str(path)])
    xml = tool(args.build_tools / "aapt", ["dump", "xmltree", str(path), "AndroidManifest.xml"])
    info = metadata(badging, xml, args.expected_package, args.expected_version_code, args.expected_version_name, args.expected_abi)
    require(path.read_bytes() == snapshot, "APK changed during inspection")
    return {**bundle, **info, "apk_sha256": sha(snapshot), "dex_files": len(dex), "dex_strings_checked": total_strings, "assets_checked": len([n for n in names if n.startswith('assets/') and not n.endswith('/')])}


def report_safe(path, artifact, tools):
    require(path.suffix == ".json" and not path.is_symlink() and (not path.exists() or path.is_file()), "Unsafe report")
    protected = [artifact, artifact.with_name("build-boundary.json")]
    if tools:
        protected += [tools / "aapt"]
        require(not path.resolve().is_relative_to(tools.resolve()), "Unsafe report")
    for source in protected:
        require(path.resolve() != source.resolve() and not (path.exists() and source.exists() and path.samefile(source)), "Report aliases artifact/tool")
    for directory in ("src", "scripts", "android", "node_modules"):
        require(not path.resolve().is_relative_to((ROOT / directory).resolve()), "Unsafe report")


def report_write(path, result, artifact, tools):
    report_safe(path, artifact, tools)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(result, stream, indent=2); stream.write("\n")
        report_safe(path, artifact, tools)
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--build-tools", type=Path)
    parser.add_argument("--expected-package")
    parser.add_argument("--expected-version-code", type=int)
    parser.add_argument("--expected-version-name")
    parser.add_argument("--expected-abi")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = {"status": "blocked", "scope": "static packaging only; signature/native provenance/device not assessed"}
    safe = False
    try:
        if args.report:
            report_safe(args.report, args.artifact, args.build_tools)
            report_write(args.report, result, args.artifact, args.build_tools)
            safe = True
        if args.artifact.suffix == ".apk":
            result.update(verify_apk(args.artifact, args))
        else:
            result.update(verify_bundle(args.artifact.read_bytes(), args.artifact.with_name("build-boundary.json").read_bytes()))
        result["status"] = "static_packaging_pass"
    except (Blocked, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    if safe:
        try:
            report_write(args.report, result, args.artifact, args.build_tools)
        except (Blocked, OSError) as error:
            result["status"] = "blocked"; result["error"] = "Report write failed: " + str(error)
    print(json.dumps(result, sort_keys=True))
    return int(result["status"] != "static_packaging_pass")


if __name__ == "__main__":
    sys.exit(main())
