#!/usr/bin/env bash
# Optional source-build investigation; output is NOT automatically approved for APK use.
# Usage: LMA_NODE_ARCHIVE=... LMA_NDK_ARCHIVE=... ./build-node-android.sh arm64|x86_64 [jobs]
set -euo pipefail
runtime_arch=${1:?usage: build-node-android.sh arm64|x86_64 [jobs]}
runtime_jobs=${2:-8}
case "$runtime_arch" in arm64|x86_64) ;; *) echo "Unsupported architecture" >&2; exit 2 ;; esac
[[ "$runtime_jobs" =~ ^[1-9][0-9]*$ ]] || { echo "jobs must be a positive integer" >&2; exit 2; }
runtime_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
runtime_repo=$(cd -- "$runtime_script_dir/../.." && pwd)
runtime_node_archive=${LMA_NODE_ARCHIVE:?Set LMA_NODE_ARCHIVE to the official node-v24.22.3.tar.xz archive}
runtime_ndk_archive=${LMA_NDK_ARCHIVE:?Set LMA_NDK_ARCHIVE to the official android-ndk-r27d-linux.zip archive}
# Node SHA-256 comes from official SHASUMS256.txt. The SDK repository publishes SHA-1 for this NDK archive.
python3 - "$runtime_node_archive" "$runtime_ndk_archive" <<'PY'
import hashlib
from pathlib import Path
import sys
for filename, algorithm, expected in (
    (sys.argv[1], "sha256", "48ca3aa8a9b02133356922ef4fc80200e00598c80a4ef446f7c39a459222593d"),
    (sys.argv[2], "sha1", "22105e410cf29afcf163760cc95522b9fb981121"),
):
    checksum = hashlib.new(algorithm)
    with Path(filename).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(chunk)
    if checksum.hexdigest() != expected:
        raise SystemExit("Source/toolchain archive checksum mismatch: " + Path(filename).name)
PY
runtime_work=${LMA_NODE_WORK:-"$runtime_repo/build/node-from-source"}
mkdir -p -- "$runtime_work"
runtime_work=$(cd -- "$runtime_work" && pwd)
runtime_build=$(mktemp -d "$runtime_work/node-v24.22.3-$runtime_arch.XXXXXXXX")
runtime_source="$runtime_build/source"
runtime_ndk="$runtime_build/ndk/android-ndk-r27d"
mkdir -p -- "$runtime_source" "$runtime_build/ndk" "$runtime_build/artifacts"
tar --extract --file "$runtime_node_archive" --directory "$runtime_source" --strip-components=1 --no-same-owner --no-same-permissions
unzip -q "$runtime_ndk_archive" -d "$runtime_build/ndk"
rg -q '^Pkg.Revision = 27\.3\.13750724$' "$runtime_ndk/source.properties" || { echo "Unexpected NDK revision" >&2; exit 1; }
cd -- "$runtime_source"
export CC_host=gcc CXX_host=g++ AR_host=ar LINK_host=g++
# Android zlib requires NDK cpufeatures; select the existing Linux getauxval path.
sed -i 's/ARMV8_OS_ANDROID/ARMV8_OS_LINUX/g' deps/zlib/zlib.gyp
python3 "$runtime_script_dir/patch-v8-gyp.py" "$runtime_source"
./android-configure "$runtime_ndk" 29 "$runtime_arch"
make -j"$runtime_jobs"
cp out/Release/node "$runtime_build/artifacts/libnode.so"
case "$runtime_arch" in arm64) runtime_triple=aarch64-linux-android ;; x86_64) runtime_triple=x86_64-linux-android ;; esac
cp "$runtime_ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/$runtime_triple/libc++_shared.so" "$runtime_build/artifacts/libc++_shared.so"
python3 - "$runtime_build/artifacts" "$runtime_arch" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
directory = Path(sys.argv[1])
manifest = {
    "approval": "NOT APPROVED for APK packaging; independent runtime and dependency review required",
    "node_version": "24.22.3", "ndk_version": "27.3.13750724", "android_api": 29,
    "architecture": sys.argv[2],
    "outputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob("*.so"))},
}
(directory / "source-build.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY
echo "Unapproved source-build artifacts: $runtime_build/artifacts"
