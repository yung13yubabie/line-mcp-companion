#!/usr/bin/env bash
# Prepare both APK ABIs from the reviewed, signed snapshot and pinned output hashes.
set -euo pipefail
runtime_repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 "$runtime_repo/scripts/node-android/native-runtime.py" prepare "$@"
