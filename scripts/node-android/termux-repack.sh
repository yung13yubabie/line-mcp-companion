#!/usr/bin/env bash
# Compatibility entry point. Arbitrary extracted package folders are no longer accepted.
set -euo pipefail
runtime_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$runtime_script_dir/native-runtime.py" prepare "$@"
