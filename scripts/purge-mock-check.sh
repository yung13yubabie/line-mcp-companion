#!/bin/bash
# Static production boundary, including complete APK assets/DEX and explicit metadata.
set -euo pipefail
exec python3 "$(dirname "$0")/production-artifact.py" "$@"
