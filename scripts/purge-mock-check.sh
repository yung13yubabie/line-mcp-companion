#!/bin/bash
# 確認 release 產物裡完全沒有 mock 資料（bundle 或 APK 皆可）。有就失敗。
set -euo pipefail
f=${1:?usage: purge-mock-check.sh bundle-or-apk}
t=""
cleanup() { if [[ -n "$t" ]]; then rm -rf -- "$t"; fi; }
trap cleanup EXIT
if [[ ! -f "$f" || ! -r "$f" ]]; then
  echo "FAIL: missing or unreadable artifact: $f" >&2
  exit 1
fi
if [[ "$f" == *.apk ]]; then
  t=$(mktemp -d)
  if ! unzip -p "$f" 'assets/nodeapp/main.mjs' > "$t/main.mjs"; then
    echo "FAIL: APK has no readable assets/nodeapp/main.mjs" >&2
    exit 1
  fi
  f="$t/main.mjs"
fi
if [[ ! -s "$f" || ! -r "$f" ]]; then
  echo "FAIL: missing, empty, or unreadable main bundle: $f" >&2
  exit 1
fi
bad=0
for pat in LMA_MOCK_DATA_v1 LMA_MOCK_AI_v1 u_mock_ 社區住戶交流群 c_mock_ MockAiProvider.calls 滷肉; do
  if grep -F -q -- "$pat" "$f"; then
    echo "FAIL: mock marker '$pat' found in $f"
    bad=1
  else
    result=$?
    if [[ $result -gt 1 ]]; then
      echo "FAIL: unable to inspect main bundle: $f" >&2
      exit 1
    fi
  fi
done
if [[ $bad -eq 0 ]]; then echo "OK: no mock data in $f"; fi
exit "$bad"
