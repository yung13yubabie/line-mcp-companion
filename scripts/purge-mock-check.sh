#!/bin/bash
# 確認 release 產物裡完全沒有 mock 資料（bundle 或 APK 皆可）。有就失敗。
set -euo pipefail
f=$1
if [[ "$f" == *.apk ]]; then t=$(mktemp -d); unzip -q -o "$f" 'assets/nodeapp/*' -d "$t"; f="$t/assets/nodeapp/main.mjs"; fi
bad=0
for pat in LMA_MOCK_DATA_v1 u_mock_ 林家家族群組 c_mock_; do
  if grep -q "$pat" "$f"; then echo "FAIL: mock marker '$pat' found in $f"; bad=1; fi
done
[ $bad = 0 ] && echo "OK: no mock data in $f"
exit $bad
