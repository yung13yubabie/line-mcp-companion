#!/bin/bash
# Termux nodejs-lts → APK jniLibs（備案）：改 DT_NEEDED 成 lib*.so 名稱、RUNPATH=$ORIGIN
set -euo pipefail
P=root/data/data/com.termux/files/usr
OUT=${1:-jnilibs-arm64}
rm -rf $OUT && mkdir -p $OUT
declare -A MAP=( [libz.so.1]=libtx_z.so [libcares.so]=libtx_cares.so [libsqlite3.so]=libtx_sqlite3.so [libsqlite3.so.0]=libtx_sqlite3.so
  [libcrypto.so.3]=libtx_crypto.so [libssl.so.3]=libtx_ssl.so [libicui18n.so.79]=libtx_icui18n.so [libicuuc.so.79]=libtx_icuuc.so
  [libicudata.so.79]=libtx_icudata.so [libc++_shared.so]=libtx_cxx.so )
cp $P/bin/node $OUT/libnode.so
for k in "${!MAP[@]}"; do [ -e "$P/lib/$k" ] && cp -L "$P/lib/$k" "$OUT/${MAP[$k]}"; done
for f in $OUT/*.so; do
  chmod 755 $f
  for k in "${!MAP[@]}"; do patchelf --replace-needed "$k" "${MAP[$k]}" "$f" 2>/dev/null || true; done
  n=$(basename $f); [ "$n" != libnode.so ] && patchelf --set-soname "$n" "$f"
  patchelf --set-rpath '$ORIGIN' "$f"
done
ls -la $OUT
