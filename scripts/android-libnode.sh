#!/bin/bash
# 把 Node for Android 放進 jniLibs（二進位不進 git）
#   x86_64：NDK 交叉編譯產物（node-android-work/artifacts/x86_64）
#   arm64 ：NDK 產物若存在（artifacts/arm64）就用，否則用 Termux nodejs-lts 重新打包的備案
set -euo pipefail
W=/workspace/line-mcp-app/node-android-work
J=$(dirname "$0")/../android/app/src/main/jniLibs
rm -f $J/x86_64/*.so $J/arm64-v8a/*.so
cp $W/artifacts/x86_64/libnode.so $W/artifacts/x86_64/libc++_shared.so $J/x86_64/
if [ -f $W/artifacts/arm64/libnode.so ]; then
  cp $W/artifacts/arm64/libnode.so $W/artifacts/arm64/libc++_shared.so $J/arm64-v8a/; echo "arm64: NDK build"
else
  cp $W/termux-arm64/jnilibs-arm64/*.so $J/arm64-v8a/; echo "arm64: Termux repack (fallback)"
fi
du -sh $J/*
