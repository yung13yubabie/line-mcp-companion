#!/bin/bash
# 交叉編譯 Node 24 for Android（NDK r27d, API 29）。用法：./build-node-android.sh arm64|x86_64 [jobs]
set -euo pipefail
ARCH=$1; JOBS=${2:-8}
W=/workspace/line-mcp-app/node-android-work
NDK=$W/android-ndk-r27d
SRC=$W/src-$ARCH
[ -d "$SRC" ] || { mkdir -p "$SRC" && tar xf $W/node-v24.22.3.tar.xz -C "$SRC" --strip-components=1; }
cd "$SRC"
export CC_host=gcc CXX_host=g++ AR_host=ar LINK_host=g++
[ "${FRESH:-0}" = 1 ] && rm -rf out
# Android 上 zlib 的 android_getCpuFeatures 需要 NDK cpufeatures；改用 Linux 的 getauxval 路徑
sed -i "s/ARMV8_OS_ANDROID/ARMV8_OS_LINUX/g" deps/zlib/zlib.gyp
python3 $W/patch-v8-gyp.py "$SRC"
./android-configure "$NDK" 29 "$ARCH"
make -j"$JOBS"
ls -la out/Release/node
file out/Release/node
echo "BUILD_OK $ARCH"
