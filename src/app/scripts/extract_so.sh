#!/usr/bin/env bash
# 从原版 APK 提取 libcore.so 到 android/app/src/main/jniLibs/arm64-v8a/
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$HERE")"        # src/app
SRC_DIR="$(dirname "$APP_DIR")"     # src
PROJ_DIR="$(dirname "$SRC_DIR")"    # 项目根

APK="${1:-$PROJ_DIR/assets/apk/base.apk}"
DEST="$APP_DIR/android/app/src/main/jniLibs/arm64-v8a"

if [ ! -f "$APK" ]; then
  echo "找不到 APK: $APK" >&2
  exit 1
fi

mkdir -p "$DEST"

echo "从 $APK 提取 libcore.so ..."
python - "$APK" "$DEST" <<'PY'
import sys, zipfile, os, hashlib
apk, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(apk) as z:
    name = "lib/arm64-v8a/libcore.so"
    data = z.read(name)
    out = os.path.join(dest, "libcore.so")
    with open(out, "wb") as f:
        f.write(data)
    print("  写出 %s  (%d 字节)" % (out, len(data)))
    print("  sha256 %s" % hashlib.sha256(data).hexdigest())
PY

echo "完成。"
