#!/usr/bin/env bash
# 构建 src/web 的 React 前端，并同步到 src/app/www（Capacitor 的 webDir）
#
# 关键：注入 VITE_API_BASE 指向**设备本机**的 Kotlin 桥（JcyBridgeServer，127.0.0.1:8792）。
# WebView 的页面源是 http://localhost，相对路径 /api/... 会打到 localhost（无桥），
# 所以 App 包必须走绝对地址。浏览器开发态不设这个变量，继续走 Vite 反代。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$HERE")"        # src/app
SRC_DIR="$(dirname "$APP_DIR")"     # src
WEB_DIR="$SRC_DIR/web"              # src/web
OUT_DIR="$APP_DIR/www"              # src/app/www

# 与 JcyBridgeServer.PORT 保持一致
export VITE_API_BASE="${VITE_API_BASE:-http://127.0.0.1:8792}"

if [ ! -d "$WEB_DIR" ]; then
  echo "找不到前端目录: $WEB_DIR" >&2
  exit 1
fi

echo "构建 React 前端 ($WEB_DIR) ..."
echo "  VITE_API_BASE = $VITE_API_BASE"
cd "$WEB_DIR"
if [ ! -d node_modules ]; then
  npm install
fi
npm run build

echo "同步构建产物到 $OUT_DIR ..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cp -r "$WEB_DIR/dist/." "$OUT_DIR/"

echo "完成。产物条目数：$(find "$OUT_DIR" -type f | wc -l)"
