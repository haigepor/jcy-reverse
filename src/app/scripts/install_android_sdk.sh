#!/usr/bin/env bash
# 安装 Android SDK 组件到 C:\Android\Sdk
set -uo pipefail
export MSYS_NO_PATHCONV=1
export JAVA_HOME="C:/Program Files/Eclipse Adoptium/jdk-21.0.10.7-hotspot"
SDK_WIN='C:\Android\Sdk'
SDKM="/c/Android/Sdk/cmdline-tools/latest/bin/sdkmanager.bat"

echo "=== 0. sdkmanager 可用性 ==="
"$SDKM" --version || { echo "sdkmanager 不可用，中止"; exit 1; }

echo "=== 1. 接受 license ==="
yes | "$SDKM" --sdk_root="$SDK_WIN" --licenses 2>&1 | tail -5

echo "=== 2. 安装组件（约 4-5 GB，耗时较长）==="
"$SDKM" --sdk_root="$SDK_WIN" \
  "platform-tools" \
  "platforms;android-35" \
  "build-tools;35.0.0" \
  "ndk;27.0.12077973" \
  "cmake;3.22.1" 2>&1 | grep -v "^\[" | tail -40

echo "=== 3. 安装结果 ==="
"$SDKM" --sdk_root="$SDK_WIN" --list_installed 2>&1 | tail -20
echo "=== 目录 ==="
ls /c/Android/Sdk/
echo "=== DONE ==="
