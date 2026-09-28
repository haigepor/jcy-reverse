#!/bin/sh
# ROLLBACK.sh - 恢复 pristine 状态
# 用法: sh ROLLBACK.sh [工作目录]
# 功能:
#   1) 用原始样本 apk\base.apk 覆盖一切"已打补丁"的交付名称
#   2) 删除构建产物与中间目录, 仅保留 {工具链, 补丁脚本, diff, 验证记录}
set -e
DIR="${1:-.}"
cd "$DIR"

PRISTINE="apk/base.apk"
TARGET="out/base_adfree_final-aligned-debugSigned.apk"

if [ ! -f "$PRISTINE" ]; then
  echo "[ROLLBACK] 找不到原始样本 $PRISTINE; 中止" >&2
  exit 1
fi

echo "[ROLLBACK] 1/3 用原始样本覆盖交付 APK"
cp -f "$PRISTINE" "$TARGET"
cp -f "$PRISTINE" "out/base_restored.apk"

echo "[ROLLBACK] 2/3 移除补丁构建产物与中间目录"
rm -f  out/base_adfree_final-aligned-debugSigned.apk.idsig
rm -rf out/base_nores out/base_smali_patched out/base_smali out/base_decoded out/jadx_src

echo "[ROLLBACK] 3/3 校验恢复后的哈希"
python - <<'PY'
import hashlib, sys
def h(p):
    with open(p,'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()
BASE='AC170C12F20107533342BC32798564FB13BDA95EB0624ABB64DF30F886C5CBB9'
a=h('apk/base.apk'); b=h('out/base_restored.apk'); c=h('out/base_adfree_final-aligned-debugSigned.apk')
print('pristine :', a)
print('restored :', b)
print('delivered:', c)
sys.exit(0 if (a==b==c==BASE) else 1)
PY

echo "[ROLLBACK] OK: 已恢复原始字节 (保留 out/DIFF_smali.patch, out/VERIFICATION.txt 作审计)"
