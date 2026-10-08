#!/usr/bin/env bash
# 把 囧次元/{research,tools} 的内容逐项搬进 jcy-reverse/
cd /c/Users/haige/Desktop/instruct || exit 1
OLD="囧次元"; NEW="jcy-reverse"
mkdir -p "$NEW/research" "$NEW/tools"
shopt -s dotglob nullglob

move_all() {
  local src="$1" dst="$2" label="$3"
  echo "=== $label ==="
  for item in "$src"/*; do
    [ -e "$item" ] || continue
    local b; b=$(basename "$item")
    if mv "$item" "$dst/" 2>/dev/null; then
      echo "  OK   $b"
    else
      echo "  FAIL $b"
    fi
  done
}

move_all "$OLD/research" "$NEW/research" "research 子项"
move_all "$OLD/tools" "$NEW/tools" "tools 子项"

echo ""
echo "=== 残留 ==="
ls -A "$OLD/research" 2>/dev/null | head
ls -A "$OLD/tools" 2>/dev/null | head
echo "=== 旧壳 ==="
ls -A "$OLD" 2>/dev/null | head
echo "=== 搬移后体积 ==="
for d in "$NEW/research" "$NEW/tools"; do
  s=$(find "$d" -type f -printf "%s\n" 2>/dev/null | awk '{t+=$1} END {printf "%.1f", t/1048576}')
  echo "  $d : ${s:-0} MB"
done
echo "=== DONE ==="
