# -*- coding: utf-8 -*-
"""tmp_g1_step7b.py — churn 运行画像: blr/br 目标热点 + 注入值来源内存地址.

目标: 判断流注入 S 是否由一个独立 schedule 函数生成 (范围缩小的关键).
"""
import os
import sys
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa: E402
from decrypt_e import EDecryptor, ISBOX, xr, _gmul  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
SITES = [DEV_BASE + o for o in (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
                                0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]

d = EDecryptor()
d._oracle()
uc = d._uc

K = bytes(range(0x05, 0x15))
iv = K[::-1]

# ---- 画像 hook: 记录 PC 序列 (块0 churn ≈ 300k 指令) ----
pcs = collections.deque(maxlen=400000)
h_all = uc.hook_add(unicorn.UC_HOOK_CODE,
                    lambda u_, a, s, ud: pcs.append(a),
                    begin=DEV_BASE, end=DEV_BASE + 0x400000)

d._cap.clear()
d._enc_big(bytes(32), K, iv)

uc.hook_del(h_all)
print("记录 PC 数: %d" % len(pcs))

# blr/br 位置: 离线反汇编查 (PC+4 = 返回点 → 目标)
import capstone
import struct
b = open(os.path.join(HERE, "..", "libcore.so"), "rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

seq = list(pcs)
# 间接跳转: PC 落点的前一条是 blr/br —— 用返回地址前 4 字节反汇编
targets = collections.Counter()
for i in range(1, len(seq)):
    prev = seq[i - 1]
    if seq[i] != prev + 4:          # 非顺序执行 = 跳转落点
        # 读取 prev 处指令判断是否 blr/br (跳转源)
        off = prev - DEV_BASE
        if 0 <= off < len(b):
            code = b[off:off + 4]
            ins = next(md.disasm(code, prev), None)
            if ins and ins.mnemonic in ("blr", "br"):
                targets[seq[i]] += 1

print("间接跳转次数: %d, 不同目标: %d" % (sum(targets.values()), len(targets)))
print("=== blr/br 目标 top15 ===")
for t, c in targets.most_common(15):
    print("  0x%x: %d 次" % (t, c))

# 区间热点 (2KB 粒度)
hot = collections.Counter(p // 2048 * 2048 for p in seq)
print("=== 执行热点区间 top12 (2KB) ===")
for a, c in hot.most_common(12):
    print("  0x%x: %d (%.1f%%)" % (a, c, 100.0 * c / len(seq)))
