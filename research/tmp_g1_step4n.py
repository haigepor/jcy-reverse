# -*- coding: utf-8 -*-
"""tmp_g1_step4n.py — 读 AES 状态演化：每组首乘读 [x0] 16B，推轮密钥，对照 expand(K)。"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_PC,
)
from decrypt_e import EDecryptor, expand, xr, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
PREP = DEV_BASE + 0x2D9AD4
BOUND = DEV_BASE + 0x2DA498
SITE0 = DEV_BASE + 0x2D32AC          # 每组第 1 个乘法的返回点
K = bytes(range(0x30, 0x40))
NBLK = 2

d = EDecryptor()
_, _, CONSTg, _ = d.calibrate(K, NBLK)
golden = [bytes(c) for c in CONSTg]

d._o = None
d._uc = None
d._oracle()
uc = d._uc

ctx = [None]
mem0 = []


def on_snap(uc_, address, size, ud):
    if ctx[0] is not None:
        return
    ctx[0] = uc_.context_save()
    for rbase, rend, _perms in uc_.mem_regions():
        sz = rend - rbase
        if sz > 64 * 1024 * 1024:
            continue
        try:
            mem0.append((rbase, sz, bytes(uc_.mem_read(rbase, sz))))
        except Exception:
            pass


h = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 3)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, K[::-1])
uc.hook_del(h)

uc.context_restore(ctx[0])
for base, size, data in mem0:
    try:
        uc.mem_write(base, data)
    except Exception:
        pass
uc.ctl_flush_tb()

st = {"groups": [], "lr": 0}
nfires = [0]


def on_mul(uc_, address, size, ud):
    lr = uc_.reg_read(UC_ARM64_REG_X30)
    if lr == SITE0:                    # 组首乘
        x0 = uc_.reg_read(UC_ARM64_REG_X0)
        st["groups"].append(bytes(uc_.mem_read(x0, 16)))
    nfires[0] += 1
    if nfires[0] >= 288 * 3:           # 采 3 块的量
        uc_.emu_stop()


h_mul = uc.hook_add(unicorn.UC_HOOK_CODE, on_mul, begin=MUL, end=MUL + 3)
d._cap.clear()
try:
    uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=180 * 1000000,
                 count=8_000_000)
except Exception:
    pass

G = st["groups"]
print("采集组数=%d (期望 36/块 × 3)" % len(G))
rk = expand(K)

print("\n=== 每 9 组（=1 轮）状态 + 相邻 XOR 掩码 ===")
for gi in range(0, min(len(G), 36 * 2)):
    s = G[gi]
    line = "g%02d state=%s" % (gi, s.hex())
    if gi > 0:
        line += "  xor_prev=%s" % xr(s, G[gi - 1]).hex()
    print(line)

print("\n=== 对照 expand(K) 轮密钥 ===")
for r in range(10):
    print("rk[%d] = %s" % (r, bytes(rk[r]).hex()))

# 初始状态（g0 前）与 golden 对照
print("\ngolden[0]=%s golden[1]=%s" % (golden[0].hex(), golden[1].hex()))
json.dump([g.hex() for g in G],
          open(os.path.join(HERE, "reports", "aes_state_trace.json"), "w"))
print("已存 reports/aes_state_trace.json")
