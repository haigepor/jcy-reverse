# -*- coding: utf-8 -*-
"""dump_image.py — 全域 trace 唯一 PC 采样 + 内存镜像 dump + 输入装配."""
import os
import sys
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402
from decrypt_e import _b64len  # noqa: E402

NBLK = 128
K = bytes(range(0x05, 0x15))
iv = K[::-1]
PT = bytes(16 * NBLK)  # dummy 全零明文 (与 lean harvest 相同)

d = EDecryptor()
d._oracle()
s = d._o.s
e = s.e

# ---- 输入装配 (复刻 _enc_big 的准备, 不 emu) ----
e.fix_long_string(0x688130, K)
e.fix_long_string(0x688148, iv)
L = next(c for c in range(1, len(PT) + 1) if _b64len(c) == len(PT))
s._cur[0] = PT
s._out.clear()
inp = e.mkstr(b"\x00" * L)
sret = s.sret
print("inp=0x%x sret=0x%x L=%d" % (inp, sret, L))

# ---- 全域 PC 覆盖采样 (128 块) ----
uc = d._uc
import unicorn  # noqa: E402
covered = set()
hooks = []


def cb(u_, a, sz, ud):
    covered.add(a)


h = unicorn.UC_HOOK_CODE
hk = uc.hook_add(h, cb, begin=DEV_BASE, end=DEV_BASE + 0x400000)

from authgen import OFF_PIPE, OFF_AFTER_A1, OFF_AFTER_E  # noqa: E402

ctd = d._enc_big(PT, K, iv)
uc.hook_del(hk)
print("全域唯一 PC: %d" % len(covered))
print("ctd 前 32 字节: %s" % ctd[:32].hex())

# ---- 内存镜像 dump ----
regions = [(r[0], r[1]) for r in uc.mem_regions()]
outp = os.path.join(HERE, "engine_c", "image.bin")
with open(outp, "wb") as f:
    f.write(struct.pack("<I", len(regions)))
    for lo, hi in regions:
        size = hi - lo + 1
        f.write(struct.pack("<QQ", lo, size))
        f.write(uc.mem_read(lo, size))
print("镜像: %d 区间 → %s (%.1f MB)" % (len(regions), outp,
      sum(h - l + 1 for l, h in regions) / 1048576))

# ---- 辅助常量 ----
meta = {
    "inp": inp, "sret": sret, "L": L, "nblk": NBLK, "K": K.hex(), "iv": iv.hex(),
    "OFF_PIPE": OFF_PIPE, "OFF_AFTER_A1": OFF_AFTER_A1, "OFF_AFTER_E": OFF_AFTER_E,
    "cur_len": len(PT),
}
import json  # noqa: E402
json.dump(meta, open(os.path.join(HERE, "engine_c", "meta.json"), "w"), indent=1)
print("meta:", meta)
open(os.path.join(HERE, "reports", "pc_cover_all.txt"), "w").write(
    "\n".join(hex(p - DEV_BASE) for p in sorted(covered)))
print("PC 集已存 reports/pc_cover_all.txt")
