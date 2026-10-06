# -*- coding: utf-8 -*-
"""tmp_g1_step4o.py — 乘法 I/O 全收割 + 8 调用点反汇编 → 验证 GF 乘与组合逻辑。"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X30, UC_ARM64_REG_PC  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
PREP = DEV_BASE + 0x2D9AD4
SITES = [DEV_BASE + o for o in
         (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
          0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]
K = bytes(range(0x30, 0x40))
NBLK = 1

d = EDecryptor()
d.calibrate(K, NBLK)
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

st = {"calls": [], "pending": None, "io": [], "n": 0}


def on_mul(uc_, address, size, ud):
    st["pending"] = (
        uc_.reg_read(UC_ARM64_REG_X30) - DEV_BASE,
        uc_.reg_read(UC_ARM64_REG_X1) & 0xFF,
        uc_.reg_read(UC_ARM64_REG_X2) & 0xFF,
        uc_.reg_read(UC_ARM64_REG_X3) & 0xFF,
    )


def on_site(uc_, address, size, ud):
    if st["pending"] is None:
        return
    w0 = uc_.reg_read(UC_ARM64_REG_X0 if False else UC_ARM64_REG_X1)  # w0 占位
    # Unicorn 读 W0: 用 X0
    w0 = uc_.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF
    site, c, b, x = st["pending"]
    st["io"].append((site - DEV_BASE, c, b, x, w0 & 0xFF))
    st["pending"] = None
    st["n"] += 1
    if st["n"] >= 288:
        uc_.emu_stop()


h_mul = uc.hook_add(unicorn.UC_HOOK_CODE, on_mul, begin=MUL, end=MUL + 3)
h_sites = uc.hook_add(unicorn.UC_HOOK_CODE, on_site,
                      begin=SITES[0], end=SITES[0] + 3)
# 8 个站点分开挂钩子（范围挂钩会覆盖中间代码）
for s in SITES:
    uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=s, end=s + 3)

d._cap.clear()
try:
    uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=180 * 1000000,
                 count=8_000_000)
except Exception:
    pass

print("收割乘法 I/O %d 条" % len(st["io"]))


def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


ok = bad = 0
for site, c, b, x, r in st["io"]:
    exp = gf_mul(c, b) if c in (2, 3) else None
    if exp is None:
        continue
    if exp == r:
        ok += 1
    else:
        bad += 1
        if bad <= 8:
            print("  不匹配 site=+%#x coef=%d byte=%02x w3=%02x got=%02x exp=%02x"
                  % (site, c, b, x, r, exp))
print("GF 乘验证: ok=%d bad=%d" % (ok, bad))

print("\n=== 前 24 条 I/O（按序） ===")
for site, c, b, x, r in st["io"][:24]:
    print("  site=+%#x coef=%d byte=%02x w3=%02x → %02x" % (site, c, b, x, r))

# 8 调用点反汇编（仿真内存）
code = bytes(uc.mem_read(DEV_BASE + 0x2D3200, 0xF00))
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
print("\n=== 调用点反汇编（各 12 条） ===")
for s in SITES:
    off = s - DEV_BASE - 0x2D3200 - 6 * 4
    print("\n-- 返回点 +%#x（含前 6 条） --" % (s - DEV_BASE))
    cnt = 0
    for ins in md.disasm(code[max(0, off):off + 18 * 4],
                         DEV_BASE + 0x2D3200 + max(0, off)):
        cnt += 1
        mark = " ←" if ins.address == s else ""
        print("  +%#08x %-8s %s%s" % (ins.address - DEV_BASE, ins.mnemonic,
                                      ins.op_str, mark))
        if cnt >= 18:
            break
