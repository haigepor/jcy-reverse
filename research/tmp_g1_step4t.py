# -*- coding: utf-8 -*-
"""tmp_g1_step4t.py — 基准校验：K=30..3f 的收割应复现 step4q 结构。"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2, UC_ARM64_REG_PC  # noqa: E402
from decrypt_e import EDecryptor, ISBOX, xr  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
PREP = DEV_BASE + 0x2D9AD4
SITES = [DEV_BASE + o for o in
         (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
          0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]


def harvest(K, nblk):
    d = EDecryptor()
    d.calibrate(K, nblk)
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
    d._enc_big(bytes(16 * nblk), K, K[::-1])
    uc.hook_del(h)
    uc.context_restore(ctx[0])
    for base, size, data in mem0:
        try:
            uc.mem_write(base, data)
        except Exception:
            pass
    uc.ctl_flush_tb()

    st = {"pending": None, "tr": [], "n": 0}

    def on_mul(uc_, address, size, ud):
        st["pending"] = uc_.reg_read(UC_ARM64_REG_X2) & 0xFF

    def on_site(uc_, address, size, ud):
        if st["pending"] is None:
            return
        st["tr"].append(st["pending"])
        st["pending"] = None
        st["n"] += 1
        if st["n"] >= 288 * nblk:
            uc_.emu_stop()

    uc.hook_add(unicorn.UC_HOOK_CODE, on_mul, begin=MUL, end=MUL + 3)
    for s in SITES:
        uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=s, end=s + 3)
    d._cap.clear()
    try:
        uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=300 * 1000000,
                     count=15_000_000)
    except Exception:
        pass
    return st["tr"]


def cols_of(tr, blk):
    out = []
    for g in range(36):
        by = tr[blk * 288 + g * 8: blk * 288 + g * 8 + 8]
        out.append((by[0], by[1], by[3], by[5]))
    return out


def extract_rks(tr, blk):
    from decrypt_e import _gmul
    cols = cols_of(tr, blk)
    rks = {}
    for r in range(8):
        mc = []
        for c in range(4):
            a, b, cc, dd = cols[r * 4 + c]
            mc.extend((_gmul(a, 2) ^ _gmul(b, 3) ^ cc ^ dd,
                       a ^ _gmul(b, 2) ^ _gmul(cc, 3) ^ dd,
                       a ^ b ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                       _gmul(a, 3) ^ b ^ cc ^ _gmul(dd, 2)))
        nxt = [v for c in range(4) for v in cols[(r + 1) * 4 + c]]
        preSB = bytes(ISBOX[v] for v in nxt)
        rks[r + 1] = xr(bytes(mc), preSB)
    return rks


if __name__ == "__main__":
    K = bytes(range(0x30, 0x40))
    tr = harvest(K, 1)
    cols = cols_of(tr, 0)
    s = bytes(v for col in cols[0:4] for v in col)
    preSB = bytes(ISBOX[v] for v in s)
    print("preSB0 =", preSB.hex())
    print("预期   = 0f0f0f0f0a000a0005050505000a000a")
    rks = extract_rks(tr, 0)
    print("rk1 =", rks[1].hex())
    print("预期= 16ab56f2228f71c51ab65aef269a75d0")
    iv = K[::-1]
    print("preSB^iv =", xr(preSB, iv).hex())
