# -*- coding: utf-8 -*-
"""tmp_w1_profile3.py — 补丁后标定运行的准确指令剖析（hook 先于任何执行安装）。"""
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, os.path.join(HERE, "captures", "rsa_scan"))

from decrypt_e import EDecryptor, expand, xr, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

RET = bytes.fromhex("c0035fd6")
DRIVER = DEV_BASE + 0x2DA498

FUNCS = {
    0x2D7440: "block_loop",
    0x2D9AD4: "extract",
    0x2D9ED0: "neon(tweak)",
    0x2DA1C8: "reorder",
    0x2DA498: "round_driver",
}


def bucket(off):
    best = None
    for start, name in FUNCS.items():
        if off >= start and (best is None or start > best[0]):
            best = (start, name)
    return best[1] if best and off - best[0] < 0x4000 else None


def main():
    d = EDecryptor()
    o = d._oracle()                          # 仅 boot，不跑管线
    uc = o.s.e.uc

    orig = o.s.e.rd(DRIVER, 4)
    uc.mem_write(DRIVER, RET)                # 先补丁

    import unicorn
    counts = Counter()
    total = [0]

    def prof(u, address, size, ud):
        counts[address - DEV_BASE] += 1
        total[0] += 1

    h = uc.hook_add(unicorn.UC_HOOK_CODE, prof, begin=DEV_BASE, end=DEV_BASE + 0x800000)

    K = os.urandom(16)
    nblk = 8
    d._cap.clear()
    t0 = time.time()
    ctd = d._enc_big(bytes(16 * nblk), K, K[::-1])   # 首次执行（惰性初始化也在此跑）
    dt = time.time() - t0
    ncap = len(d._cap)
    uc.hook_del(h)
    uc.mem_write(DRIVER, orig)

    print("[补丁后·首跑] nblk=%d %.2fs  instr=%d  %.0f/块  捕获=%d  body=%dB"
          % (nblk, dt, total[0], total[0] / nblk, ncap, len(ctd)))
    agg = Counter()
    for off, c in counts.items():
        agg[bucket(off) or "other"] += c
    print("\n== 按函数段聚合 ==")
    for name, c in agg.most_common(12):
        print("  %-14s %10d  %5.1f%%  (%.0f/块)" % (name, c, 100.0 * c / total[0], c / nblk))
    print("\n== Top 40 PC 偏移 ==")
    for off, c in counts.most_common(40):
        print("  %#08x  %8d  %s" % (off, c, bucket(off) or "-"))


if __name__ == "__main__":
    main()
