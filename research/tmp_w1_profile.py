# -*- coding: utf-8 -*-
"""tmp_w1_profile.py — 剖析标定运行每块指令分布在哪些函数段。

对 8 块 dummy 加密开全镜像 UC_HOOK_CODE 计数（只为剖析，生产路径不装），
按 PC 偏移聚合到已知函数与热点区，回答「skip-rounds 能省多少」。
"""
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, os.path.join(HERE, "captures", "rsa_scan"))

from decrypt_e import EDecryptor  # noqa: E402

# 已知函数入口（libcore 偏移）
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
    return best[1] if best and off - best[0] < 0x8000 else None


def main():
    d = EDecryptor()
    t0 = time.time()
    o = d._oracle()
    print("[boot] EOracle+Emu4 %.2fs" % (time.time() - t0), flush=True)

    import unicorn
    from authgen import DEV_BASE
    from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa: F401

    counts = Counter()
    total = [0]

    def prof(uc, address, size, ud):
        counts[address - DEV_BASE] += 1
        total[0] += 1

    uc = o.s.e.uc
    h = uc.hook_add(unicorn.UC_HOOK_CODE, prof,
                    begin=DEV_BASE, end=DEV_BASE + 0x800000)
    K = os.urandom(16)
    nblk = 8
    t0 = time.time()
    d.calibrate(K, nblk)
    dt = time.time() - t0
    uc.hook_del(h)
    print("[calib+hook] nblk=%d %.2fs  total_instr=%d  %.0f instr/块"
          % (nblk, dt, total[0], total[0] / nblk), flush=True)

    # 聚合：已知函数 / 热点区 / 其余
    agg = Counter()
    top_raw = counts.most_common(24)
    for off, c in counts.items():
        b = bucket(off)
        agg[b or "other"] += c
    print("\n== 按函数段聚合 ==")
    for name, c in agg.most_common():
        print("  %-14s %10d  %5.1f%%  (%.0f/块)" % (name, c, 100.0 * c / total[0], c / nblk))
    print("\n== Top PC 偏移 ==")
    for off, c in top_raw:
        print("  %#08x  %8d  %s" % (off, c, bucket(off) or "-"))


if __name__ == "__main__":
    main()
