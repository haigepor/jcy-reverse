# -*- coding: utf-8 -*-
"""tmp_w1_fastcal_test.py — 验证 skip-rounds 快速标定：把轮驱动 0x2DA498 补成 ret，
对照慢标定的 CONST/Cb 是否逐字节一致，并测提速比。

依据：CONST_b/Cb_b 与明文、密文链无关（e2e-decrypt.md 已实测）→ 轮函数输出
不影响 tweak 生成器状态，补丁后提取的 CONST 仍是真值。
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, os.path.join(HERE, "captures", "rsa_scan"))

from decrypt_e import EDecryptor, expand, xr  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

RET = bytes.fromhex("c0035fd6")     # arm64 ret
DRIVER = DEV_BASE + 0x2DA498


def fast_const(d, K, nblk):
    """补丁轮驱动为 ret → 跑 dummy 加密 → 提取 CONST（不依赖 C 的真值）。"""
    o = d._oracle()
    uc = o.s.e.uc
    orig = o.s.e.rd(DRIVER, 4)
    assert orig != RET, "驱动入口已是 ret？"
    uc.mem_write(DRIVER, RET)
    try:
        C = d._determine_C(K)          # 注意：此调用也被补丁，C 是错的——仅占位
        rk = expand(K)
        iv = K[::-1]
        dummy = bytes(16 * nblk)
        d._cap.clear()
        t0 = time.time()
        ctd = d._enc_big(dummy, K, iv)
        dt = time.time() - t0
        xs = [bytes(T_ := tuple(__import__("decrypt_e").T(list(d._cap[i]))))
              for i in range(0, len(d._cap), 2)]
        CONST = []
        for b in range(min(nblk, len(xs))):
            xb = xs[b]
            prev = ctd[b * 16 - 16:b * 16] if b else iv
            CONST.append(bytes(xr(xr(xb, dummy[b * 16:(b + 1) * 16]), prev)))
    finally:
        uc.mem_write(DRIVER, orig)
    return CONST, ctd, dt


def main():
    d = EDecryptor()
    K = b"T9Z19J7NCY9S9X58"          # 真实样本用过的 K16（ASCII 16B）
    nblk = 8

    # ---- 慢标定（黄金参照）----
    t0 = time.time()
    C, rk, CONST_g, Cb_g = d.calibrate(K, nblk)
    t_slow = time.time() - t0
    print("[慢标定] %.3fs  (%.4fs/块)" % (t_slow, t_slow / nblk))

    # ---- 快标定（补丁轮驱动）----
    d._cache.clear()
    CONST_f, ctd, t_fast_run = fast_const(d, K, nblk)
    print("[快标定] dummy 运行 %.3fs  body_len=%d  捕获=%d"
          % (t_fast_run, len(ctd), len(d._cap)))

    ok_len = len(CONST_f) >= nblk
    match = ok_len and all(CONST_f[b] == bytes(CONST_g[b]) for b in range(nblk))
    print("CONST[0]==0 ?", CONST_f[0] == bytes(16) if CONST_f else "-")
    print("CONST 全一致 :", match)
    if not match and ok_len:
        for b in range(nblk):
            if CONST_f[b] != bytes(CONST_g[b]):
                print("  b=%d\n    慢=%s\n    快=%s" % (b, bytes(CONST_g[b]).hex(), CONST_f[b].hex()))
                break

    # Cb 用 V15 不变式从 CONST 推导，与慢标定实测 Cb 对照
    if ok_len and len(CONST_f) >= nblk:
        Cb_f = [bytes(xr(CONST_f[b + 1], CONST_f[1])) for b in range(nblk - 1)]
        cb_match = all(Cb_f[b] == bytes(Cb_g[b]) for b in range(nblk - 1))
        print("Cb(不变式推导) 全一致 :", cb_match)

    if match:
        print("\n✔ 验证通过：skip-rounds 标定与慢标定等价")
        print("  每块成本: %.4fs -> ~%.4fs（含固定开销，块数越大越接近纯轮函数占比）"
              % (t_slow / nblk, t_fast_run / nblk))


if __name__ == "__main__":
    main()
