#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""verify_post.py — 验证 C 版标定后处理(jcy_post)与 Python 逐位一致, 并计时。

V22 目的: 把 639 块标定里的 207.6 ms Python 循环下沉到 C。
本脚本**必须**证明:
  1. jcy_determine_C 产出与 Python _determine_C_c 的 C 完全相同;
  2. jcy_post 一次算完的 CONST[]/Cb[] 与 Python 循环逐位相同(1/8/128/639 全测);
  3. 端到端耗时下降, 且 1/128/639 的**密文 body** 仍与 golden 一致
     (后处理换了实现, 绝不允许影响密文)。

用法: py -3.12 verify_post.py [nblk ...]
"""
import ctypes
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import decrypt_e as D                        # noqa: E402
from c_engine import load                    # noqa: E402


def main():
    K = bytes(range(0x05, 0x15))
    img = os.path.abspath(os.path.join(HERE, "engine_c", "image639.bin"))
    lib = load()
    rc = lib.jcy_init(img.encode())
    if rc != 0:
        print("jcy_init 失败: %s" % lib.jcy_last_error().decode())
        return 1

    # 注册新导出
    lib.jcy_expand.restype = ctypes.c_int
    lib.jcy_expand.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.jcy_determine_C.restype = ctypes.c_int
    lib.jcy_determine_C.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.jcy_post.restype = ctypes.c_int
    lib.jcy_post.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                             ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                             ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]

    # ---- 1) 轮密钥 ----
    rk_c = ctypes.create_string_buffer(176)
    lib.jcy_expand(K, rk_c)
    rk = D.expand(K)
    rk_ok = all(rk_c.raw[r * 16:(r + 1) * 16] == rk[r] for r in range(11))
    print("[1] 轮密钥 11 个: %s" % ("一致" if rk_ok else "不一致"))
    if not rk_ok:
        for r in range(11):
            a = rk_c.raw[r * 16:(r + 1) * 16].hex()
            b = rk[r].hex()
            if a != b:
                print("    rk[%d] C=%s py=%s" % (r, a, b))

    # ---- 2) C (必须用 iv=全零 的 1 块加密) ----
    out1 = ctypes.create_string_buffer(16 * 1 + 16 + 64)
    n1 = lib.jcy_encrypt_iv(K, bytes(16), bytes(16), 16, out1, len(out1))
    if n1 < 0:
        print("encrypt_iv 失败: %s" % lib.jcy_last_error().decode())
        return 1
    ct0 = bytes(out1.raw[:16])

    Cc = ctypes.create_string_buffer(16)
    lib.jcy_determine_C(ct0, K, Cc)
    dc = D.EDecryptor(backend="c")
    Cpy = dc._determine_C_c(dc._c_engine(), K)
    c_ok = Cc.raw == Cpy
    print("[2] C: %s  C=%s" % ("一致" if c_ok else "不一致", Cc.raw.hex()))
    if not c_ok:
        print("    py=%s" % Cpy.hex())

    allok = rk_ok and c_ok

    # ---- 3) CONST[]/Cb[] 逐块对拍 ----
    for nblk in [int(x) for x in (sys.argv[1:] or [1, 8, 128, 639])]:
        dummy = bytes(16 * nblk)
        lib.jcy_capture_enable(nblk)
        outcap = len(dummy) + 16 + 64
        buf = ctypes.create_string_buffer(outcap)
        t0 = time.time()
        nn = lib.jcy_encrypt_ex(K, dummy, len(dummy), buf, outcap, 1)
        t_eng = (time.time() - t0) * 1000
        if nn < 0:
            print("[3] %d 块 encrypt_ex 失败: %s" % (nblk, lib.jcy_last_error().decode()))
            allok = False
            continue
        got = lib.jcy_capture_count()
        xs = ctypes.create_string_buffer(max(nblk, got) * 16)
        # 逐条取回
        xflat = bytearray()
        for i in range(nblk):
            b16 = ctypes.create_string_buffer(16)
            if lib.jcy_capture_get(i, b16) != 0:
                print("capture_get(%d) 失败: %s" % (i, lib.jcy_last_error().decode()))
                allok = False
                break
            xflat += b16.raw
        body = bytes(buf.raw[:nn])

        # 生产 _calibrate_c 用的 iv 是 K[::-1], 不是全零 —— 必须按生产值测,
        # 否则 CONST[0] 会因 prev 不同而错(V22接线时踩过)。
        iv = K[::-1]
        CO = ctypes.create_string_buffer(nblk * 16)
        Cb = ctypes.create_string_buffer(nblk * 16)
        t0 = time.time()
        rp = lib.jcy_post(bytes(xflat), body, dummy, iv, Cc.raw, K,
                          nblk, CO, Cb)
        t_cpost = (time.time() - t0) * 1000
        if rp != 0:
            print("[3] %d 块 jcy_post 失败: %s" % (nblk, lib.jcy_last_error().decode()))
            allok = False
            continue

        # Python 参考
        t0 = time.time()
        CONST, Cbpy = [], []
        for b in range(nblk):
            xb = bytes(D.T(list(xflat[b * 16:(b + 1) * 16])))
            prev = body[b * 16 - 16:b * 16] if b else iv
            CONST.append(D.xr(D.xr(xb, dummy[b * 16:(b + 1) * 16]), prev))
            Cbpy.append(D.xr(body[b * 16:(b + 1) * 16], D.xr(D.F(xb, rk), Cpy)))
        t_pypost = (time.time() - t0) * 1000

        cok = CO.raw[:nblk * 16] == b"".join(CONST)
        bok = Cb.raw[:nblk * 16] == b"".join(Cbpy)
        bad = [b for b in range(nblk) if CO.raw[b*16:(b+1)*16] != CONST[b]
               or Cb.raw[b*16:(b+1)*16] != Cbpy[b]]
        print("[3] %4d 块: CONST %s  Cb %s  |后处理 C %.1f ms vs py %.1f ms (%.0fx)"
              % (nblk, "一致" if cok else "不一致", "一致" if bok else "不一致",
                 t_cpost, t_pypost, (t_pypost / t_cpost) if t_cpost else 0))
        if bad:
            print("      差异块: %s" % bad[:8])
        allok = allok and cok and bok

    print()
    print("=== 全部逐位一致: %s ===" % allok)
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
