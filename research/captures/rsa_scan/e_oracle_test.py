# -*- coding: utf-8 -*-
"""e_oracle_test.py — 验证能否用 Unicorn 管线做「任意 key/iv + 任意明文」的 E 加密预言机。

管线 0x304eb0:  A1 = CUSTOM_B64(x0)  ->  E(key@0x688130, iv@0x688148, A1)
hook 在 A1 阶段把缓冲区覆写成我们给的明文, 只要长度相等。
故: 选 x0 长度 L 使 4*ceil(L/3) == len(pt)。
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables"))
sys.path.insert(0, os.path.join(ROOT, "research", "toolchain"))
sys.path.insert(0, os.path.join(ROOT, "src", "tools"))

from authgen import UnicornESession, DEV_BASE, OFF_PIPE, AES_KEY, AES_IV  # noqa: E402


def b64len(n):
    return 4 * ((n + 2) // 3)


def enc(sess, pt, key, iv):
    sess.e.fix_long_string(0x688130, key)
    sess.e.fix_long_string(0x688148, iv)
    # 选 x0 长度 L, 使 b64len(L) == len(pt)
    L = None
    for cand in range(1, len(pt) + 1):
        if b64len(cand) == len(pt):
            L = cand
            break
    if L is None:
        raise SystemExit("明文长度 %d 无法用 b64 长度凑出" % len(pt))
    sess._cur[0] = pt
    sess._out.clear()
    inp = sess.e.mkstr(b"\x00" * L)
    sess.e.call(DEV_BASE + OFF_PIPE,
                (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
                sret=sess.sret, timeout=120_000_000)
    return sess._out.get("body", b"")


def main():
    print("[*] boot unicorn ...", flush=True)
    s = UnicornESession()
    print("[*] booted, boots=%d" % s.boots, flush=True)

    # 1) 回归: 用真 key/iv 复现 auth 的 A1 -> E 输出 (112B)
    from jcy_protocol.auth import custom_b64, CT0
    S = b"3.0.0.8-1790618586569-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
    a1 = custom_b64(S).encode()
    out = enc(s, a1, AES_KEY, AES_IV)
    print("[1] pt=%d -> out=%d bytes" % (len(a1), len(out)))
    print("    out[:32] =", out[:32].hex())
    print("    CT0       =", CT0.hex())

    # 2) 16 字节明文
    pt16 = bytes(range(16))
    out16 = enc(s, pt16, AES_KEY, AES_IV)
    print("[2] pt=%d -> out=%d bytes  %s" % (len(pt16), len(out16), out16.hex()))

    # 3) 32 字节明文
    pt32 = bytes(range(32))
    out32 = enc(s, pt32, AES_KEY, AES_IV)
    print("[3] pt=%d -> out=%d bytes  %s" % (len(pt32), len(out32), out32.hex()))

    # 4) 换 key/iv 看输出是否变化 (差分)
    out16b = enc(s, pt16, b"Z" * 32, b"Y" * 16)
    print("[4] 换 key/iv: %s  变化=%s" % (out16b.hex(), out16b != out16))


if __name__ == "__main__":
    main()
