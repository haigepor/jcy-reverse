# -*- coding: utf-8 -*-
"""cipher_probe.py — 从 Unicorn 会话里提取自研密码 E 的内部参数。

目标: 拿到 KSA(0x2cd8b0) 产出的 256B 表 T, 判断它是不是置换 (S 盒),
      以及 E 的轮函数/密钥扩展特征, 以便在 Python 里实现 E 与其逆。
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
for _p in (os.path.join(ROOT, "research", "deliverables"),
           os.path.join(ROOT, "research", "toolchain"),
           os.path.join(ROOT, "src"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_LR)
from authgen import UnicornESession, DEV_BASE, OFF_PIPE, AES_KEY, AES_IV  # noqa: E402
from jcy_protocol.auth import custom_b64  # noqa: E402

KSA = 0x2cd8b0


def main():
    s = UnicornESession()
    e = s.e
    calls = []

    def ksa_enter(uc, addr, size, ud):
        calls.append({"x0": uc.reg_read(UC_ARM64_REG_X0),
                      "x1": uc.reg_read(UC_ARM64_REG_X1),
                      "x2": uc.reg_read(UC_ARM64_REG_X2),
                      "x3": uc.reg_read(UC_ARM64_REG_X3),
                      "lr": uc.reg_read(UC_ARM64_REG_LR)})

    e.uc.hook_add(UC_HOOK_CODE, ksa_enter, begin=DEV_BASE + KSA, end=DEV_BASE + KSA)

    S = b"3.0.0.8-1790618586569-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
    a1 = custom_b64(S).encode()
    out = s.encrypt(a1)
    print("[*] enc ok, out=%dB, KSA calls=%d" % (len(out), len(calls)))
    for i, c in enumerate(calls):
        print("    call%d x0=0x%x x1=0x%x x2=0x%x lr_off=0x%x"
              % (i, c["x0"], c["x1"], c["x2"], c["lr"] - DEV_BASE))

    # 读 x1 指向的表 (调用后仍在栈上)
    for i, c in enumerate(calls):
        try:
            t = e.rd(c["x1"], 256)
        except Exception as ex:
            print("    call%d 读取失败 %r" % (i, ex))
            continue
        uniq = len(set(t))
        isperm = (uniq == 256 and sorted(t) == list(range(256)))
        print("    call%d T[0:32]=%s 唯一值=%d 置换=%s"
              % (i, t[:32].hex(), uniq, isperm))
        # 与标准 AES S 盒对比 (就地生成, 避免手抄错)
        AES_SBOX = gen_aes_sbox()
        if t == AES_SBOX:
            print("    call%d == 标准 AES S 盒" % i)
        else:
            diff = sum(1 for a, b in zip(t, AES_SBOX) if a != b)
            print("    call%d 与 AES S 盒不同字节数=%d/256" % (i, diff))
            print("    call%d 与 AES 逆S盒相同=%s" % (i, t == gen_aes_inv_sbox()))
        open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "ksa_table_call%d.bin" % i), "wb").write(t)


def gmul(a, b):
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


def gen_aes_sbox():
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if gmul(i, j) == 1:
                inv[i] = j
                break
    sbox = []
    for i in range(256):
        x = y = inv[i]
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            y ^= x
        sbox.append(y ^ 0x63)
    return bytes(sbox)


def gen_aes_inv_sbox():
    s = gen_aes_sbox()
    inv = [0] * 256
    for i, v in enumerate(s):
        inv[v] = i
    return bytes(inv)


if __name__ == "__main__":
    main()
