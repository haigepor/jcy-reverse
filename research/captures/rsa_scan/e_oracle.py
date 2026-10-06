# -*- coding: utf-8 -*-
"""e_oracle.py — 自研分组密码 E 的可复用加密预言机 (Unicorn 管线)

E 就是 authentication 头用的那个 CBC 分组密码 (libcore 管线 0x304eb0)。
本模块把 key/iv 参数化:  fix_long_string(0x688130,key) / (0x688148,iv)
hook 在 A1 阶段覆写明文缓冲区 -> 可加密任意明文。

语义:  ct = CBC-E(key, iv, PKCS7(pt))   —— 与 CT0 回归一致 (pt=104 -> 112B, 首块=CT0)
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
for _p in (os.path.join(ROOT, "research", "deliverables"),
           os.path.join(ROOT, "research", "toolchain"),
           os.path.join(ROOT, "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from authgen import UnicornESession, DEV_BASE, OFF_PIPE, AES_KEY, AES_IV  # noqa: E402
from jcy_protocol.auth import custom_b64  # noqa: E402


def b64len(n):
    return 4 * ((n + 2) // 3)


class EOracle:
    def __init__(self):
        self.s = UnicornESession()

    def enc(self, pt, key, iv):
        s = self.s
        s.e.fix_long_string(0x688130, key)
        s.e.fix_long_string(0x688148, iv)
        L = None
        for cand in range(1, len(pt) + 1):
            if b64len(cand) == len(pt):
                L = cand
                break
        if L is None:
            raise ValueError("明文长度 %d 无法用 b64 长度凑出" % len(pt))
        s._cur[0] = pt
        s._out.clear()
        inp = s.e.mkstr(b"\x00" * L)
        s.e.call(DEV_BASE + OFF_PIPE,
                 (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
                 sret=s.sret, timeout=120_000_000)
        return s._out.get("body", b"")

    def ct(self, pt, key, iv):
        """返回去掉 PKCS7 后的密文 (标准 CBC 语义) 与完整密文。"""
        raw = self.enc(pt, key, iv)
        return raw


def _selftest():
    o = EOracle()
    S = b"3.0.0.8-1790618586569-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
    out = o.enc(custom_b64(S).encode(), AES_KEY, AES_IV)
    from jcy_protocol.auth import CT0
    ok = out[:16] == CT0
    print("selftest CT0 match:", ok, out[:16].hex())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_selftest())
