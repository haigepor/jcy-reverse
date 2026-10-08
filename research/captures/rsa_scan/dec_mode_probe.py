# -*- coding: utf-8 -*-
"""dec_mode_probe.py — 试探 E 管线是否存在"解密模式"。

思路: E(0x2d6f78) 是 libcore 里唯一 0x180 栈帧的函数, 可能兼做加/解密。
      管线 0x304eb0 目前按 (x0=输入串, x1=key, x2=iv) 调用;
      若存在第 4 个参数作为模式位, 传入后应能对 A1 缓冲区做"逆变换"。

判定: 先用 key/iv 加密 pt 得 ct0 = E(pt ⊕ iv);
      再把 ct0 当作 A1 缓冲区喂回, 看首块是否等于 pt。
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
for _p in (os.path.join(ROOT, "research", "deliverables"),
           os.path.join(ROOT, "research", "toolchain"),
           os.path.join(ROOT, "src", "tools"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from authgen import UnicornESession, DEV_BASE, OFF_PIPE  # noqa: E402

KEY = b"K" * 32
IV = b"\x00" * 16


def b64len(n):
    return 4 * ((n + 2) // 3)


def run(s, pt, key, iv, mode_args):
    s.e.fix_long_string(0x688130, key)
    s.e.fix_long_string(0x688148, iv)
    L = next((c for c in range(1, len(pt) + 1) if b64len(c) == len(pt)), None)
    if L is None:
        raise ValueError("pt 长度 %d 不可用" % len(pt))
    s._cur[0] = pt
    s._out.clear()
    inp = s.e.mkstr(b"\x00" * L)
    args = [inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148] + list(mode_args)
    s.e.call(DEV_BASE + OFF_PIPE, tuple(args), sret=s.sret, timeout=120_000_000)
    return s._out.get("body", b"")


def main():
    s = UnicornESession()
    pt = bytes(range(16))
    ct = run(s, pt, KEY, IV, [])            # 加密: ct0 = E(pt)
    print("[enc] pt =%s" % pt.hex())
    print("[enc] ct0=%s (ct 全长 %d)" % (ct[:16].hex(), len(ct)))

    for m in (0, 1, 2, 0x10, 0x100):
        try:
            out = run(s, ct[:16], KEY, IV, [m])
            print("[mode=%#x] out0=%s  等于 pt? %s" % (m, out[:16].hex(), out[:16] == pt))
        except Exception as e:
            print("[mode=%#x] 异常 %r" % (m, e))

    # 也试试把 mode 放到 x4
    for m in (1, 2):
        try:
            out = run(s, ct[:16], KEY, IV, [0, m])
            print("[x3=0,x4=%#x] out0=%s  等于 pt? %s" % (m, out[:16].hex(), out[:16] == pt))
        except Exception as e:
            print("[x3=0,x4=%#x] 异常 %r" % (m, e))


if __name__ == "__main__":
    main()
