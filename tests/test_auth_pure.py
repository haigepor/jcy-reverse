# -*- coding: utf-8 -*-
"""tests/test_auth_pure.py — ``authentication`` 算法的**纯逻辑**单元测试。

不依赖 Unicorn 与任何大二进制产物，可随时运行::

    ./.venv/Scripts/python.exe tests/test_auth_pure.py

覆盖：自定义字母表编解码、输入串构造、body 结构校验、主流程拼装
（用假的 ``E`` 后端验证流程正确性）。
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "tools"))

from jcy_protocol import auth as A  # noqa: E402

FAILED: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name, ("  " + extra) if extra and not cond else ""))
    if not cond:
        FAILED.append(name)


# ---------------------------------------------------------------- 字母表

def test_alphabet_shape() -> None:
    print("\n== 字母表 ==")
    check("字母表长度 64", len(A.ALPHABET) == 64)
    check("字母表无重复字符", len(set(A.ALPHABET)) == 64)
    check("标准字母表长度 64", len(A.STD_B64) == 64)
    check("两表字符集相同", set(A.ALPHABET) == set(A.STD_B64))


def test_custom_b64_known_vectors() -> None:
    print("\n== CUSTOM_B64 已知向量 ==")
    # 标准 base64 与自定义字母表的对应关系：A→y, Q→y? 以实际映射为准
    vec = [
        (b"A", "yy=="),
        (b"B", "yI=="),
        (b"AAAA", "ye0iyy=="),
        (b"", ""),
    ]
    for raw, expect in vec:
        got = A.custom_b64(raw)
        check("custom_b64(%r) == %r" % (raw, expect), got == expect, "实际 %r" % got)


def test_custom_b64_roundtrip() -> None:
    print("\n== CUSTOM_B64 往返 ==")
    import os as _os
    ok = True
    for n in range(0, 130):
        data = _os.urandom(n)
        if A.custom_b64d(A.custom_b64(data)) != data:
            ok = False
            break
    check("0..129 字节随机往返一致", ok)

    s = A.build_input(1790618586109, "16613a7076284a15bc723d018bcd67e1")
    a1 = A.custom_b64(s.encode())
    check("78 字节输入 → A1 长度 104", len(a1) == 104, "实际 %d" % len(a1))
    check("A1 解码回原串", A.custom_b64d(a1).decode() == s)


# ---------------------------------------------------------------- 输入串

def test_build_input() -> None:
    print("\n== 输入串构造 ==")
    s = A.build_input(1790618586109, "16613a7076284a15bc723d018bcd67e1")
    expect = ("3.0.0.8-1790618586109-Android-1.5.8.0-"
              "16613a7076284a15bc723d018bcd67e1-default")
    check("格式与真机一致", s == expect, "实际 %r" % s)
    check("长度 78", len(s) == 78, "实际 %d" % len(s))
    check("ts 为十进制毫秒", s.split("-")[1] == "1790618586109")


# ---------------------------------------------------------------- body

def test_split_body() -> None:
    print("\n== body 结构 ==")
    body = A.CT0 + bytes(range(96))
    d = A.split_body(body)
    check("ct0 = 前 16 字节", d["ct0"] == A.CT0)
    check("o32 = [16:48]", d["o32"] == bytes(range(32)))
    check("o64 = [16:80]", d["o64"] == bytes(range(64)))
    check("o96 = [16:112]", d["o96"] == bytes(range(96)))

    try:
        A.split_body(b"\x00" * 100)
        check("长度错误时抛 ValueError", False, "未抛异常")
    except ValueError:
        check("长度错误时抛 ValueError", True)


# ---------------------------------------------------------------- 主流程

class FakeE:
    """假的 E 后端：CBC 用 XOR 代替分组密码，仅用于验证流程拼装。"""

    def __init__(self):
        self.seen: list[bytes] = []

    def encrypt(self, a1: bytes) -> bytes:
        self.seen.append(a1)
        assert len(a1) == 104
        pt = a1 + bytes([8]) * 8          # PKCS7 补到 112
        out = bytearray()
        prev = A.AES_IV
        for i in range(0, len(pt), 16):
            blk = bytes(x ^ y for x, y in zip(pt[i:i + 16], prev))
            prev = bytes(b ^ 0xA5 for b in blk)
            out += prev
        return bytes(out)


def test_generate_flow() -> None:
    print("\n== 主流程（假后端）==")
    fe = FakeE()
    auth = A.generate(1790618586109, "16613a7076284a15bc723d018bcd67e1", fe)
    check("返回 152 字符", len(auth) == 152, "实际 %d" % len(auth))
    check("后端收到 104 字节 A1", len(fe.seen[0]) == 104)
    check("后端收到的 A1 == CUSTOM_B64(S)",
          fe.seen[0] == A.custom_b64(A.build_input(
              1790618586109, "16613a7076284a15bc723d018bcd67e1").encode()).encode())
    check("头可解回 112 字节 body", len(A.body_of(auth)) == 112)

    p = A.generate_parsed(1790618586109, "16613a7076284a15bc723d018bcd67e1", FakeE())
    for k in ("ts", "device_fp", "input", "a1", "auth", "body", "ct0", "o32", "o64", "o96"):
        check("generate_parsed 含字段 %s" % k, k in p)


def test_ct0_constant() -> None:
    print("\n== 常量 ==")
    check("CT0 长度 16", len(A.CT0) == 16)
    check("CT0 == 23754ae9d0cbe749f5441e769b45143e",
          A.CT0.hex() == "23754ae9d0cbe749f5441e769b45143e")
    check("AES_KEY 32 字节", len(A.AES_KEY) == 32)
    check("AES_IV 16 字节", len(A.AES_IV) == 16)


def main() -> int:
    test_alphabet_shape()
    test_custom_b64_known_vectors()
    test_custom_b64_roundtrip()
    test_build_input()
    test_split_body()
    test_generate_flow()
    test_ct0_constant()
    print()
    if FAILED:
        print("[test_auth_pure] 失败 %d 项: %s" % (len(FAILED), FAILED))
        return 1
    print("[test_auth_pure] 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
