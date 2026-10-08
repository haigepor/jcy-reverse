# -*- coding: utf-8 -*-
"""decrypt_p1.py — 囧次元响应体 P1 的解密接口(协议层已完成, 分组密码逆为唯一缺口)。

协议模型(本轮已由 hit21 逐字节复现证实):
    P1 = CBC-E(key=K16raw, iv=reverse(K16), PKCS7-16(明文))
    P0 = RSA-2048 PKCS1v1.5(app_pub, K16)     # 用 priv_from_go.pem 离线可解

E: libcore 自研 **16 字节** 分组密码(AES 结构: AES S-box + GF(2^8)/0x1b + 自研轮/密钥扩展)。
   加密可用 Unicorn 执行原函数(e_oracle.EOracle); **逆函数尚未还原**。

用法::

    from decrypt_p1 import unwrap_k16, decrypt, encrypt
    k16 = unwrap_k16(p0_b64)          # 需要 priv_from_go.pem
    pt  = decrypt(p1_bytes, k16)      # 需要 E 的逆
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_RESEARCH = os.path.dirname(_HERE)
_ROOT = os.path.dirname(_RESEARCH)
for _p in (os.path.join(_RESEARCH, "captures", "rsa_scan"),
           os.path.join(_RESEARCH, "toolchain"),
           os.path.join(_ROOT, "src", "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

BLOCK = 16


# ---------------------------------------------------------------- RSA / 信封

def unwrap_k16(p0_b64: str, pem_path: str | None = None) -> bytes:
    """解响应 P0(custom-b64 的 RSA-2048 密文) 得到会话密钥 K16(16 字节)。"""
    from Crypto.PublicKey import RSA
    from jcy_protocol.auth import custom_b64d

    pem_path = pem_path or os.path.join(_RESEARCH, "captures", "rsa_scan",
                                        "priv_from_go.pem")
    key = RSA.import_key(open(pem_path, "rb").read())
    ct = custom_b64d(p0_b64)
    m = pow(int.from_bytes(ct, "big"), key.d, key.n).to_bytes(256, "big")
    # PKCS#1 v1.5: 00 02 <PS> 00 <M>
    i = m.index(b"\x00", 2)
    return m[i + 1:]


def split_envelope(data: str):
    """`<P0_b64>.<P1_b64>` -> (P0_b64, P1_b64)。"""
    p0, _, p1 = data.partition(".")
    return p0, p1


# ---------------------------------------------------------------- PKCS7

def _unpad(b: bytes, bs: int = BLOCK) -> bytes:
    if not b or len(b) % bs:
        raise ValueError("密文长度非分组整数: %d" % len(b))
    n = b[-1]
    if n < 1 or n > bs or b[-n:] != bytes([n]) * n:
        raise ValueError("PKCS7 填充非法")
    return b[:-n]


# ---------------------------------------------------------------- 分组密码逆(缺口)

def _E_inv_block(ct16: bytes, k16: bytes) -> bytes:
    """E 的分组逆。**尚未还原** —— 见模块 docstring。"""
    raise NotImplementedError(
        "E 的分组逆尚未还原: E 是 libcore 自研 16 字节分组密码"
        "(密钥相关 S 盒 + 私有轮结构, OLLVM 混淆), "
        "libcore 内未找到解密入口, 加密侧只能通过 Unicorn 执行原函数。\n"
        "可用的替代: 设备在环 —— 见 research/deliverables/decrypt_v5/mem_plaintext.py。")


# ---------------------------------------------------------------- 公开接口

def decrypt(p1: bytes, k16: bytes) -> bytes:
    """P1 密文 -> 明文。"""
    if len(p1) % BLOCK:
        raise ValueError("P1 长度 %d 非 16 的倍数" % len(p1))
    iv = k16[::-1]
    prev = iv
    out = bytearray()
    for i in range(0, len(p1), BLOCK):
        blk = p1[i:i + BLOCK]
        p = _E_inv_block(blk, k16)
        out += bytes(a ^ b for a, b in zip(p, prev))
        prev = blk
    return _unpad(bytes(out))


def encrypt(pt: bytes, k16: bytes) -> bytes:
    """明文 -> P1 密文(用 Unicorn 执行 libcore 原函数, 已由 hit21 复现证实)。"""
    from e_oracle import EOracle
    raw = EOracle().enc(pt, k16, k16[::-1])
    return raw


if __name__ == "__main__":
    print("模块说明见 docstring。")
