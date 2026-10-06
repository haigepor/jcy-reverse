# -*- coding: utf-8 -*-
"""囧次元 (com.tudou.tool) 三通道解密 —— 公共原语。

所有函数均为纯 Python, 无外部网络依赖 (frida 相关能力见 mem_plaintext.py)。
"""
import base64
import json
import os

from Crypto.Cipher import AES

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")

# ---------------------------------------------------------------- 通道密钥
# 出处 (双源互证, 见 out/VERIFICATION.txt [F3]/[F4] 与 docs/crypto/overview.md):
#   blutter 对象池 out/blutter_out/pp.txt
#     [pp+0x7000] "kFGTbLlOzFHQCIKp"   [pp+0x7008] "F3q22XoM8l6T2Ydc"  (信令, libloader.so)
#     [pp+0x1b838] "qPwClBj7j7ZQraSm"  [pp+0x1b840] "p3JdVQl3q7WQJIgG"  (监控, libcore.so)
#   真机 frida hook aes_v8_set_encrypt_key: key=715077436c426a376a375a517261536d
#     = ASCII "qPwClBj7j7ZQraSm"  (独立复现)
MON_KEY = b"qPwClBj7j7ZQraSm"
MON_IV = b"p3JdVQl3q7WQJIgG"
SIG_KEY = b"kFGTbLlOzFHQCIKp"
SIG_IV = b"F3q22XoM8l6T2Ydc"

# ---------------------------------------------------------------- 基础原语


def b64d(s):
    """宽容 base64 解码 (自动补齐 padding)。"""
    if isinstance(s, str):
        s = s.encode("ascii")
    return base64.b64decode(s + b"=" * (-len(s) % 4))


def b64e(b):
    return base64.b64encode(b).decode("ascii")


def pkcs7_unpad(b):
    if not b:
        return None
    n = b[-1]
    if n < 1 or n > 16 or b[-n:] != bytes([n]) * n:
        return None
    return b[:-n]


def pkcs7_pad(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def aes_cbc_decrypt(key, iv, ct, unpad=True):
    """AES-CBC 解密; unpad=True 时剥离 PKCS7 (非法填充返回 None)。"""
    if len(ct) % 16 != 0:
        raise ValueError("ciphertext length %d not multiple of 16" % len(ct))
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    if not unpad:
        return pt
    return pkcs7_unpad(pt)


def aes_cbc_encrypt(key, iv, pt):
    """AES-CBC + PKCS7 加密。"""
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(pt))


def load_http_samples():
    with open(os.path.join(SAMPLES, "http_responses.json"), encoding="utf-8") as f:
        return json.load(f)


def load_json_samples(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as f:
        return json.load(f)
