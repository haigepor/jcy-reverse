# -*- coding: utf-8 -*-
"""通道 2 —— 信令通道 (libloader.so `call`, 本地 native↔Dart IPC)

算法: AES-128-CBC + PKCS7, 编码 base64
key : kFGTbLlOzFHQCIKp
iv  : F3q22XoM8l6T2Ydc

状态: **完全破解** —— 含真实密文断言。

语义: libloader.so 的 native 逻辑需要 app 信息时, 通过该加密 FFI 回调通道向 Dart 侧查询。
      对端是本进程内 native 代码, 无网络流量 (真机 hook 实证)。

运行: python chan2_signaling.py
"""
import sys

from common import SIG_IV, SIG_KEY, aes_cbc_decrypt, aes_cbc_encrypt, b64d, b64e

# ---------------------------------------------------------------- 真实样本
# 出处: 真机 frida hook libloader.so!call (进程 14673/5390) 捕获的响应帧。
# 记录于 docs/crypto/signaling-channel.md 与 docs/crypto/overview.md。
REAL_RESPONSE_B64 = (
    "VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L"
    "3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY="
)
REAL_RESPONSE_PT = b'{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}'


def decrypt_frame(b64frame):
    """解密一条信令帧 (base64 → AES-128-CBC/PKCS7 → 明文 bytes)。"""
    return aes_cbc_decrypt(SIG_KEY, SIG_IV, b64d(b64frame))


def encrypt_frame(plaintext):
    """构造一条信令帧 (明文 → AES-128-CBC/PKCS7 → base64 字符串)。"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    return b64e(aes_cbc_encrypt(SIG_KEY, SIG_IV, plaintext))


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("  [OK] " + msg)


def selftest():
    print("[chan2 signaling] key=%s iv=%s" % (SIG_KEY.decode(), SIG_IV.decode()))
    print("-" * 66)
    print("[1] 真实密文断言")
    ct = b64d(REAL_RESPONSE_B64)
    print("    b64len=%d  ctlen=%d bytes  blocks=%d" % (len(REAL_RESPONSE_B64), len(ct), len(ct) // 16))
    _assert(len(REAL_RESPONSE_B64) == 108, "b64 长度 108 字符 (与留档一致)")
    _assert(len(ct) == 80 and len(ct) % 16 == 0, "密文 80 字节 = 5 个 AES 块")
    pt = decrypt_frame(REAL_RESPONSE_B64)
    print("    plaintext = %s" % pt.decode())
    _assert(pt == REAL_RESPONSE_PT, "真实密文解密结果与留档明文逐字节一致")

    print("[2] 填充合法性 (独立于明文比对的旁证)")
    raw = aes_cbc_decrypt(SIG_KEY, SIG_IV, ct, unpad=False)
    _assert(raw[-1] == 9 and raw[-9:] == b"\x09" * 9, "PKCS7 padding = 0x09 x9 (明文 71B + 9B = 80B)")

    print("[3] 往返自检 (encrypt → decrypt)")
    for msg in (b'{"action":"get_app_info"}', b"hello", REAL_RESPONSE_PT):
        _assert(decrypt_frame(encrypt_frame(msg)) == msg, "round-trip %r" % msg[:24])

    print("[4] 密钥判别性 (证明 key 唯一正确, 非任意 key 都能过)")
    import os
    for _ in range(3):
        wrong = os.urandom(16)
        try:
            got = aes_cbc_decrypt(wrong, SIG_IV, ct)
        except Exception:
            got = None
        _assert(got != REAL_RESPONSE_PT, "随机 key %s 无法得到留档明文" % wrong.hex())

    print("-" * 66)
    print("[chan2 signaling] 全部断言通过")


if __name__ == "__main__":
    try:
        selftest()
    except AssertionError as e:
        print("FAIL:", e)
        sys.exit(1)
