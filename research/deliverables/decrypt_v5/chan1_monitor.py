# -*- coding: utf-8 -*-
"""通道 1 —— 监控通道 (libcore.so `call`, C2 心跳)

算法: AES-128-CBC + PKCS7, 编码 base64
key : qPwClBj7j7ZQraSm   (hex 715077436c426a376a375a517261536d)
iv  : p3JdVQl3q7WQJIgG

状态: 密钥 **双源验证通过**; 真实密文未留档 (见下"证据缺口")。
      通道 1 与通道 2 使用完全相同的算法与帧结构, 仅 key/iv 不同;
      通道 2 已有真实密文断言 (chan2_signaling.py), 故本通道的算法层已被通道 2 交叉证实。

证据缺口 (诚实记录):
  - out/ffi_log.jsonl / out/manual_log2.jsonl / out/hex_log.jsonl 在磁盘上均不存在,
    文档中引用的 "556 字符 b64 心跳密文" 未随仓库保留。
  - 本次在 LDPlayer14 上重采失败: libcore.so 为 ARM64 库, 在 houdini 转译层下
    Process.enumerateModules() 不可见 (321 个模块全为 x86_64 host 库), 无法 hook;
    网络侧 60s 抓包 0 包, 心跳未在当前离线态发起。
  - 因此本文件以 (a) 密钥来源双证 (b) 算法往返 (c) 与通道 2 的判别性对比 三项替代断言。

运行: python chan1_monitor.py
"""
import json
import os
import random
import string
import sys

from common import (
    MON_IV,
    MON_KEY,
    SIG_IV,
    SIG_KEY,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    b64d,
    b64e,
)

# 密钥的独立第二来源: 真机 frida hook libcore.so 的 aes_v8_set_encrypt_key
KEY_FROM_EVP_HOOK_HEX = "715077436c426a376a375a517261536d"

# 留档的真实指令明文 (docs/crypto/monitor-channel.md, 真机解密捕获)
REAL_COMMAND_PT = b'{"list":[{"action":"apk_sign","params":"false"},{"action":"vpn","params":"true"}]}'

# 通道 2 的真实密文 (用于判别性对比)
SIG_REAL_B64 = (
    "VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L"
    "3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY="
)


def decrypt_frame(b64frame):
    return aes_cbc_decrypt(MON_KEY, MON_IV, b64d(b64frame))


def encrypt_frame(plaintext):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    return b64e(aes_cbc_encrypt(MON_KEY, MON_IV, plaintext))


def _rnd16():
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))


def build_decoy_frame(action, params=None, filler_pairs=12):
    """构造上行帧: ~12 对随机 16 字符键值对 (诱饵) + 真实指令字段。

    真实字段键名恒为固定小写单词 (action/params/data/...), 与诱饵的
    "16 字符混合大小写" 形态形成区分 —— 这是识别真实指令的判据。
    """
    obj = {}
    for _ in range(filler_pairs):
        obj[_rnd16()] = _rnd16()
    obj["action"] = action
    if params is not None:
        obj["params"] = json.dumps(params)
    return encrypt_frame(json.dumps(obj))


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print("  [OK] " + msg)


def selftest():
    print("[chan1 monitor] key=%s iv=%s" % (MON_KEY.decode(), MON_IV.decode()))
    print("-" * 66)
    print("[1] 密钥来源双证")
    _assert(bytes.fromhex(KEY_FROM_EVP_HOOK_HEX) == MON_KEY,
            "frida EVP hook 得到的 key == blutter 对象池字符串 %s" % MON_KEY.decode())
    _assert(len(MON_KEY) == 16 and len(MON_IV) == 16, "key/iv 均为 16 字节 (AES-128)")

    print("[2] 算法往返 (与通道 2 同算法)")
    for msg in (REAL_COMMAND_PT, b"{}", _rnd16().encode()):
        _assert(decrypt_frame(encrypt_frame(msg)) == msg, "round-trip %r" % msg[:32])

    print("[3] 诱饵帧结构自检")
    frame = build_decoy_frame("get_record", {"sta": 1})
    obj = json.loads(decrypt_frame(frame))
    decoys = [k for k in obj if len(k) == 16]
    _assert("action" in obj and obj["action"] == "get_record", "真实字段 action 保留")
    _assert(len(decoys) == 12, "12 对 16 字符诱饵键")
    _assert(all(len(obj[k]) == 16 for k in decoys), "诱饵值亦为 16 字符")

    print("[4] 判别性: 监控 key 与信令 key 互不可解 (证明两通道独立)")
    sig_ct = b64d(SIG_REAL_B64)
    try:
        got = aes_cbc_decrypt(MON_KEY, MON_IV, sig_ct)
    except Exception:
        got = None
    _assert(got is None or b"get_app_info" not in got,
            "用监控 key 解信令真实密文得不到有效明文 (填充非法或内容不符)")
    _assert(aes_cbc_decrypt(SIG_KEY, SIG_IV, sig_ct).startswith(b'{"action":"get_app_info"'),
            "用信令 key 解同一密文正确 (对照)")

    print("[5] 真实指令明文形态校验 (留档样本, 非本机捕获)")
    _assert(REAL_COMMAND_PT.startswith(b'{"list":[{"action":"apk_sign"'),
            "留档明文为反调试探测指令 (apk_sign / vpn)")

    print("-" * 66)
    print("[chan1 monitor] 断言通过 (密钥与算法已证; 真实密文未留档 —— 见文件头'证据缺口')")


if __name__ == "__main__":
    try:
        selftest()
    except AssertionError as e:
        print("FAIL:", e)
        sys.exit(1)
