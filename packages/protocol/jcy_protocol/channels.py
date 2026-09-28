"""双通道加解密原语（与 out/client/gg_client.py 常量一致，经真机抓包验证）。

证据来源：
- out/API_ANALYSIS.md（加密层增补节）
- out/VERIFICATION.txt（两阶段审计链）
- docs/crypto/monitor-channel.md、docs/crypto/signaling-channel.md
"""

from __future__ import annotations

import base64
import json
import random
import string
import time

from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

APPID = "com.tudou.tool"

# 当前生效主 API（抓包确认）
HOST_API_LIVE = "http://43.145.33.254:27990"

# 通道 1：监控通道（libcore.so C2 心跳）
MON_KEY = b"qPwClBj7j7ZQraSm"
MON_IV = b"p3JdVQl3q7WQJIgG"

# 通道 2：信令通道（libloader.so IPC / WebRTC 上报）
SIG_KEY = b"kFGTbLlOzFHQCIKp"
SIG_IV = b"F3q22XoM8l6T2Ydc"

BLOCK_SIZE = 16
DEFAULT_FILLER_PAIRS = 12

# HTTP 头集合（HeadersInterceptor 池引用实证）
HTTP_HEADERS_STATIC = {
    "appid": APPID,
    "tcs": "2",
    "x-version": "2020-09-17",
    "user-agent": "Dart/3.6 (dart:io)",
}


# ---------------------------------------------------------------------------
# PKCS7
# ---------------------------------------------------------------------------


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """PKCS7 填充。"""
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """PKCS7 去填充；填充非法时抛 ValueError（避免静默返回脏数据）。"""
    if not data or len(data) % block_size != 0:
        raise ValueError("密文长度非块大小整数倍")
    pad = data[-1]
    if not 1 <= pad <= block_size or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("PKCS7 填充非法")
    return data[:-pad]


# ---------------------------------------------------------------------------
# AES-128-CBC
# ---------------------------------------------------------------------------


def _check_key_iv(key: bytes, iv: bytes) -> None:
    if len(key) != 16:
        raise ValueError(f"key 必须为 16 字节，当前 {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"iv 必须为 16 字节，当前 {len(iv)}")


def aes128cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CBC 加密并做 PKCS7 填充（等价 vmplugin.utils_aes128cbc_encrypt）。"""
    _check_key_iv(key, iv)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(data))


def aes128cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CBC 解密并去 PKCS7 填充。"""
    _check_key_iv(key, iv)
    return pkcs7_unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data))


# ---------------------------------------------------------------------------
# 通道帧（base64 单字符串进出 FFI call）
# ---------------------------------------------------------------------------


def channel_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> str:
    """通道帧加密：AES-128-CBC PKCS7 -> base64。"""
    return base64.b64encode(aes128cbc_encrypt(key, iv, plaintext)).decode()


def channel_decrypt(b64_frame: str, key: bytes, iv: bytes) -> bytes:
    """通道帧解密：base64 -> AES-128-CBC PKCS7 unpad。"""
    return aes128cbc_decrypt(key, iv, base64.b64decode(b64_frame))


def _random_key(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _filler_obj(pairs: int) -> dict:
    """构造诱饵键值对，用于把真实指令藏在噪声中。"""
    return {_random_key(): _random_key() for _ in range(pairs)}


def monitor_frame(action: str, params: dict, filler_pairs: int = DEFAULT_FILLER_PAIRS) -> str:
    """构造监控通道上行帧：诱饵 JSON 内嵌真实指令，返回 base64 帧。"""
    obj = _filler_obj(filler_pairs)
    obj["action"] = action
    obj["params"] = json.dumps(params)
    return channel_encrypt(json.dumps(obj).encode(), MON_KEY, MON_IV)


def signaling_request(action: str, params: dict, filler_pairs: int = DEFAULT_FILLER_PAIRS) -> bytes:
    """构造信令通道上行帧（libloader call 输入），返回 base64 帧的 bytes。"""
    obj = _filler_obj(filler_pairs)
    obj["action"] = action
    obj.update(params)
    return channel_encrypt(json.dumps(obj).encode(), SIG_KEY, SIG_IV).encode()


def signaling_decrypt_response(b64_frame: str) -> bytes:
    """信令通道响应解密（真机验证：见 vectors.SIGNALING_RESPONSE_B64）。"""
    return channel_decrypt(b64_frame, SIG_KEY, SIG_IV)


def monitor_decrypt_response(b64_frame: str) -> bytes:
    """监控通道响应解密。"""
    return channel_decrypt(b64_frame, MON_KEY, MON_IV)


# ---------------------------------------------------------------------------
# HTTP 层
# ---------------------------------------------------------------------------


def http_headers(x_token_b64: str) -> dict:
    """构造 HTTP 请求头。

    x_token_b64 为真机登录后 hook TokenInterceptor 抓到的 authentication 值；
    服务器响应头 new-token 下发，与 ts/nonce 绑定，无法纯离线构造。
    """
    headers = dict(HTTP_HEADERS_STATIC)
    headers["ts"] = str(int(time.time() * 1000))
    headers["nonce"] = str(random.randint(10**7, 10**8 - 1))
    headers["authentication"] = x_token_b64
    return headers
