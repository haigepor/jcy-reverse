"""jcy_protocol —— 囧次元 (com.tudou.tool) 协议层可复用实现。

本包把逆向得出的加密原语从分析脚本中抽取为可安装、可测试的库：
- 监控通道 / 信令通道：AES-128-CBC + PKCS7 + base64 单字符串帧
- 诱饵 JSON 帧构造（上行帧内嵌真实指令）
- HTTP API 头集合构造

分析期的完整客户端仍在 `out/client/gg_client.py`（保持冻结，作为取证产物）。
本包与之常量一致，并由 `tests/test_channels.py` 用真机抓包向量校验。

声明：仅用于个人学习与研究，不得用于商业或非法用途。
"""

from .channels import (
    APPID,
    HOST_API_LIVE,
    HTTP_HEADERS_STATIC,
    MON_IV,
    MON_KEY,
    SIG_IV,
    SIG_KEY,
    aes128cbc_decrypt,
    aes128cbc_encrypt,
    channel_decrypt,
    channel_encrypt,
    http_headers,
    monitor_decrypt_response,
    monitor_frame,
    pkcs7_pad,
    pkcs7_unpad,
    signaling_decrypt_response,
    signaling_request,
)

__all__ = [
    "APPID",
    "HOST_API_LIVE",
    "HTTP_HEADERS_STATIC",
    "MON_IV",
    "MON_KEY",
    "SIG_IV",
    "SIG_KEY",
    "aes128cbc_decrypt",
    "aes128cbc_encrypt",
    "channel_decrypt",
    "channel_encrypt",
    "http_headers",
    "monitor_decrypt_response",
    "monitor_frame",
    "pkcs7_pad",
    "pkcs7_unpad",
    "signaling_decrypt_response",
    "signaling_request",
]

__version__ = "0.1.0"
