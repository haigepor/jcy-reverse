"""已验证的测试向量（真机抓包 / 实测通过）。

所有向量均经本地实测确认，未经验证的值不会写入本文件。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 信令通道：真机抓包响应，实测可解出完整 JSON
# 来源：docs/README.md 快速上手、docs/crypto/signaling-channel.md
# ---------------------------------------------------------------------------

SIGNALING_RESPONSE_B64 = (
    "VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L"
    "3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY="
)

SIGNALING_RESPONSE_PLAINTEXT = (
    b'{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}'
)

# 实测密文长度 80 字节，明文 71 字节（PKCS7 填充至 80）
SIGNALING_RESPONSE_CT_LEN = 80
SIGNALING_RESPONSE_PT_LEN = 71

# ---------------------------------------------------------------------------
# 监控通道：无公开抓包样本，仅做加解密往返一致性校验
# ---------------------------------------------------------------------------

MONITOR_ROUNDTRIP_PLAINTEXT = b'{"action":"ping"}'

# ---------------------------------------------------------------------------
# 常量自检（长度必须为 16 字节，否则算法不成立）
# ---------------------------------------------------------------------------

EXPECTED_KEY_IV_LEN = 16
