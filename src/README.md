# src/protocol — 协议层库

把逆向得出的加密原语从分析脚本中抽取为**可安装、可测试**的 Python 包 `jcy_protocol`。

## 定位

| 目录 | 角色 |
|---|---|
| `research/deliverables/client/gg_client.py` | 分析期完整客户端，**保持冻结**，作为取证产物 |
| `src/` | 可复用协议库，供新脚本/工具直接 import |

两者常量一致；本包由 `tests/test_channels.py` 用真机抓包向量校验。

## 安装

```bash
# 项目虚拟环境已由 pnpm install 创建
.venv/Scripts/python.exe -m pip install -e src/protocol      # Windows
.venv/bin/python -m pip install -e src/protocol             # macOS / Linux
```

## 使用

```python
from jcy_protocol import SIG_KEY, SIG_IV, channel_decrypt, signaling_request

# 解一条真实信令响应
print(channel_decrypt(
    "VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L"
    "3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY=", SIG_KEY, SIG_IV))
# b'{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}'

# 构造信令上行帧
frame = signaling_request("get_app_info", {"address": "723da3db40"})
```

## 测试

```bash
pnpm test:protocol
# 或直接：
.venv/Scripts/python.exe tests/test_channels.py
```

测试覆盖：密钥长度自检、PKCS7 往返与非法填充拒绝、**真机信令向量解密**、
监控通道往返、帧构造形状、HTTP 头动态字段。

## 边界

- 只包含已验证的对称加密层；HTTP body 的随机会话 key + RSA-2048 包裹属遗留项
  （见 `docs/analysis/open-questions.md`），不在本包范围内。
- `X-Token` 无法离线构造，需真机登录后 hook 获取，本包仅提供头部装配函数。
