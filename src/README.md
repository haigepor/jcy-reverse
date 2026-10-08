# src/ — 源码层

三个**并列工作区**：安卓客户端、Web 前端、协议库。

| 目录 | 角色 | 技术栈 |
|---|---|---|
| `app/` | 安卓客户端 | Capacitor 7 + Kotlin/JNI + `libcore.so`（React UI 直接复用 `src/web`） |
| `web/` | Web 前端 + 本地后端桥 | Vite 7 / React 19 / Tailwind 4 / ArtPlayer；桥为 FastAPI :8792 |
| `tools/` | 协议加解密库 | 纯 Python 包 `jcy_protocol`（可 pip 安装，零大文件依赖） |

## 依赖方向

```
src/web/src  ──fetch /api /resolve /stream──▶  本机桥
                                              ├─ 浏览器：FastAPI 桥（src/web/server/main.py）
                                              └─ 安卓：Kotlin 桥（src/app/.../JcyBridgeServer.kt）

src/tools/jcy_protocol  ◀── import ──  research/deliverables/*.py（20+ 处）
```

- `src/app` 与 `src/web` **共用同一份 React 源码**（`src/web/src`）。构建时由
  `src/app/scripts/build_web.sh` 注入 `VITE_API_BASE=http://127.0.0.1:8792`，
  前端业务代码零改动即可在浏览器与 App 内运行。
- `src/tools/jcy_protocol` 是**纯逻辑**库（`auth` / `channels` / `vectors`），
  不含任何二进制；真正的 E 分组密码在 `libcore.so` / `research/engine_c`，
  通过 `EBackend` 协议注入。

## 为什么 tools 独立成目录

协议库被 `research/deliverables/*.py` 与 `research/captures/rsa_scan/*.py` 共 20+ 处
`import`，与两个应用**无代码耦合**。2026-10-08 从 `src/` 顶层移入 `src/tools/`，
使 `src/` 顶层只剩三个工作区，边界清晰；同时同步修正了全部 23 处 `sys.path` 注入。

## 安装协议库

```bash
.venv/Scripts/pip install -e src/tools      # Windows
.venv/bin/pip install -e src/tools          # macOS / Linux
```

## 使用

```python
from jcy_protocol import SIG_KEY, SIG_IV, channel_decrypt, signaling_request

# 解一条真实信令响应
print(channel_decrypt(
    "VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L"
    "3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY=", SIG_KEY, SIG_IV))
# b'{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}'

frame = signaling_request("get_app_info", {"address": "723da3db40"})
```

## 测试

```bash
pnpm test:protocol
# 或直接：
.venv/Scripts/python.exe tests/test_channels.py
```

## 边界

- `src/tools/jcy_protocol` 只包含已验证的对称加密层；HTTP body 的随机会话 key +
  RSA-2048 包裹属遗留项（见 `docs/analysis/open-questions.md`），不在本包范围内。
- `X-Token` 无法离线构造，需真机登录后 hook 获取，本包仅提供头部装配函数。
