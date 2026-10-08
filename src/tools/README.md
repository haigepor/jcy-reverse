# src/tools — 协议库（Python）

囧次元协议层的**可复用 Python 库**，独立于 `src/app`（安卓客户端）与 `src/web`（Web 前端）。
2026-10-08 从 `src/` 顶层移入本目录，使 `src/` 只剩三个并列工作区：`app/`、`web/`、`tools/`。

| 文件 | 作用 |
|---|---|
| `jcy_protocol/auth.py` | `authentication` 算法的**纯逻辑实现**：自定义字母表编解码、输入串构造、body 拆分、头拼装；定义 `EBackend` 协议。零大文件依赖 |
| `jcy_protocol/channels.py` | 监控通道与信令通道（AES-128-CBC）的加解密实现 |
| `jcy_protocol/vectors.py` | 测试向量与已知明文/密文对 |
| `jcy_protocol/__init__.py` | 包导出 |
| `pyproject.toml` | 打包配置（`pip install -e src/tools`） |

## 谁在用它

`research/deliverables/*.py` 与 `research/captures/rsa_scan/*.py` 通过 `sys.path` 注入
`<root>/src/tools` 后 `import jcy_protocol`：

```python
import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src", "tools"))
from jcy_protocol.auth import ALPHABET
```

> 移动时同步修正了 **23 处** `sys.path` 注入点（`research/` 21 处 + `src/web/server/main.py` +
> `tests/` 2 处），全部由 `, "src")` 改为 `, "src", "tools")`。

## 安装

```bash
.venv/Scripts/pip install -e src/tools
```

## 注意

`auth.py` 只含**纯逻辑**；真正的 `E` 分组密码在 `libcore.so` / `research/engine_c`，
通过 `EBackend` 协议注入。本目录不依赖任何大二进制。
