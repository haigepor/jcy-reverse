# 囧次元 (com.tudou.tool) 逆向工程

Flutter 壳 + 自研加密协议的视频 App 完整逆向工程项目。
目标样本: versionName 1.5.8.0 (Dart 3.6.0 / Flutter 3.27.x)。

## 成果速览

| 目标 | 状态 | 位置 |
|---|---|---|
| 视频播放接口全链路分析 | ✅ 端点/参数/头/链路全部还原 | `docs/api/`、`out/API_ANALYSIS.md` |
| 登录逻辑（设备静默登录） | ✅ device-base + X-Token 机制 | `docs/api/device-base.md`、`docs/crypto/x-token.md` |
| API 加解密逆向 | ✅ 监控/信令双通道 100%；HTTP 结构 100% | `docs/crypto/` |
| 离线客户端库 | ✅ Python 客户端已验证加密层 | `out/client/gg_client.py` |
| Dart 结构还原 | ✅ blutter 产物（对象池/asm/frida 模板） | `out/blutter_out/` |
| 离线验证页 | ✅ hls.js 播放验证 | `out/demo/index.html` |

## 仓库目录结构

```
.
├── README.md              本文件（项目入口）
├── .gitignore             版本控制排除规则（工具/二进制/解包产物不入库）
├── CLEANUP_REPORT.md      项目清理报告（2026-09-28）
├── apk/                   原始样本 base.apk（仅本地保存，不入库）
├── docs/                  逆向文档站（docsify，阅读入口 docs/index.html）
│   ├── analysis/          解密过程全记录（时间线/工具链/证据/遗留问题）
│   ├── api/               接口文档（总览/视频列表/播放/设备登录/端点速查）
│   ├── crypto/            加密算法（三通道架构/监控/信令/HTTP body/X-Token）
│   └── assets/            静态资源
├── out/                   分析工作区（入库：脚本/客户端/文档产物）
│   ├── client/            Python 客户端 gg_client.py + Frida 脚本族（成果）
│   ├── demo/              离线验证页 index.html（hls.js）
│   ├── blutter_out/       blutter 产物（pp.txt 对象池 / objs.txt / frida 模板）
│   └── *.py / *.js / *.c  分析与 hook 脚本（104 个，含迭代过程）
├── reflutter_work/        reflutter 工作区（dump.dart 等，仅本地保存）
├── tools/                 逆向工具链（第三方工具，仅本地保存，见 tools/README.md）
└── zcode-keysmith/        密钥工具包 v0.3.3（含文档与源码）
```

> 标注"仅本地保存"的目录因体积/版权原因不入库，本地完整保留；获取方式见 `tools/README.md`。

## 快速上手

```python
import sys; sys.path.insert(0, 'out/client')
from gg_client import SIG_KEY, SIG_IV, channel_decrypt

# 解一条真实信令响应
print(channel_decrypt(
    "VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L"
    "3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY=", SIG_KEY, SIG_IV))
# b'{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}'
```

## 密钥速查

| 通道 | 算法 | key | iv |
|---|---|---|---|
| 监控 (libcore C2) | AES-128-CBC PKCS7 | `qPwClBj7j7ZQraSm` | `p3JdVQl3q7WQJIgG` |
| 信令 (libloader IPC) | AES-128-CBC PKCS7 | `kFGTbLlOzFHQCIKp` | `F3q22XoM8l6T2Ydc` |
| HTTP body | 随机会话 key AES-CBC + RSA-2048 包裹 | 每请求随机 | 每请求随机 |

## 一键环境安装（pnpm）

项目已整理为可复现的 pnpm 骨架。首次克隆后，在根目录执行：

```bash
pnpm install
```

这会安装 Node 依赖、core 逆向工具（apktool / uber-apk-signer / jadx / platform-tools），并创建 `.venv` 安装 `requests` 与 `pycryptodome`。完整工具集（blutter / PCAPdroid / Frida Gadget）按需执行：

```bash
pnpm tools:install:all
pnpm tools:status
pnpm validate
```

详细的下载源、代理设置、Python 环境与目录落点见 [`docs/installation.md`](docs/installation.md)；工具清单见 [`config/tools.json`](config/tools.json)。

## 文档导航（docsify 本地阅读）

```bash
pnpm docs:serve
# 浏览器打开 http://localhost:3000
```

- 加密算法：三通道架构 / 监控通道 / 信令通道 / HTTP body / X-Token → `docs/crypto/`
- 接口文档：总览与请求头 / 视频列表 / 播放链接 / 设备登录 / 端点速查 → `docs/api/`
- 解密全记录：破解放事 / 工具链手册 / 证据索引 / 遗留问题 → `docs/analysis/`

## 版本标签

- `v0.1.0` — 首个完整分析版本（接口全链路 + 双通道加密还原 + 客户端库），标签说明见 `docs/tags.md`

## 免责声明

本项目仅为个人学习与研究用途的逆向分析记录，不提供任何 App 安装包的分发，不用于任何商业或非法用途。样本与接口数据仅用于验证分析结论。
