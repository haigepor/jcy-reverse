# 环境安装与复现

## 前置条件

- Node.js 22+
- pnpm 9.15+
- Python 3.10+（运行 `out/client/gg_client.py` 时需要）
- Android 设备动态分析阶段需要启用 USB 调试；`adb` 由 `platform-tools` 提供

## 一键安装

在项目根目录执行：

```bash
pnpm install
```

`pnpm install` 会执行两类初始化：

1. 安装 Node 侧依赖（当前为 `docsify-cli`）；
2. 执行 `postinstall`，从官方发布源安装 core 工具：
   `apktool`、`uber-apk-signer`、`jadx`、`platform-tools`；
3. 创建项目内 `.venv` 并安装 Python 依赖：`requests`、`pycryptodome`。

已有工具会自动跳过，不会覆盖本地修改。

## 完整工具集

blutter、PCAPdroid APK、Frida Gadget 体积较大或需要按设备 ABI 选择，默认不在 `pnpm install` 中下载。需要时执行：

```bash
pnpm tools:install:all
```

查看工具安装状态：

```bash
pnpm tools:status
```

如果当前网络不可用，`postinstall` 使用 best-effort 模式，不会阻断 Node 依赖安装；网络恢复后重新执行 `pnpm tools:install` 即可。需要严格失败退出时执行：

```bash
pnpm setup
```

## 可选环境变量

| 变量 | 作用 |
|---|---|
| `JCY_HTTP_PROXY` | 为工具下载指定 HTTP/HTTPS 代理；未设置时读取 `HTTPS_PROXY` / `HTTP_PROXY` |
| `JCY_SKIP_TOOLS=1` | 预留的工具跳过开关（推荐使用 `pnpm install --ignore-scripts` 完全跳过脚本） |
| `JCY_SKIP_PYTHON=1` | 跳过 `.venv` 与 Python 依赖安装 |
| `JCY_BEST_EFFORT=1` | 工具或 Python 安装失败时输出警告并继续 |
| `PYTHON` | 指定 Python 可执行文件路径 |

## 常用命令

```bash
pnpm validate       # 校验目录骨架、文档入口与工具清单
pnpm docs:serve     # 启动 docsify 文档站
pnpm python:install # 只安装/修复 Python 虚拟环境
pnpm tools:install  # 只安装 core 逆向工具
pnpm tools:status   # 查看 core/all 工具是否存在
```

## 目录与工具落点

安装脚本只写入 `tools/`、`.venv/` 和临时下载目录；这些路径已加入 `.gitignore`，不会进入版本库。

- Java / APK：`tools/jadx/`、`tools/apktool.jar`、`tools/uber-apk-signer.jar`
- 设备连接：`tools/platform-tools/adb(.exe)`
- Flutter/Dart：`tools/blutter/`
- 抓包：`tools/PCAPdroid.apk`
- Frida Gadget：`tools/frida-gadget-android-arm64.so.xz`
- Python：`.venv/`

## 验证

```bash
pnpm validate
pnpm tools:status
.venv/Scripts/python.exe -c "import requests; from Crypto.Cipher import AES; print('python deps ok')"
```

Windows PowerShell 中最后一条使用 `.venv\Scripts\python.exe`；Git Bash 中使用 `.venv/Scripts/python.exe`。
