# 逆向分析模块清单与安装记录

> 在已搭好的雷电14 环境（见 [环境搭建](ldplayer-magisk-env.md)）之上，安装用于
> **抓包解密 / SSL 绕过 / Root 隐藏 / 动态注入** 的 Zygisk 与 LSPosed 模块。
> 全部命令实测，加载结果取自 Zygisk Next 与 LSPosed 的运行日志。

## 0. 选型思路

目标 App `com.tudou.tool` 是 **Flutter 壳 + 自研三通道加密**，因此模块优先级为：

1. **Flutter 流量拦截**（对应本项目主线）→ `FlutterTap`
2. **SSL Pinning 绕过**（否则抓不到明文）→ `TrustMe` / `SSLUnpinner`
3. **Root / 环境隐藏**（防目标 App 检测）→ `Zygisk-Assistant` / `HMA-OSS`
4. 动态注入与抓包工具链（frida-server，已单独部署）

**前置硬约束**：雷电是 **x86_64**，而大量 Zygisk 模块只编译 arm64。
所以选型第一步是**验证模块内含 `zygisk/x86_64.so`**，否则装了也不会加载。

```python
# ABI 预检脚本（下载后先跑）
import zipfile
z = zipfile.ZipFile('模块.zip')
print([n for n in z.namelist() if 'zygisk' in n])
# 必须能看到 zygisk/x86_64.so
```

## 1. 已安装模块总表

| 模块 | 类型 | 版本 | x86_64 | 作用 | 上游 |
|---|---|---|---|---|---|
| **FlutterTap** | Zygisk | v1.0.0 | ✅ 4.08 MB | 把指定 Flutter 应用的流量重定向到代理，并绕过 TLS 证书校验 | `script-or-script/FlutterTap` (123★) |
| **TrustMe** | LSPosed | v1.3.0 | 纯 Java | SSL 证书固定绕过 | `kirklin/TrustMe` (46★) |
| **SSLUnpinner** | LSPosed | 8f31de38 | 纯 Java | SSL Pinning 绕过（支持 Android 14+） | `pccr10001/SSLUnpinner` (39★) |
| **Zygisk-Assistant** | Zygisk | v2.1.4 | ✅ 291 KB | Root 隐藏（Magisk/KSU/APatch 通用） | `snake-4/Zygisk-Assistant` (2618★) |
| **HMA-OSS Zygisk** | Zygisk | oss-168 | ✅ 13 KB | 隐藏应用列表 / 包安装信息，反检测 | `frknkrc44/HMA-OSS` (3347★) |

配套 App（管理器，需单独安装）：

| App | 包名 | 用途 |
|---|---|---|
| FlutterTap Manager | `com.eduardolopes.fluttertap` | 选择目标 App + 配置代理 IP/端口 |
| HMA-OSS | `org.frknkrc44.hma_oss` | 配置隐藏策略 |
| TrustMe | `hk.kirk.trustme` | LSPosed 模块，管理器内勾选生效 |
| SSLUnpinner | `li.power.app.sslunpinner` | 同上 |

## 2. 安装步骤

### 2.1 推送（注意路径陷阱）

```bash
export MSYS_NO_PATHCONV=1
# ❌ 推到目录形式（/data/local/tmp/mods/ 或 /sdcard/Download/）在本环境会"报成功但不落盘"
# ✅ 逐文件显式指定目标文件名
adb push "模块.zip" /data/local/tmp/模块.zip
```

### 2.2 Zygisk 模块（走 magisk CLI，无需 GUI）

```bash
adb shell "su -c 'magisk --install-module /data/local/tmp/FlutterTap-v1.0.0.zip'"
adb shell "su -c 'magisk --install-module /data/local/tmp/Zygisk-Assistant-v2.1.4-release.zip'"
adb shell "su -c 'magisk --install-module /data/local/tmp/HMA-OSS-ZYGISK-oss-168-release.zip'"
```

HMA-OSS 安装时输出关键行（自动识别 Zygisk Next 并放对架构）：

```
- Device arch: x64
- 检测到 ZygiskNext / NeoZygisk 框架
- Placing x86_64 libraries
```

> HMA-OSS 的 `customize.sh` 里那步自动装 manager 会失败
> （`INSTALL_FAILED_INVALID_APK: No packages staged`），手动装 `manager.apk` 即可。

### 2.3 LSPosed 模块（APK 形式）

```bash
adb install -r "宿主机绝对路径/TrustMe-v1.3.0-release.apk"
adb install -r "宿主机绝对路径/SSLUnpinner.apk"
```

> `adb install` 的参数是**宿主机路径**，传 `/data/local/tmp/x.apk` 会报
> `failed to stat`。

### 2.4 重启激活

```bash
ldconsole.exe reboot --index 0
```

## 3. 验证：Zygisk Next 加载日志

```bash
adb shell "su -c 'grep -a zygisk /data/adb/lspd/log/verbose_*.log'"
```

实测输出（`zn-daemon64` 为 Zygisk Next 守护进程）：

```
I/zn-daemon64  loading 64bit zygisk modules
I/zn-daemon64  loaded 64bit zygisk module zygisk_lsposed
I/zn-daemon64  loaded 64bit zygisk module fluttertap
I/zn-daemon64  loaded 64bit zygisk module zygisk-assistant
I/zn-daemon64  loaded 64bit zygisk module hma_oss_zygisk
I/zn-daemon64  loaded 4 64bit zygisk module(s)
I/zn-daemon64  loading 32bit zygisk modules
I/zn-daemon64  loaded 32bit zygisk module zygisk-assistant
I/zn-daemon64  loaded 32bit zygisk module hma_oss_zygisk
I/zn-daemon64  loaded 2 32bit zygisk module(s)
```

`/data/adb/zygisksu/modules_info` 也记录了每个模块被 mmap 的 so 与大小：

```
zygisk_lsposed  64 fd=8  ino=00001045 sz=2191360
fluttertap      64 fd=9  ino=00001097 sz=4100096   ← x86_64.so 已加载
zygisk-assistant 64 fd=10 ino=00001109 sz=327680
hma_oss_zygisk  64 fd=11 ino=00001146 sz=20480
```

## 4. 启用 LSPosed 模块（无需点 GUI）

LSPosed 会自动发现模块（写入 `modules` 表），但默认**未启用、无作用域**。
设备自带 `sqlite3`，可直接改库：

```bash
DB=/data/adb/lspd/config/modules_config.db

# 看现状
adb shell "su -c \"sqlite3 -header $DB 'SELECT * FROM modules; SELECT * FROM modules_state'\""

# 启用 + 绑定作用域到目标 App
adb shell "su -c \"sqlite3 $DB \\\"
  INSERT OR REPLACE INTO modules_state(module_pkg_name,user_id,enabled,scope_request_blocked)
    VALUES('hk.kirk.trustme',0,1,0);
  INSERT OR REPLACE INTO scope(module_pkg_name,app_pkg_name,user_id)
    VALUES('hk.kirk.trustme','com.tudou.tool',0);
\\\"\""
```

库结构（便于按需扩展）：

| 表 | 字段 |
|---|---|
| `modules` | `module_pkg_name`, `apk_path` |
| `modules_state` | `module_pkg_name`, `user_id`, `enabled`, `scope_request_blocked` |
| `scope` | `module_pkg_name`, `app_pkg_name`, `user_id` |
| `module_configs` / `app_configs` / `lspd_configs` | 模块与框架配置（blob） |

改完库后需重启（或重启 zygote）让 LSPosed 重新读取。

## 5. 模块加载优先级与冲突提示

| 注意点 | 说明 |
|---|---|
| 内置 Zygisk 必须关闭 | 否则 Zygisk Next 会报 `Please disable built-in zygisk of magisk` |
| FlutterTap 依赖 Zygisk | 安装日志会提示 `Make sure Zygisk (or Zygisk Next) is enabled` |
| FlutterTap 默认无目标 | 安装后**必须**打开 manager 选择目标 App 并填代理地址，否则不生效 |
| HMA-OSS 依赖 Zygisk Next | 安装时会检测框架，KernelSU 场景走 `21-enforce-ksu-kernel.sh` 分支 |
| Shamiko 不适用 | 要求 Magisk >27005，Kitsune 为 27002，改用 Zygisk-Assistant |

## 6. 社区与资源

| 社区 / 仓库 | 地址 | 说明 |
|---|---|---|
| **LSPosed 官方模块仓库** | `https://modules.lsposed.org/` | 模块集中索引（本机因网络未加载成功，日志有 `Failed to load repo`） |
| **Magisk 模块仓库** | `https://github.com/Magisk-Modules-Repo` | 官方模块收录组织 |
| **Magisk 备选仓库** | `https://github.com/Magisk-Modules-Alt-Repo` | 社区维护的备选模块集 |
| **看雪安全社区** | `https://bbs.kanxue.com/` | 中文 Android 安全/逆向主论坛，有「算法助手」等教程 |
| **吾爱破解 · 移动安全区** | `https://www.52pojie.cn/forum-65-1.html` | 中文 Android 破解/加密分析讨论区 |
| **XDA Forums** | `https://xdaforums.com/tags/lsposed/` | 英文 LSPosed/Magisk 模块与机型讨论 |

GitHub 按 topic 检索模块：

```
https://github.com/topics/magisk-modules
https://github.com/search?q=topic%3Alsposed+module&type=repositories
https://github.com/search?q=zygisk+module&type=repositories
```

## 7. 待评估候选（已检索，未安装）

| 项目 | 星标 | 用途 | 未安装原因 |
|---|---|---|---|
| `tin537/AStools` | 37 | LSPosed 安卓安全工具箱 | 最后更新 2023-12，Android 14 兼容性未知 |
| `j-hc/zygisk-detach` | 2151 | 把应用从 Play 商店解绑 | 与当前分析目标无关 |
| `MhmRdd/NoHello` | 1356 | Root 隐藏（备选） | 与 Zygisk-Assistant 功能重叠 |
| `theShinigami/MaFrida` | 41 | Magisk 化 frida-server 开机自启 | 现用 `nohup` 手动拉起，够用 |
| `qiang/Riru-ModuleFridaGadget` | 177 | Riru 版 frida gadget 注入 | 依赖 Riru，与 Zygisk 路线冲突 |
| `badjtsx/frida-gadget-lsposed-injector` | 3 | LSPosed 注入任意 so | 星标低，暂缓 |

## 8. 与本项目的关系

- **FlutterTap** 直接对应本项目主线（Flutter 流量 + 证书绕过），可用于替代/补充现有的
  `research/deliverables/client/` frida 脚本族做抓包验证。
- ⚠️ 但请注意 [环境搭建](ldplayer-magisk-env.md) 第 9 节的结论：
  `com.tudou.tool` 仅含 arm64 原生库，在雷电 x86_64 上会崩于 `libhoudini.so`。
  **这些模块在 x86_64 上加载正常，但目标 App 本身跑不起来**——
  动态分析仍需换 arm64 环境。
