# tools/ — 逆向工具链

本目录存放本项目使用的第三方逆向工具，**因体积与版权原因不入库**，仅本地保存。

## 自动安装

工具安装清单集中在根目录 `config/tools.json`，无需手工下载和改路径：

```bash
pnpm install             # Node 依赖 + core 工具 + Python 环境
pnpm tools:install       # 只安装 core 工具
pnpm tools:install:all   # 追加 blutter / PCAPdroid / Frida Gadget
pnpm tools:status        # 查看安装状态
```

下载失败时可设置 `JCY_HTTP_PROXY`，或在网络恢复后重复执行命令；已存在的工具会自动跳过。

本地完整目录如下：

| 工具 | 形态 | 用途 | 获取方式 |
|---|---|---|---|
| `blutter/` | 源码构建（734 MB） | Flutter/Dart 快照反编译，产出 pp.txt/asm | https://github.com/worawit/blutter |
| `jadx/` | 解压目录 | DEX → Java 反编译器 | https://github.com/skylot/jadx/releases |
| `platform-tools/` | 解压目录 | adb / fastboot（设备连接、截屏、pull） | https://developer.android.com/tools/releases/platform-tools |
| `apktool.jar` | jar | APK 解包 / smali 重打包 | https://apktool.org |
| `uber-apk-signer.jar` | jar | APK 对齐与调试签名 | https://github.com/patrickfav/uber-apk-signer |
| `PCAPdroid_v2.0.2.apk` | apk | 设备端抓包（无需 root） | https://github.com/emanuele-f/PCAPdroid |
| `libgadget.so` | so | Frida Gadget（注入非 root 设备） | https://github.com/frida/frida-gadget |
| `fs` | ELF | blutter 构建用 rootfs 可执行文件 | blutter 构建产物 |
| `re-env/` | 脚本 | 本项目环境辅助脚本 | 本项目维护 |

## 典型工作流

```
apk/base.apk ──apktool──▶ out/base_smali(_patched)/ ──uber-apk-signer──▶ 设备安装
     │
     └──blutter──▶ out/blutter_out/（pp.txt 对象池 + asm）
                    │
                    └──frida(libgadget)──▶ out/gg_*.js hook 脚本族
```

> 恢复环境时，按上表链接下载并放置到对应子目录即可。
