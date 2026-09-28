# 分析脚本索引

`out/` 目录下共 **104 个脚本**，是逆向过程的完整工作记录。本索引按功能族归类。

> 分类依据：脚本头部注释、实际 import 依赖、`docs/analysis/toolchain.md` 记载的构建过程。
> 同名带数字后缀（如 `gg_dart_hook2`）为**迭代版本**，数字越大越接近最终可用版本。

## 一、Dart 快照 Hook（15 个）

通过 reFlutter dump offset 定位并 hook Dart AOT 函数，还原方法名与地址。

地址换算（`out/gg_dart_hook.js` 头部注明）：

```
运行时地址 = libapp.so base + 0x4b6b40 (isolate instructions st_value) + dump offset
```

| 文件 | 说明 |
|---|---|
| `gg_dart_hook.js` | 基线 hook 脚本（含 OneByteString 读取与 heap 前缀判定） |
| `gg_dart_hook.py` ~ `gg_dart_hook8.py` | 驱动迭代：attach、冷启动、日志落盘 `dart_log*.jsonl` |
| `gg_dart_hook3.js` ~ `gg_dart_hook8.js` | hook 脚本迭代，逐步补齐类名/方法名/地址三元组 |

## 二、加密层 Hook（9 个）

定位 `apiEncrypt` / AES 调用点与密钥常量。

| 文件 | 说明 |
|---|---|
| `gg_enc_hook.js` / `.py` | 基线：attach 后保持存活，配合手工 adb 驱动 UI |
| `gg_enc_hook2` ~ `gg_enc_hook5` | 迭代，逐步收敛到密钥提取 |

## 三、FFI 调用 Hook（6 个）

hook `vmplugin.invoke_method` 等 FFI 边界，捕获跨语言调用的明文与密文。

`gg_ffi_hook.js` / `.py` ~ `gg_ffi_hook5.py`，日志落 `ffi_log*.jsonl`。

## 四、认证链路 Hook（14 个）

抓取 X-Token / 设备静默登录的生成链，覆盖
`Encrypter` / `RSA` / `AES` / `getRandomString` / `HeadersInterceptor`。

`gg_auth_hook.js` + `gg_auth_driver.py`，迭代至 `gg_auth7_*`，日志落 `auth_rt*.jsonl`。

## 五、手工分步驱动（8 个）

处理 EMUI 双弹窗后分步执行 hook，避免一次性脚本被弹窗打断。

`gg_manual_hook.js` 1–4 + `gg_manual_driver.py` 1–4，日志落 `manual_log*.jsonl`。

## 六、端到端流水线（7 个）

`full_run.py` ~ `full_run7.py`：一次完成冷启动 → 装 hook → 清弹窗 → 触发新视频请求 → 落盘。
依赖 `PIL`（截图处理）与 `frida`。

## 七、专题 Hook 与驱动（约 20 个）

| 文件 | 说明 |
|---|---|
| `gg_luahook.py` / `gg_luahook2.py` | Lua 桥捕获：`LuaJNI.eval` / `LuavmPlugin.invoke_method` |
| `gg_evp_hook.py` / `gg_evp_coldstart.py` / `evp_hook.js` | OpenSSL EVP 层 hook |
| `gg_key_hook.js` / `gg_key_driver.py` | 密钥提取专题 |
| `gg_hex_hook.js` / `gg_hex_driver.py` | hex 帧捕获 |
| `gg_final_hook.js` / `.py` | 收敛后的最终 hook 组合 |
| `gg_native_hook.py` | native 层（libcore/libloader）hook |
| `gg_dump.py` / `gg_daemon.py` | 内存 dump 与常驻守护 |
| `dartscan.js` / `liveneedle.js` | 内存特征扫描（Dart 堆 / 实时指针） |
| `memscan_driver.py` / `pscan_driver.py` / `channel_driver.py` / `smart_drive.py` | 各类扫描与通道驱动 |
| `fs_hook1.py` / `fs_probe.py` | frida-server 探测 |

## 八、数据处理与验证（约 10 个）

| 文件 | 说明 |
|---|---|
| `analyze_keylog.py` | 密钥日志分析 |
| `parse_flows.py` | PCAPdroid flows 解析（→ `http_*.tsv`） |
| `scan_dump.py` | 内存转储扫描 |
| `strdump.py` | so 字符串导出（→ `libapp_strings*.txt`） |
| `dexdiff.py` | DEX 差分 |
| `try_keys.py` | 候选密钥批量试解 |
| `dec_test.py` ~ `dec_test4.py` | 解密验证迭代 |
| `pull_files.py` | 从设备拉取产物 |

## 九、构建与打包（8 个）

| 文件 | 说明 |
|---|---|
| `build_gadget_surgery.py` | 组合包构建：原 APK 逐条目复制 + reFlutter `libflutter.so` + gadget loader dex + `libgadget.so` |
| `build_gadget_apk.py` | gadget loader 版 APK 构建 |
| `rebuild_minimal.py` | 最小重打包 |
| `apply_adfree_patch.py` | 去广告补丁应用 |
| `run_blutter.bat` / `run_blutter_exe.bat` | blutter 运行封装 |
| `run_cmake.bat` / `run_cmake2.bat` / `run_cmake3.bat` | blutter 构建配置（含 no-analysis 变体） |

## 十、C 侧工具（3 个）

| 文件 | 说明 |
|---|---|
| `cscan.c` | 16 字节窗口 AES 密钥扫描器；CBC/ECB oracle，启动时用 FIPS-197 Appendix B 向量自检 |
| `cscan2.c` | 扫描器迭代版 |
| `authbrute.c` | authentication 头（112B = 15B 常量前缀 + 1B 生成位 + 96B 密文）离线密钥扫描器 |

编译：`g++ -O3 -march=native -o cscan.exe cscan.c`（MinGW）。
编译产物 `.exe` 不入库，见 `.gitignore`。

## 依赖汇总（实测统计）

| 模块 | 引用次数 | 归属 |
|---|---|---|
| `frida` | 51 | 分析必备，**版本须与设备端 frida-server 一致** |
| `PIL` (Pillow) | 8 | 截图与弹窗处理（`full_run*.py`） |
| `Crypto` (pycryptodome) | 6 | 解密验证与协议库 |
| `numpy` | 1 | 数值处理 |
| `requests` | — | `out/client/gg_client.py` HTTP 层 |

安装：

```bash
pnpm python:install            # 基础：requests + pycryptodome
pnpm python:install:analysis   # 分析：追加 frida / Pillow / numpy
```

## 复现建议

1. 先跑 `packages/protocol/tests/test_channels.py` 确认协议层可用
2. 静态分析走 `tools/apktool.jar` + `tools/jadx`，产物落 `out/base_smali` / `out/jadx_src`
3. 动态分析需要 arm64 真机或原生 ARM 模拟器（x86_64 转译层会 SIGSEGV，见 `docs/analysis/toolchain.md`）
4. hook 脚本按族取**数字最大的迭代版**作为起点，再按需裁剪
