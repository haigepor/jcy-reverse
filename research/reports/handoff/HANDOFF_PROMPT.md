# 囧次元 APK 逆向 — 新会话续接提示词

把下面整段复制到新对话作为第一条消息。工作区不变：`C:\Users\haige\Desktop\instruct\囧次元`

---

## 任务背景（总目标链）

囧次元视频 App 逆向（Flutter 壳 + 自研加密协议）。最终交付四件东西：
1. **视频播放接口全链路分析**（列表→详情→播放地址，含全部参数）
2. **登录/注册逻辑分析**（设备静默登录机制，无传统账密接口）
3. **API 加解密完整逆向**（能离线构造合法请求、解密响应）
4. **示例 HTML 页**（渲染视频列表 + 播放器，用真实接口数据）

原始样本 `apk/base.apk`（SHA256 `AC170C12F20107533342BC32798564FB13BDA95EB0624ABB64DF30F886C5CBB9`）保持未动。已交付去广告版 `out/base_adfree_final-aligned-debugSigned.apk`（15 方法 smali 补丁）。

App 基本参数：`applicationId=com.tudou.tool`，smali 包 `app.video.guoguo`，versionName 1.5.8.0 (versionCode 88)，targetSdk 35，Flutter 3.27.x / Dart 3.6，Lua 壳在 `libloader.so`+`liblua-core.so`（仅图片下载，已排除与 API 加密无关）。

## 环境

- Windows 11 + Git Bash（MSYS2）。MinGW g++ 16.1 / cmake 4.2.3 / ninja / Python 3.13（有 pyelftools、capstone、pycryptodome、cryptography、reflutter）
- 设备：华为 LLD-AL20（EMUI，Android），adb = `./tools/platform-tools/adb.exe`（在囧次元目录下用相对路径）
- 签名：`java -jar tools/uber-apk-signer.jar --allowResign -a <apk>`（自动 zipalign+v2/v3 签名，java 可用）
- frida gadget 流程已建好：`tools/libgadget.so` + `out/build_gadget_apk.py`（装 gadget 的 APK、forward tcp:27042、`attach('Gadget')`；frida 17 API：用 `p.readByteArray(n)` 实例方法、模块实例 `m.findExportByName(sym)`）
- EMUI 安装弹窗自动化坐标（1080x2340 屏）：「继续安装」= tap 540 2040；「继续使用」= tap 270 2130；「移入管控」弹窗点「取消」= tap 270 2130；安装来源确认页等待「正在安装...」消失
- 启动命令：`$ADB shell am start -n com.tudou.tool/app.video.guoguo.SplashActivity`（monkey 起不来，必须 am start）

## 已确认结论（全部有硬证据，别重做）

**监控通道（libcore.so，已完全破解）**：AES-128-CBC，key=`qPwClBj7j7ZQraSm`，iv=`p3JdVQl3q7WQJIgG`，2 秒心跳，密文 416B→400B 诱饵 JSON（随机 16 字符键值对填充藏真实指令如 `"action":"get_record"`），响应 119B→128B `{"action":null,"code":200,"payload":{"list":[{"action":"apk_sign","params":"false"},{"action":"vpn","params":"true"}]}}`。EVP 钩子 460 次确认。`out/evp_hook.js` + `out/gg_evp_hook.py` 可复跑。

**auth 头（Dart 路径，结构已破译）**：112B = 15B 恒定头 `e8cb1f120ef5a42c59e22a4d00279e` + 1B flag（`9c..9f`，低 2bit=请求序号）+ 96B 密文（6 AES 块）。行为学：C0(=auth[16:32]) 对每个 ts 唯一（25 ts → 25 个 C0）；同 ts 不同 URI → 密文前 4 块相同、第 5 块起分叉 → 明文 P[0:64]=f(ts)、P[64:32]=f(nonce,URI)。恒定头不是明文硬编码（libapp/libcore/libloader/dump 全搜过不存在）。

**请求体格式**：POST body = b64 文本，`.` 分隔两段：`P0.P1`。P0=256B（随 endpoint 变，15 个不同 blob；RSA-1024 公钥 `out/RSA_PUBLIC_KEY.pem` 对 P0 两半块均无 PKCS1 结构，P0[128:]≥n，不是该钥匙的密文）；P1=变长 16 倍数（play=656B、play-connect=432B、record=96B、give_me=48B…）。play-connect 5 次请求 body 完全相同 → 确定性加密（固定 IV 或 ECB）。密文 XOR 差分无零前缀 → 排除 CTR/OFB 静态密钥流 → CBC/ECB 模型。

**API 双路径**：native 路径（config/upgrade，大写头）vs Dart 路径（e8cb1f12 前缀，小写头 appid/ts/nonce/tcs/x-version，UA `Dart/3.6 (dart:io)`）。EVP 日志只有监控通道一把 key → native 路径用 libcore 自带 AES+SM4 表（S-box 在 libcore.so @1965056、SM4 S-box @2143792，libloader 同款 @1468048/@1847824，双库完全一致）。

**已排除（别再试）**：
- Lua 层加密（17,058 chunks 全是 LuaSocket 库代码）
- ASCII key：176,791 候选 × 全结构假设 = 0
- AES-128 二进制 16B 窗口：libapp.so + libcore + libloader + libflutter + 178MB 内存 dump 全扫（printable+PKCS7 强 oracle）= 0
- AES-256 + SM4：四个 native 库全扫 = 0（dump 的 AES-256/SM4 未跑完，低优先）
- pointycastle S-box 连续字节扫描：Dart 里 const 列表是 Smi 指针数组不是字节数组，找不到是正常的

**关键突破（本会话最后）**：`libapp.so` **未开混淆**，Dart 符号全可读。已确认存在：`utils_aes128cbc_encrypt`（libapp.so 偏移 1081127 的字符串表）、`utils_aes128cbc_decrypt`（1144516）、`apiEncrypt`（1234036）、`apiDecrypt`（1149155）、`ApiEncryptException`、`Encrypter`、`Encrypted.fromUtf8/fromBase64`（encrypt 包）、`TokenInterceptor`、`UserToken`、`GUpdateData.fromJson`、`DailySigner`、`buildSignature` 等。**AES-128-CBC 由函数名直接确认**。请求明文 JSON 结构（native malloc 区见过）：`{"payload":{"authentication":"<auth b64>","data":"P0.P1"}}`。

**snapshot hash**：`f956f595844a2f845a55707faaaa51e4` = Flutter 3.27.0–3.27.4（reFlutter enginehash.csv 七行命中）。libapp.so ELF dynsym：`_kDartIsolateSnapshotData @0x4280`（4.8MB）、`_kDartIsolateSnapshotInstructions @0x4b6b40`（7.4MB，代码段）。

## 当前断点（被中断时的精确状态）

reFlutter dump 模式路线已走到 90%：
1. ✅ `reflutter -p base.apk` 跑完 → `reflutter_work/release.RE.apk`（patched 引擎替换版）
2. ✅ 发现 reFlutter 在 Windows 上大小写碰撞丢 238 个 res 文件（`res/2F.xml` 被写成 `2f.xml` 的内容）→ 直接装会 crash（`Resources$NotFoundException: res/hq.xml`）
3. ✅ **手术版已构建并校验**：`reflutter_work/surgery.RE-aligned-debugSigned.apk` = 原始 base.apk 逐条目复制 + 只替换 `lib/arm64-v8a/libflutter.so`（10812728B，reFlutter patched 引擎）+ uber 签名。1961 条目全在，非引擎条目与原始 0 差异，`res/hq.xml` 完好
4. ❌ 安装进行到一半被取消（`adb install` + EMUI 弹窗自动化循环被中断），当前设备上没有装这个包

## 下一步执行序（按顺序做）

1. **装手术版**：`$ADB uninstall com.tudou.tool`（可能已不在）→ `$ADB install reflutter_work/surgery.RE-aligned-debugSigned.apk` → EMUI 弹窗按上面坐标逐个点掉 → `pm list packages | grep tudou` 确认
2. **启动**：`am start -n com.tudou.tool/app.video.guoguo.SplashActivity`，sleep 15（首次启动引擎要 dump 所有函数，慢）
3. **拿 dump.dart**：reFlutter patched 引擎会把全量函数表写到 app 数据目录。试 `$ADB shell cat /data/data/com.tudou.tool/dump.dart`（非 debuggable 不能 run-as，shell 也可能读不了 private 目录）→ 失败就试：`/sdcard/dump.dart`、`/sdcard/Android/data/com.tudou.tool/`、`find /sdcard -name dump.dart`。**都拿不到就用 frida 方案**：把 gadget 装进 surgery 版（套 `out/build_gadget_apk.py` 流程把 `tools/libgadget.so` 加进去），attach 后在进程内读文件回传（`new File('/data/data/com.tudou.tool/dump.dart').readText()` 或 frida 直接 open/read）
4. **dump.dart 解析**：JSONL，每行 `{"method_name":...,"class_name":...,"library_url":...,"offset":"0x..."}`。搜 `utils_aes128cbc_encrypt`、`apiEncrypt`、`buildSignature` 的 offset。reFlutter 还会自动生成配套 `frida.js` 模板（hook offset 用）
5. **frida hook 拿 key**：offset 是相对 Dart instructions image 起点（= libapp.so 里 `_kDartIsolateSnapshotInstructions` 或运行时映射的 instructions 段）——dump.dart 附带的说明/reFlutter 生成的 frida.js 里有基准算法，直接用。hook 到 utils_aes128cbc_encrypt 入口后 dump 寄存器 x0-x7 指向的 Dart 对象（AOT 调用约定，参数是压缩指针 0x7100000000 基）。**key/iv 是参数里的 Dart String 或 Uint8List，肉眼可辨**
6. key 到手后：先解 `auth_samples` 里 88 个样本的 96B 密文验证（CBC 块 1..5 解出来应可打印），再解 P1（JSON），再攻 P0（256B，若不是 RSA-1024 就找 2048 钥匙：libapp.so 里搜 `MIIBI`/`MIIBCg` b64 前缀或 DER 头 `30 82 02 0a 02 82 01 01 00`）
7. 跑通后写 `out/API_ANALYSIS.md`（接口链 + 登录注册逻辑：注意无 login/register 端点，是 device-base 静默设备登录，`UserToken`/`TokenInterceptor`/`X-Token` 符号是线索）→ 回填 `out/client/gg_client.py`（接口骨架已有，缺加密层）→ 写 HTML 示例页（列表 + 播放，播放器用 hls.js，视频源是 m3u8）→ 追加 `out/VERIFICATION.txt`

## 关键文件清单（都在 out/ 下）

- `auth_samples.json`（88 样本：st/uri/auth_b64/body_b64）、`auth_full_rows.json`（28 行：uri/auth_hex/ts/nonce/tcs）
- `ct_samples/*.hex`（35 个密文样本，`__AUTH`=printable oracle 用、`__P1`/`__BODY`=PKCS7+printable oracle 用）
- `cscan.c`/`cscan2.c`/`cscan.exe`/`cscan2.exe`（AES-128/AES-256+SM4 窗口扫描器，FIPS-197 + GB/T 32907 自测通过）
- `mem_dump.bin`（178MB）+ `.idx`（Dart 堆 0x7100000000/21MB、Java 堆、anon 区）
- `evp_hook.js`、`gg_evp_hook.py`、`gg_evp_coldstart.py`、`gg_dump.py`、`gg_native_hook.py`、`client/`（gg_client.py、frida 脚本们）
- `nativelibs/`（解出来的全部 .so：libapp 12.3MB、libflutter 10.8MB、libcore 6.8MB、libloader 6.2MB…）
- reFlutter CLI：`$LOCALAPPDATA/Packages/PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0/LocalCache/local-packages/Python313/Scripts/reflutter.exe`

## 风格要求

每步以命令输出为准，不推测。完成后追加 `out\VERIFICATION.txt` 审计链。所有交付文件完整、无 stub。
