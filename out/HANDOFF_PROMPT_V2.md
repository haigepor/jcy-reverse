# 囧次元 APK 逆向 — 新会话续接提示词 (V2, 2026-09-28)

把下面整段复制到新对话作为第一条消息。工作区不变: `C:\Users\haige\Desktop\instruct\囧次元`

---

## 任务背景（总目标链）

囧次元视频 App 逆向（Flutter 壳 + 自研加密协议，applicationId=com.tudou.tool，
versionName 1.5.8.0，Dart 3.6.0 / Flutter 3.27.x，snapshot hash f956f595844a2f845a55707faaaa51e4）。
最终交付四件：① 视频播放接口全链路分析 ② 登录逻辑分析（设备静默登录）③ API 加解密完整逆向 ④ 示例 HTML 页。

**当前完成度**：监控通道加密 100% 破解、信令通道加密 100% 破解、HTTP 层结构 100% 清楚
（端点/头/X-Token 机制/P0.P1 构架），四件交付物已写好并落盘。
**docsify 文档站已建成**（docs/ 目录，python -m http.server 8765 即可浏览）。
唯一遗留：HTTP body 的 P0/P1 逐字节离线构造（差 RSA 公钥来源 + 随机会话 key 的运行时抓取）。

## 仓库关键内容（全部在工作区内，路径相对囧次元根目录）

### 文档站（本轮新建成，docsify）
- `docs/index.html` — docsify 入口（CDN 加载，本地 `python -m http.server 8765` 后访问 localhost:8765）
- `docs/_sidebar.md` — 三大分组导航
- `docs/README.md` — 首页（成果速览/密钥速查/快速上手/仓库路径）
- `docs/crypto/overview.md` — 三通道架构总览（含架构图/密钥在二进制中的位置/诱饵 JSON 格式）
- `docs/crypto/monitor-channel.md` — 监控通道完整文档（算法/帧结构/真实指令样本/Python 复现）
- `docs/crypto/signaling-channel.md` — 信令通道完整文档（**注意已修正语义：本地 native↔Dart IPC，非远程**）
- `docs/crypto/http-body.md` — P0.P1 加密流程/调用链/已排除假设清单/响应密文样本
- `docs/crypto/x-token.md` — X-Token 机制/重放实验结果表
- `docs/api/overview.md` — 端点全集（配置/账号/视频/其他）+ 通用请求头 + 错误码
- `docs/api/video-list.md` — 列表接口（channel/sort/limit/page 参数、GVideoPage 预期结构、逻辑链路）
- `docs/api/video-play.md` — 播放链路（play→video/key→playaddr/v4/client→m3u8→#EXT-X-KEY→阿里播放器）
- `docs/api/device-base.md` — 设备静默登录机制
- `docs/api/endpoints.md` — 其余端点速查表（⊕ 标记 = 真机 hook 实际捕获过流量的端点）
- `docs/analysis/journey.md` — **破解全过程时间线（阶段〇~七，含所有死路与有效方法）**
- `docs/analysis/toolchain.md` — blutter 构建手册（三个坑+解法）/frida gadget 集成/Dart 对象内存布局/地址换算
- `docs/analysis/evidence.md` — 证据索引（每条结论 ↔ 原始产物路径）
- `docs/analysis/open-questions.md` — 遗留问题与实验设计（会话 key 获取的 4 个方案/pm clear 实验）

### 分析主文档（第一/二阶段成果）
- `out/API_ANALYSIS.md`（230 行）— 主分析文档：§1-7 静态分析（端点清单/头/加密原语/播放链路）+ 增补 A-E 节（三通道/修正/HTTP body 流程/端点补遗/工具产物）
- `out/VERIFICATION.txt`（166 行）— 审计链：第一阶段 [1]-[E] + 第二阶段 [F1]-[F8]

### 核心数据（抓包/hook 产物）
- `out/auth_samples.json` — 88 条抓包样本（st/uri/auth_b64/body_b64）
- `out/auth_full_rows.json` — 28 条完整头样本（uri/auth_hex/ts/nonce/tcs/xver），
  含列表完整参数 `/app/video/list?channel=1&sort=weight&limit=6&page=1`
- `out/ct_samples/*.hex` — 35 个密文样本（__AUTH=112B token、__P0=256B、__P1=变长）
- `out/key_log.jsonl` — **最新一轮真机捕获**：apiDecrypt.enter 的 x1（响应密文 hex，含
  /app/video/record、play-connect、play、device-base、config.video、config.channel、give_me 的完整响应密文）
  + x2（完整 URL）+ sig.call 19 帧（get_app_info 本地回调）
- `out/hex_log.jsonl` — hex 转储轮（78 条，apiEncrypt/apiDecrypt/HttpClient.post/HeadersInterceptor）
- `out/manual_log.jsonl / manual_log2.jsonl` — 手动操作轮捕获（含 libloader!call 完整收发帧）
- `out/ffi_log*.jsonl / dart_log*.jsonl` — 早期 hook 轮日志

### 工具与构建产物
- `out/blutter_out/` — **blutter 产物**（决定性工具）：pp.txt（对象池 2.6MB，密钥常量出处）、
  asm/（102 包函数索引，格式 `// ** addr: 0x..., size: 0x...`）、objs.txt、blutter_frida.js
- `reflutter_work/dump2.dart` + `dump2_parsed.jsonl` — reFlutter 全量符号（59470 个）
- `reflutter_work/combo.RE-gadget-aligned-debugSigned.apk` — **当前设备已安装的组合包**
  （原始 base.apk 逐条目 + reFlutter patched libflutter.so + gadget loader dex + libgadget.so，
  reFlutter dump 与 frida gadget 双能力，真机 dump.dart 已验证可用）
- `out/build_gadget_surgery.py` — 组合包构建脚本
- `out/client/gg_client.py` — Python 客户端（含已验证加密层：channel_encrypt/decrypt、
  monitor_frame、signaling_request/decrypt_response、http_headers；自测通过）
- `out/client/frida_vmplugin_hook.js` — Lua 桥 hook（旧）
- `out/demo/index.html` — 示例 HTML 页（hls.js 播放器 + 真实列表数据）
- `out/jadx_src/` — jadx 反编译源码
- `out/base_decoded/` — apktool 解包（assets/flutter_assets/packages/luavm/lua/ 是标准 LuaSocket 库）
- `out/nativelibs/` — 全部 so（libapp 12.3MB/libcore 6.8MB/libloader 6.2MB/libflutter 10.8MB 等）
- `apk/base.apk` — 原始样本 SHA256 AC170C12F20107533342BC32798564FB13BDA95EB0624ABB64DF30F886C5CBB9（未动）

## 已确认结论（全部有硬证据，不要重做）

### 三通道加密架构
1. **监控通道**（libcore.so `call @0x307a38`/`init @0x2fdc24` FFI 导出）：
   AES-128-CBC PKCS7，key=`qPwClBj7j7ZQraSm` iv=`p3JdVQl3q7WQJIgG`（hook aes_v8_set_encrypt_key 直接捕获）。
   2 秒心跳，帧=b64(416B 诱饵 JSON：~12 对随机 16 字符键值 + 藏真实 action 如 get_record/apk_sign/vpn)。
   加密在 Dart 层完成（__call @0x6eed7c 池含 qPwC + Encrypter 调用，backtrace 已证）。
2. **信令通道**（libloader.so `call @0x2A3D2C`/`reload` FFI 导出）：
   AES-128-CBC PKCS7，key=`kFGTbLlOzFHQCIKp` iv=`F3q22XoM8l6T2Ydc`
   （blutter pp.txt [pp+0x7000/0x7008]，紧邻 AESMode{cbc} 枚举）。
   **语义修正（重要）**：真机实证返回 address=0x723... 本进程内存地址——这是 **native↔Dart 本地 FFI 回调 IPC**
   （native 查询 app 信息，对应 FFIUtils.dartCallback/getAppInfo 系），**不是远程服务器通信**。
   响应实测解密：`{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}`。
3. **HTTP API**（dio 明文 HTTP `http://43.145.33.254:27990`）：
   - 头集合（HeadersInterceptor._onRequest @0xa3bdc8 池引用）：APPID=com.tudou.tool / ts=13位毫秒 /
     nonce=8位随机数字 / tcs=2 / x-version=2020-09-17 / authentication=<X-Token b64> / UA=Dart/3.6 (dart:io)
   - body=`"<P0_b64>.<P1_b64>"`：P0=恒256B（RSA-2048 包裹随机会话 key+iv），P1=变长业务 JSON 密文
   - 流程（反汇编实锤）：HeadersInterceptor → bl 0x716b7c clearKey → bl 0x7eee0c apiEncrypt →
     bl 0x715cb0 getRandomString ×2（随机 key/iv）→ AES-CBC(P1) + RSA(P0)
   - 响应用同一会话 key 加密（apiDecrypt @0x607518 解密）；错误响应明文
4. **X-Token**：服务器签发不透明 token（112B = 15B 前缀 e8cb1f120ef5a42c59e22a4d00279e + 1B 代次 + 96B 服务器侧密文），
   经响应头 new-token 下发（TokenInterceptor 池引用 X-Token/new-token 实锤），客户端只回传。
   **重放实验**：无 authentication → 30000；旧 token+新 ts → 403501 "校验客户端签名失败"；
   旧 token+旧 ts → 403502 "设备时间异常"。⇒ token 绑定 ts/nonce，离线纯重放不可行，必须真机 device-base 登录。
5. **地址换算**（两套系统互通，已验证 0xa3bc20-0x4b6b40=0x5850e0=TokenInterceptor.onRequest3）：
   运行时地址 = libapp.base + blutter_addr = libapp.base + 0x4b6b40 + reflutter_dump_offset
6. **Dart 对象布局**（arm64 compressed pointers）：堆基址 0x7100000000，地址 0x7101xxxxxx；
   OneByteString = tags@+0(u32,e0050000) + hash@+4 + len Smi@+8(u32,值=len<<1) + pad@+12 + data@+16
7. **关键函数 offset**（dump offset，运行时 +0x4b6b40）：
   apiEncrypt=0x3382cc、apiDecrypt=0x607518、getRandomString=0x715cb0（bl 0x5591e8 Random）、
   clearKey=0x26003c、__call=0x6eed7c、_rawCall=0x6eeca8、_loaderCall=0x72cf20、
   TokenInterceptor.onRequest=0x58507c、HeadersInterceptor.onRequest=0xa3bdc8-0x4b6b40=0x585288、
   HttpClient.post=0x213634、Encrypter.encrypt=0x238e6c、AES.encrypt=0x60383c、RSA.encrypt=0x603968

### 已排除（不要重复尝试）
- P0/P1 用 qPwC/kFGT 解（AES-CBC/ECB × 多 IV 全灭）
- pp.txt 199 个 16 字符串 × 60 IV 候选 × AES-CBC = 0；× RC4 = 仅短样本假阳性
- RSA 公钥内嵌于 libapp/libcore/libloader/APK assets（PEM/DER/b64 全格式）= 未找到 → 判定服务器下发
- ASCII key 176791 候选、AES-128 二进制窗口扫四库+178MB 内存、AES-256+SM4 全库 = 0（第一阶段）
- Lua 壳（luavm/lua/ 全是标准 LuaSocket 库）与主链路加密无关
- libcore 数据段无 "api_encrypt" 字符串（该 action 由 Dart 传入，native 侧用别的方式分发）

## 当前设备与运行状态

- 华为 LLD-AL20（adb=37KRX18825013759，`./tools/platform-tools/adb.exe`）
- 已安装：**组合包** `reflutter_work/combo.RE-gadget-aligned-debugSigned.apk`（reFlutter+gadget 双能力）
- EMUI 弹窗坐标（1080×2340）：不再提示复选框(110,2030)、继续使用/取消(281,2150)、
  继续安装(540,2040)底部版/(823,2150)右侧版、移入管控弹窗点取消(270,2130)
- 启动命令：`adb shell am start -n com.tudou.tool/app.video.guoguo.SplashActivity`（monkey 不行）
- frida 连接：`adb forward tcp:27042 tcp:27042` 后
  `frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')`

## 关键坑（血泪，必读）

1. **EMUI 管控**：unconfirm_app 状态下 `am force-stop` **失效**（进程杀不死）→ 用 `adb shell am crash com.tudou.tool`
2. **gadget 每进程仅一轮 script session**：create_script 二次必超时；python 驱动被 cancel 也会弄死 gadget
   → 每轮 hook 前 `am crash` + `am start` + sleep 25 秒（libapp 加载要 20+ 秒，attach 太早 libapp=null）
3. **中文路径**：cmake/MSVC 直接吃 `囧次元` 路径会崩（0xC0000409）→ junction `C:\blutter_w` 规避；
   bat 文件里不能有中文（用 %CD% 运行时展开）；cmd /c 的 /c 在 Git Bash 要写 `//c` 或 MSYS_NO_PATHCONV=1
4. **JS 端 Dart 字符串读取**：堆前缀必须覆盖 0x7100-0x712f（曾写 ===0x7100 漏掉全部）；
   async 函数参数不在寄存器（在闭包），chase 指针追踪不可靠 → **最稳是 raw hex dump（1600B/寄存器）落盘 + python 端解析**
5. **视频详情/播放有本地缓存**：重复打开同一视频不发网络请求 → 测请求要换没看过的视频
6. **frida send 第二参数只能是 ArrayBuffer**（字符串会报 expected buffer-like object）
7. 弹窗每轮冷启动重弹（双弹窗：风险提示→移入管控），先处理再驱动 UI

## 下一步工作方向（按价值排序）

1. **HTTP 会话 key 运行时抓取**（完成后 P0.P1 全闭环）——4 个方案见 docs/analysis/open-questions.md：
   FFIUtils 静态字段转储（completer@0x115c/_#ffiCallback0@0x1164 同区）/ apiEncrypt.enter 栈扫描 /
   Random stub 内联 hook / native api_encrypt 分支定位（libcore call 32KB 内，action 字符串不在数据段是坑）
2. **pm clear 首装实验**：`adb shell pm clear com.tudou.tool` 清数据 → 冷启动 → 抓首个 /app/config
   请求/响应（初始状态无会话 key，响应必可解）→ 拿 RSA 公钥 → P0 构造闭环
3. **getRandomString 种子规则**：play-connect 同参数 5 次同 body 证明种子确定（可复算）；
   实验：同一秒发两次同参数请求看 body 是否相同（区分时间播种/固定 seed）
4. 交付物收尾：demo/index.html 的 play 字段填入真实 m3u8（会话 key 到手后解 play 响应即得）

## 风格要求

每步以命令输出为准，不推测。完成后追加 out/VERIFICATION.txt 审计链。
所有交付文件完整、无 stub。hook 驱动脚本放 out/，文档改动同步 docs/ 与 out/API_ANALYSIS.md。
