# 破解全记录：从零到三通道加密完整还原

> 本文按时间线完整记录囧次元 (com.tudou.tool v1.5.8.0) 逆向的全过程：
> 每一步做了什么、为什么、看到什么、结论如何、走过的死路。所有中间产物都在仓库内可复核。

## 阶段〇：基线与环境

- 样本: `apk/base.apk` SHA256 `AC170C12...C5CBB9` (未动)，applicationId `com.tudou.tool`，
  smali 包 `app.video.guoguo`，Flutter 3.27.x / Dart 3.6.0
- 设备: 华为 LLD-AL20 (EMUI, Android 10, 1080×2340)，adb 有线
- 工具: Python 3.13 (pyelftools/capstone/pycryptodome/frida 17)、MinGW g++、cmake、ninja、
  uber-apk-signer、jadx

**关键困难与解法**（后续反复用到）:
- 无 root → frida 用 **gadget 模式**：把 `libgadget.so` + patched classes.dex 塞进 APK 重签
- EMUI 风险管控：unconfirm_app 状态下 **`am force-stop` 失效**，改用 **`am crash`**
- 安装弹窗自动化坐标：继续安装 (540,2040)/(823,2150)、继续使用/取消 (281,2150)、不再提示 (110,2030)
- **frida gadget 每个进程只支持一轮 script session**；python 端被 cancel 会把 gadget 搞死 → 每轮前 `am crash` 重启

## 阶段一：静态面 (第一会话)

1. **apktool/jadx 解包** → 端点全集 (40+)、`vmplugin.invoke_method` Lua 桥 (md5/aes128cbc/base64/httpGet)、
   windmill 广告插件。产出 `out/jadx_src`、初版 API_ANALYSIS.md。
2. **libcore.so 监控通道发现**: 导出 `init`/`call`，EVP hook 460 次捕获
   key=`qPwClBj7j7ZQraSm` iv=`p3JdVQl3q7WQJIgG` (AES-128-CBC)，2 秒心跳，416B 诱饵 JSON。
3. **auth 头结构**: 112B = 15B 常量前缀 `e8cb1f12...` + 1B flag + 96B 密文。
4. **大规模 key 搜索失败** (存档避免重做):
   - ASCII key 176,791 候选 × 结构假设 = 0
   - AES-128 二进制 16B 窗口扫 libapp/libcore/libloader/libflutter + 178MB 内存 dump = 0
   - AES-256 + SM4 全库扫描 = 0
   - pointycastle S-box 连续扫描不可行 (Dart const 列表是指针数组)
5. **去广告版 APK** 制作并交付 (15 方法 smali 补丁)。

## 阶段二：reFlutter 与 dump (第二会话前半)

1. **reFlutter 路线**: `reflutter base.apk` → patched 引擎替换。
   发现 Windows 大小写碰撞丢 238 个 res 文件 → 手术版 APK (逐条目复制 + 只换 libflutter.so)。
2. **安装手术版** → 启动 → `dump.dart` (4.7MB) 落在 `/data/data/com.tudou.tool/dump.dart`
   (权限 777, `adb shell cat` 直读, 注意 MSYS 路径转换需引号内路径)。
3. **dump 解析**: 29,735 个 `{method_name, offset, library_url, class_name}` JSON 对象。
   关键发现: **`apiEncrypt`/`apiDecrypt` 在 `FFIUtils` 类** (package:guoguo/utils/ffi_utils.dart)
   → 加密走 FFI 到 native！
4. **native 导出表**: libcore.so 有 `init @0x2fdc24` + `call @0x307a38` (32KB 分发器)；
   libloader.so 有 `call`/`reload`。
5. **组合包 APK**: 原始 base.apk 逐条目 + reFlutter libflutter.so + gadget loader dex + libgadget.so
   → 一次安装同时具备 dump 与 frida (`reflutter_work/combo.RE-gadget-aligned-debugSigned.apk`)。

## 阶段三：frida native hook (第二会话中)

1. hook libcore!call/init + libloader!call + `aes_v8_set_encrypt_key` 等:
   - 监控 key 复确认 (aes_v8 层 key=`qPwC...`)
   - libcore!call 每 2 秒心跳，x0=556 字符 b64，返回 0x280
   - **API 请求的加密不经过任何 native AES 导出** → 指向 Dart 层
2. **Dart 层 hook 攻坚** (dump offset → 运行时地址 = `libapp.base + 0x4b6b40 + offset`):
   - 命中 `Encrypter.encrypt`/`AES.encrypt` (encrypt 包): 全部为心跳诱饵 JSON 加密 (403B)
   - 命中 `TokenInterceptor.onRequest` / `FFIUtils.apiEncrypt` / `apiDecrypt` / `HttpClient.post`
   - **HTTP 主 API 服务器现身**: `http://43.145.33.254:27990/app/...`
   - 调用配对: apiEncrypt ↔ libloader!call (当时误判为远程信令，后修正为本地 IPC)
3. **Dart 对象布局** (hex 转储 + python 解析确立):
   - 堆基址 `0x7100000000`，地址形如 `0x7101xxxxxx`
   - OneByteString: tags@+0 (u32)、hash@+4、**len Smi@+8 (u32, 值=len<<1)**、data@+16
   - (踩坑: 曾把 len 当 64 位读、把堆前缀判成 `===0x7100` 而漏掉 0x7101+，导致多轮 chase 空)
4. **抓到 HTTP 响应密文与 URL 全文** (`/app/video/record`、`/app/video/play-connect`、
   `/app/video/play`、`/app/video/device-base`、`/app/config/video`、`/app/config/channel`)
   ——但解密失败：响应不是 qPwC/kFGT 任何已知 key → **会话 key 假设成立**。

## 阶段四：blutter 静态还原 (第三会话)

1. **blutter 构建三坑**:
   - cmake configure 崩 0xC0000409 → 根因**中文路径** → `mklink /J C:\blutter_w` junction 解决
   - CodeAnalyzer 崩 0xC0000409 → **no-analysis 编译变体** (`-DNO_CODE_ANALYSIS=1`) 绕过
   - bat 里 printf 把 `\b` 转义成退格 → heredoc 写文件
2. **blutter 运行成功**: 自动识别 Dart 3.6.0，Dart VM 源码编译 + blutter exe 产出
   `pp.txt` (对象池 2.6MB) / `asm/` (102 包) / `objs.txt` / `blutter_frida.js`。
3. **地址系统对齐验证**: blutter addr − 0x4b6b40 (isolate instructions st_value) == reFlutter dump offset ✓

## 阶段五：密钥破晓 (第三会话，决定性一步)

**pp.txt 搜索 16 字符高熵常量**:

```
[pp+0x7000] "kFGTbLlOzFHQCIKp"     ← 紧邻 [pp+0x7010] Obj!AESMode{cbc} 枚举
[pp+0x7008] "F3q22XoM8l6T2Ydc"     ← 和 FFI NativeFunction<(Pointer<Utf8>)=>Pointer<Utf8>> 签名
[pp+0x335d0] "5zcygwb7SjBtiALZ"    ← 邻居是 talkingData (第三方 SDK key, 排除)
```

**立即验证**: 用 `libloader!call` 返回的真实响应密文解密 →

```
密文: VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY=
明文: {"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}
```

**信令通道 (kFGT/F3q2, AES-128-CBC PKCS7) 完全破解。**

## 阶段六：语义修正与 HTTP 层收网

1. **信令通道语义修正**: 返回的 `address` 是 `0x723...` 本进程内存地址 →
   `libloader!call` 是 **native↔Dart 的本地 FFI 回调 IPC** (查询 app 信息)，
   **不是远程服务器通信** (kFGT 加密的本地 IPC)。
2. **X-Token 机制**: TokenInterceptor 池引用 `X-Token`/`new-token` →
   token 是服务器签发、客户端回传。**重放实验**:
   - 无 authentication → 30000 "authentication is empty"
   - 旧 token + 新 ts → 403501 "校验客户端签名失败" (token 绑定 ts/nonce)
   - 旧 token + 旧 ts → 403502 "设备时间异常"
   ⇒ 离线纯重放不可行，必须真机登录换新 token。
3. **HTTP body 加密链闭合** (HeadersInterceptor 反汇编直接调用):
   `clearKey → apiEncrypt → getRandomString×2 (随机 key/iv) → AES-CBC(P1) + RSA-2048(P0=256B)`
   → body = `"<P0_b64>.<P1_b64>"`，响应同会话 key。
4. **qPwC/kFGT 解 P0.P1 全部失败** (符合随机 key 设计)；pp 候选 199 × IV 60 全扫、RC4 假设全灭。

## 阶段七：手动操作 + 实时监控 (第四会话，当前)

用户提出"我手动操作、你后台监控"模式，绕开弹窗自动化：
- hook 套件迭代 5 版 (native → Dart 字符串 → chase → raw hex → 修复堆前缀 bug)
- **收获**: 全端点流量图谱 (record/play-connect/play/device-base/config.video/config.channel)、
  完整响应密文样本、信令通道全部解密
- 遗留: HTTP 会话 key 的运行时抓取 (getRandomString leave 不可 hook，返回值路径特殊)

## 方法论复盘

| 有效 | 无效/踩坑 |
|---|---|
| blutter 对象池挖常量 (决定性) | 盲扫二进制 16B 窗口找 key (几十万候选全灭) |
| 已知明文-密文对验证假设 | 无明文对时枚举算法假设 |
| raw hex 落盘 + python 解析对象布局 | JS 端解析 Dart 对象 (堆前缀 bug 隐蔽) |
| `am crash` 重启进程 | `am force-stop` (管控态失效) |
| 每进程一轮 script, 用完即重启 | 同进程二次 create_script (超时) |
| junction 规避中文路径 | 让 MSVC 工具链直接吃中文路径 (cmake 崩) |
