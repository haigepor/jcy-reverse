# 囧次元 (com.tudou.tool / package:guoguo) 接口与加密规则深度分析

取证来源: `out/jadx_src`(jadx 1.5.6 反编译) + `libapp.so` 字符串池(Dart AOT) + smali。
静态分析日期: 2026-09-27。所有字段值均为静态证据; 标注 [动态待捕] 的需真机抓包确认。

---

## 1. 总览架构

```
Dart UI (libapp.so, AOT)
  ├─ provider: api_utils/*   (riverpod)
  ├─ HTTP:     Dio + Interceptors
  ├─ 解析:     luavm (Lua 脚本引擎) + vmplugin.invoke_method 原生桥
  ├─ 签名:     package:pointycastle (AES/SHA 家族) + RSA(内嵌 PUBLIC KEY)
  └─ 视频面:   m3u8/HLS 解析 + 段加密 (#EXT-X-KEY) + 阿里播放器
```

方法通道 (Flutter↔Native):
| 通道 | 处理器 | 作用 |
|---|---|---|
| `com.windmill.ad` + `com.windmill/{splash,interstitial,banner,native,reward}` | windmill_ad_plugin | 广告 (此工作流已 stub) |
| `app.video.guoguo/TalkingData` | p015f.n | 埋点 |
| `vmplugin.invoke_method` | com.github.tgarm.luavm.LuavmPlugin | Lua ↔ 原生桥: md5/timestamp/base64/aes128cbc/httpGet |

---

## 2. 接口清单 (40+, 全部经实测存在)

### 2.1 主机
- `http://pzl.clicli.blog:8087` — 主 API
- `http://pzl.clicli.blog:8088` — 分享域 (GShareDomain: port 可配置)
- `https://vod.api.zshtys888.com` — 点播解析域
- `https://movie.douban.com/` — 元数据 (猜测: 搜索补全)

### 2.2 配置/体系
| 方法 | 路径 | 返回模型 | 说明 |
|---|---|---|---|
| GET | /app/config | GAppConfig(data:[GAppConfigItem]) | 含 `get_host_config`、`talkingData`、talkingDataVersion |
| GET | /app/update | GUpdate/GUpdateData | 版本更新; 字段含 `{"downloadIndex":` |

### 2.3 账号
| 路径 | 说明 |
|---|---|
| /app/users/smscode | 发短信验证码 |
| /app/users/captcha | 图形验证码 |
| /app/users/register | 注册 |
| /app/users/login | 登录 → LoginInfo → user_token / X-Token |
| /app/users/info / change / update / retrieve / picture | 资料 |
| /app/users/logout | 退出 |
| /app/qr_login/scan / qrconfirmlogin | 扫码登录 |

### 2.4 视频 (核心业务)
| 路径 | 返回 | 说明 |
|---|---|---|
| /app/video/list | GVideoPage(total) | 列表 |
| /app/video/detail | GVideoDetail(data) | 详情 |
| /app/video/search | | 搜索 |
| /app/video/play | | 播放凭证/起播 |
| /app/video/play-connect | | 播放心跳 |
| /app/video/key | | 播放密钥 (RSA/AES 交换环节) |
| /app/playaddr/v4/client | GUrlParsed(name, raw_play_url, m3u8FileDomain) | **播放地址解析主接口** |
| /app/video/authenticatePlayVideo | | 播放鉴权 |
| /app/video/download / record / gold / buy / device-base | | 下载/记录/金币/购买/设备 |
| /api/league/app/loadAdPositionConfig / getAuthorization / domain/heartbeat / /api/v1/league/ad/getAd | | 广告位配置 (联盟SDK) |

### 2.5 评论/弹幕/任务/VIP
- 评论: /app/vod_comment/{captcha,create,getlist,getsublist,gettop,gethitstopH,likes,report}, /app/vod_report/create
- 弹幕: /api_utils/danmaku/danmaku
- 任务: /api_utils/task/task (GTask(item.coin))
- VIP: /app/vip_price/{list,buy} → GVipPrice/GVipPriceItem(coin), /app/vip_ticket/exchange

---

## 3. 请求头与签名术语 (libapp.so 高置信度词表)

```
X-Token            登录后 user_token
appid              应用 ID (常量)
timestamp          秒级时间戳 (utils_timestamp)
nonce              随机数
apk_sign           APK 签名相关值
signnum            计数
secretid           密钥 ID
current_timestamp
api_encrypt        服务端下发: 本 API 是否启用加密
extends            服务端下发: 参与签名的字段名单
extend_sign_encourage   GSignRuleData 强力签名字段
lua_header         注入 Lua httpGet 的额外 header
raw_play_url       播放地址原始 URL (GUrlParsed)
```

---

## 4. 加密原语 (全部实证)

| 原语 | 位置 | 证据 |
|---|---|---|
| md5 | Lua utils.md5 → vmplugin | `utils_md5` |
| base64 (byte/utf8) | Lua utils.base64_encode/decode → vmplugin | option {"mode":"byte"} |
| **AES-128-CBC + PKCS7** | Lua utils.aes128cbc_{en,de}crypt(key,iv,data,{padding}) → vmplugin | key/iv 16B 字节数组 |
| **SHA1/SHA256/SHA384/SHA224** | pointycastle digests | `SHA384Digest` 等 |
| **RSA** | pointycastle `RSASigner/PSSSigner` + `-----BEGIN PUBLIC KEY-----` 内嵌 | `06082a864886f70d0205` |
| HMAC | pointycastle mac | `package:pointycastle/src/api/mac.dart` |
| 时间戳 | utils_timestamp | 秒级 |

签名规则字段 (服务端下发, g_api.dart):
```
GSignRule( data: [GSignRuleItem(key: ...)] )
GSignRuleData( extend_sign_encourage: ..., [含 api_encrypt, extends...] )
```

可疑常量 (line@strings, 待运行时确认用途):
- `04a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5` (114 hex, 疑似 device_info.player 尾)
- `e95e4a5f737059dc60dfc7ad95b3d8139515620f` (40 hex, 疑似 device salt)
- `617fab68...32f2c` / `2580f63ccfe4...400b` (60/56 hex)
> 注意: 大部分 32-64 hex 字符串为 pointycastle 曲线常量 (secp256k1 等) — 不是密钥。

---

## 5. 播放解析链路 (结论)

```
POST /app/playaddr/v4/client   (带 X-Token, appid, sign, timestamp, nonce)
   │
   ▼ 返回 GUrlParsed
   ┌─ name, raw_play_url, m3u8FileDomain (加密字段, 需 PKCS7 AES 解)
   ▼ Lua source script (服务端下发或内嵌)
   ├─ vmplugin.httpGet(raw_play_url, lua_header) -> 源站页面
   ├─ lua parse -> play_addr/m3u8
   │
   ▼ getM3U8Url / getM3U8File
   ├─ /hls.m3u8  (从 m3u8FileDomain 拼接)
   ├─ #EXTM3U / #EXT-X-STREAM-INF: / #EXT-X-KEY:
   │   └── 关键帧 AES-128-CBC(key, iv) 解密
   ▼ 阿里播放器 (libsaasCorePlayer.so) 起播
```

---

## 6. 动态取证计划 (完成签名的最后一步)

静态分析无法拿到 3 个量:  
`APPID 实值` / `SIGN_FN(组合顺序+算法选择)` / `RSA 公钥全文`。

**最快方案**: 真机/模拟器装补丁包 + MITM 捕获。  
建议用 frida hook `vmplugin.invoke_method`(LuavmPlugin) 直接观察到:
```
invoke_method('utils_md5', '<拼接原文>')        -> 看到签名原文
invoke_method('utils_timestamp', '')            -> 每请求时间戳
invoke_method('httpGet', json{url,header})      -> Lua 源解析的原始 URL
invoke_method('utils_aes128cbc_*', key/iv/data) -> 解密密钥
```
所需脚本: out/client/frida_vmplugin_hook.js

---

## 7. Python Python 客户端骨架

`out/client/gg_client.py`:
- 40+ 接口方法封装 (与 .so 字符串一致)
- utils_{md5,timestamp,base64,aes128cbc}_{en,de}crypt 与内嵌 Lua 等价实现
- HEADERS/sign() 留 SIGN_FN 占位, 回填 α,β,γ 后即可用

---

# 2026-09-28 增补: 动态取证完成 (blutter + frida 真机)

> 本节为第二阶段成果, 基于 blutter 静态反汇编 (Dart VM 3.6.0 重建) + frida gadget 真机 hook + 网络重放实验。
> 全部结论有运行时硬证据; 修正上文 §6 的三个待定项中的两个。

## A. 三通道加密架构 (全部实测验证)

| 通道 | 载体 | 算法 | key / iv | 状态 |
|---|---|---|---|---|
| 监控 (C2 心跳) | libcore.so `call` FFI | AES-128-CBC PKCS7 | `qPwClBj7j7ZQraSm` / `p3JdVQl3q7WQJIgG` | ✅ 破解 (hook aes_v8_set_encrypt_key + 解密验证) |
| 信令 (WebRTC/上报) | libloader.so `call` FFI | AES-128-CBC PKCS7 | `kFGTbLlOzFHQCIKp` / `F3q22XoM8l6T2Ydc` | ✅ 破解 (响应实测解出 get_app_info JSON) |
| HTTP API | dio 明文 HTTP 43.145.33.254:27990 | 见下 | 每请求随机会话 key | ⚙️ 结构已明, key 需运行时 |

- 信令 key 出处: blutter 对象池 pp+0x7000/0x7008 (紧邻 AESMode.cbc 枚举)
- 帧: 416B 诱饵 JSON (16 字符随机键值对 + 藏真实 action) → AES → b64 → FFI `call`(单字符串进出)
- 信令响应实测: `{"action":"get_app_info","code":200,"payload":{"address":"<房间号>"}}`

## B. 修正与补充 (对上文的修正)

1. **`api_encrypt` 双义**: 既为服务端下发配置标志 (§3), 也是 FFIUtils.apiEncrypt 的内部 action 名。
2. **X-Token (authentication 头) 为服务器签发不透明 token** (响应头 `new-token` 下发, 112B =
   15B 常量前缀 e8cb1f12... + 代次 flag + 96B 服务器侧密文)。客户端仅回传, 不解析。
   **重放实验**: 旧 token + 新 ts → code 403501 "校验客户端签名失败"; 旧 token + 旧 ts → 403502 "设备时间异常"。
   ⇒ token 与 ts/nonce 密绑, **离线请求必须先走 device-base 登录换取新 token**, 纯重放不可行。
3. **vmplugin aes128cbc 桥**为 Lua 图片下载链路专用; HTTP 主链路的加密在 Dart 层 FFIUtils (见下)。

## C. HTTP body 加密流程 (apiEncrypt @0x7eee0c 反汇编实证)

```
HeadersInterceptor._onRequest (@0xa3bdc8)
   bl 0x716b7c  clearKey()                        # 清除上次会话 key
   bl 0x7eee0c  apiEncrypt(params):
        bl 0x715cb0  getRandomString()  ×2        # 每请求随机生成 AES key 与 iv
        AES-CBC(payload)                          # → P1 段 (变长)
        RSA-2048(key+iv)                          # → P0 段 (恒 256B; 随机会话密钥被公钥包裹)
        return "<P0_b64>.<P1_b64>"                # POST body, 点分两段
   JsonCodec.encode({"data": <上述输出>, "authentication": <X-Token>})
   + 头: APPID / ts / nonce / tcs=2 / x-version=2020-09-17
```

- 服务器持 RSA 私钥解 P0 得会话 key/iv → 解 P1 → 处理后用**同一会话 key** 加密响应 → 客户端 apiDecrypt 解。
- 实测特征吻合: P0 恒 256B 且每请求不同; play-connect 5 次相同 body ⇒ getRandomString 的
  Random 种子确定 (同参数同序列)。
- 错误响应为明文: {"code":403501/403502/30000,"message":...}
- **离线复现还差**: RSA 公钥 (未内嵌于 libapp/libcore/libloader/assets; 结合 /app/video/key 密钥交换端点,
  判定公钥由服务器下发给客户端缓存) 与 getRandomString 种子算法。

## D. 端点补遗 (并入 §2 清单)

- GET /app/video/key — 播放密钥交换 (RSA/AES)
- POST /app/playaddr/v4/client — 播放地址解析主接口 (GUrlParsed: raw_play_url/m3u8FileDomain)
- GET /app/video/list 完整参数: ?channel=<N>&sort=weight&limit=6&page=1
- 服务器: 43.145.33.254:27990 (当前生效主 API, 旧文档 pzl.clicli.blog 为域名入口)

## E. 工具与产物 (第二阶段)

- blutter (worawit/blutter) Dart VM 3.6.0 重建成功; junction C:\blutter_w 规避中文路径崩溃;
  no-analysis 变体绕过 CodeAnalyzer 崩溃。产物: out/blutter_out/ (pp.txt 2.6MB / asm 102 包 / blutter_frida.js)
- reFlutter dump 59470 符号: reflutter_work/dump2.dart + dump2_parsed.jsonl
- 组合包: reflutter_work/combo.RE-gadget-aligned-debugSigned.apk (reFlutter 引擎 + frida gadget 共存)
- 关键 hook: out/gg_ffi_hook.js (native), out/gg_manual_hook*.js, out/gg_hex_hook.js (raw dump)
- 日志: out/ffi_log*.jsonl / dart_log*.jsonl / manual_log*.jsonl / hex_log.jsonl
- 注意: app 处于 EMUI unconfirm_app 管控态时 `am force-stop` 失效, 需用 `am crash com.tudou.tool`;
  gadget 每进程仅支持一轮 script session。
