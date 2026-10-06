# API 总览与请求头

> **本页已于 2026-09-30 按实测校正**。校正点见文末「与旧版本的差异」。

## 服务器

| 域 | 用途 | 状态 |
|---|---|---|
| `http://43.145.33.254:27990` | **当前生效主 API**（明文 HTTP，已实测） | ✅ |
| `http://pzl.clicli.blog:8087` | 域名入口（静态字符串） | 历史配置 |
| `http://pzl.clicli.blog:8088` | 分享域（GShareDomain） | 历史配置 |
| `https://vod.api.zshtys888.com` | 点播解析域 | 静态字符串 |

当前生效 IP 由 `/app/config` 的 host 配置动态下发（`FFIUtils.getHostConfig`）。

## 通用请求头

来源：`HeadersInterceptor._onRequest`（对象池 `@0xa3bdc8`）对象池引用，
并与真机抓包（`research/captures/proxy_capture.jsonl`）逐项核对。

```http
appid:          4150439554430529
ts:             <13 位毫秒时间戳>
nonce:          <8 位随机数字>
tcs:            2
x-version:      2020-09-17
authentication: <152 字符，客户端本地生成，见下>
content-type:   application/json; charset=utf-8
user-agent:     Dart/3.6 (dart:io)
host:           43.145.33.254:27990
```

### `authentication` 头

**它不是服务器签发的 X-Token，而是客户端本地生成的**（决定性证据：同一 `ts` 下
不同 `nonce` 的两条样本，只有末 2 个 AES 块不同，呈 CBC 误差传播特征；
服务器签发无法解释对 `nonce` 的依赖）。

```
authentication = CUSTOM_B64( E( CUSTOM_B64( S ) ) )
S = "3.0.0.8-{ts}-Android-1.5.8.0-{device_fp}-default"
```

- 长度 152 字符 → 解码 112 字节
- 与 `ts` 强绑定：改 `ts` → `403501`；`ts` 过旧 → `403502`
- **不绑定路径 / query**：同一个 auth 可跨 22 个端点使用（已实测）
- 完整算法、判定依据与用法：[`../algorithm-auth.md`](../algorithm-auth.md)
- 逆向全过程：[`../reverse-journal-auth.md`](../reverse-journal-auth.md)
- 离线生成器：`research/deliverables/authgen.py`

### 请求体

- **GET**：无 body（`req_body_len=0`），仅靠 `authentication` 头
- **POST**：body 为 `"<P0_b64>.<P1_b64>"`
  - `P0` = RSA-2048 加密的会话密钥/IV（256 字节 → base64 344 字符）
  - `P1` = AES-CBC 加密的业务 JSON（16 字节对齐）
  - 见 [`../crypto/http-body.md`](../crypto/http-body.md)

## 通用响应格式

**成功**：HTTP 200 + 加密体 `<P0_b64>.<P1_b64>`（P0 = 256 字节 RSA-2048，
包裹给客户端的会话密钥；需客户端私钥才能解出明文）。

**失败**：HTTP **200**（同样）+ **明文** JSON：

```json
{"code":30000, "message":"解码异常:authentication is empty"}
{"code":403501,"message":"校验客户端签名失败，请重启app尝试"}
{"code":403502,"message":"检测到设备时间异常，请调整到正确时间后重新打开 App尝试"}
```

> ⚠️ **该服务端错误也返回 HTTP 200**，业务码在 JSON body 里。
> 判定"请求是否被接受"要看 **body 是加密密文还是明文错误 JSON**，不能只看状态码。

## 端点全集

> 方法与路径取自真机抓包，并已用离线生成的 `authentication` 逐个实测
> （见 [`../algorithm-auth.md`](../algorithm-auth.md) §6，`research/deliverables/probe_matrix2.py`）。
> ✅ = 实测返回 200 + 加密业务数据。

### 配置

| 方法 | 路径 | 实测 |
|---|---|---|
| GET | `/app/config` | ✅ 2905 B |
| POST | `/app/config/channel` | ✅ 561 B |
| POST | `/app/config/video` | ✅ 645 B |
| GET | `/app/channel?top-level=true` | ✅ 3889 B |
| GET | `/app/banners/0` | ✅ 7493 B |
| GET | `/app/v2/config/host` | 未实测 |

### 账号

| 方法 | 路径 | 实测 |
|---|---|---|
| POST | `/app/video/device-base` | ✅（设备静默登录） |
| POST | `/app/users/task` | ✅ 497 B |
| POST | `/app/users/clearimg` | ✅ 581 B |
| GET/POST | `/app/users/login` · `register` · `info` · `logout` | 未实测 |
| GET | `/app/users/smscode` · `captcha` | 未实测 |
| GET | `/app/qr_login/scan` · `qrconfirmlogin` | 未实测 |

### 视频（核心）

> 下表为 **2026-10-04 V14** 端到端实测（真实请求 + 离线解密），完整矩阵见 [live-matrix](live-matrix.md)。

| 方法 | 路径 | 实测 |
|---|---|---|
| GET | `/app/video/list?channel=N&sort=weight&limit=6&page=1` | ✅ 8615 B（total=3366） |
| GET | `/app/video/detail?id=<vid>` | ✅ 1339 B |
| GET | `/app/video/search?key=<kw>&limit=&page=` | ✅ 参数名是 **`key`**（非 keyword）；`key=ai` → 34 KB |
| GET | `/app/video/key?key=<前缀>&limit=&page=` | ✅ 911 B（搜索联想） |
| GET | `/app/video_update_list/<YYYY-MM-DD>` | ✅ 2279 B |
| GET | `/app/vod_comment/getlist?vid=<vid>&page=1` | ✅ 4488 B |
| POST | `/app/video/record` | ✅ 20000 |
| POST | `/app/video/play` · `play-connect` · `device-base` | ⚠ `40000` 业务参数未补全（认证与解密链路通） |
| POST | `/app/playaddr/v4/client` | ❌ 404（已下线） |
| GET | `/app/danmu?vid=&play=mp4&part=&start_time_point=&end_time_point=` | ✅ 20000 + 真实弹幕（**必须带 `part`**；响应为明文 JSON） |

### 其他

| 方法 | 路径 | 实测 |
|---|---|---|
| POST | `/app/history` · `/app/history/localcahce` | ✅ `50008 未登录` / 20000 |
| POST | `/app/messagebox/dynamic` · `give_me` | ✅ 184 / 126 B |
| GET | `/app/task/sign_rule` | ✅ 466 B |
| POST | `/app/upgrade` | ⚠ 特例：不校验 auth，返回恒定 64B 桩（独立方案） |
| GET | `/app/vod_comment/{gettop,gethitstop}`、VIP `/app/vip_price/list` | ✅ 20000 |
| GET | `/app/users/info` · POST `/app/task/task` | ⚠ `50008 未登录`（游客态） |

## 与旧版本的差异（2026-09-30 校正）

| 旧说法 | 实测结论 |
|---|---|
| `APPID: com.tudou.tool` | ❌ 应为 **`4150439554430529`** |
| `authentication` 是服务器签发的 X-Token | ❌ **客户端本地生成**，算法已完全破解 |
| 用 HTTP 状态码判断成功/失败 | ❌ 错误也返回 **200**，要看 body 是密文还是明文错误 JSON |
| `auth` 绑定路径 / query | ❌ **不绑定**；同一 auth 可跨 22 个端点 |
| `/app/config/channel`、`/app/config/video` 是 GET | ❌ 实际为 **POST** |
| `/app/users/task`、`/app/messagebox/*`、`/app/history*` 未标方法 | 实际为 **POST**（用 GET 得 404） |
