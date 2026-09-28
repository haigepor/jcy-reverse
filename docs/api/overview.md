# API 总览与请求头

## 服务器

| 域 | 用途 | 状态 |
|---|---|---|
| `http://43.145.33.254:27990` | **当前生效主 API** (实测存活) | ✅ |
| `http://pzl.clicli.blog:8087` | 域名入口 (静态字符串) | 历史配置 |
| `http://pzl.clicli.blog:8088` | 分享域 (GShareDomain) | 历史配置 |
| `https://vod.api.zshtys888.com` | 点播解析域 | 静态字符串 |

当前生效 IP 由 `/app/config` 的 host 配置动态下发 (FFIUtils.getHostConfig)。

## 通用请求头

来源: HeadersInterceptor._onRequest (@0xa3bdc8) 对象池引用，100% 确定。

```
APPID:          com.tudou.tool
ts:             <13 位毫秒时间戳字符串>
nonce:          <8 位随机数字>
tcs:            2
x-version:      2020-09-17
authentication: <X-Token, base64>
User-Agent:     Dart/3.6 (dart:io)
```

- `authentication` 即 X-Token (服务器签发，见 [X-Token 机制](../crypto/x-token.md))
- GET 请求无 body；POST 请求 body 为 `"<P0_b64>.<P1_b64>"` (见 [HTTP body](../crypto/http-body.md))

## 通用响应格式

成功 (加密响应，解密后):

```json
{"code":200, "data": {...}, "message":""}
```

失败 (明文，未加密):

```json
{"code":30000,"message":"解码异常:authentication is empty"}
{"code":403501,"message":"校验客户端签名失败，请重启app尝试"}
{"code":403502,"message":"检测到设备时间异常，请调整到正确时间后重新打开 App尝试"}
```

## 端点全集 (抓包 + 字符串证据)

### 配置
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/app/config` | 全局配置 (host/公钥下发判定点) |
| GET | `/app/config/channel` | 频道配置 |
| GET | `/app/config/video` | 视频配置 (真机 apiDecrypt 捕获) |
| GET | `/app/channel?top-level=true` | 顶级频道 |
| GET | `/app/banners/0` | 首页 banner |
| GET | `/app/v2/config/host` | host 配置 v2 |

### 账号
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/app/video/device-base` | **设备静默登录** (拿 X-Token) |
| GET/POST | `/app/users/login` | 账号登录 (LoginInfo → user_token) |
| POST | `/app/users/register` | 注册 |
| GET | `/app/users/smscode` / `/app/users/captcha` | 验证码 |
| GET | `/app/users/info` / change / update / picture | 资料 |
| GET | `/app/users/logout` | 退出 |
| POST | `/app/users/task` | 任务上报 |
| POST | `/app/users/clearimg` | 头像 |
| GET | `/app/qr_login/scan` / `qrconfirmlogin` | 扫码登录 |

### 视频 (核心)
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/app/video/list?channel=N&sort=weight&limit=6&page=1` | **视频列表** |
| GET | `/app/video/detail?id=<vid>` | 详情 |
| GET | `/app/video/search` | 搜索 |
| POST | `/app/video/play?id=<vid>&play=<fmt>` | **播放凭证/地址** |
| POST | `/app/video/play-connect` | 播放心跳 |
| POST/GET | `/app/playaddr/v4/client` | **播放地址解析主接口** (GUrlParsed) |
| GET | `/app/video/key` | 播放密钥交换 (RSA/AES) |
| GET | `/app/video/authenticatePlayVideo` | 播放鉴权 |
| POST | `/app/video/record` | 播放记录上报 |
| GET | `/app/video/download` / gold / buy | 下载/金币/购买 |
| GET | `/app/danmu?vid=<vid>&play=mp4` | 弹幕 |

### 其他
评论 `/app/vod_comment/*`、任务 `/api_utils/task/task`、VIP `/app/vip_price/*`、
历史 `/app/history/localcahce`、消息 `/app/messagebox/give_me`、
广告联盟 `/api/league/app/*`、升级 `/app/upgrade`。
