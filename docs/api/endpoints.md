# 其余端点速查

> 全部端点的请求头见 [总览](overview.md)；POST 端点 body 加密见 [HTTP body](../crypto/http-body.md)。
> `⊕` = 真机 hook 实际捕获到该端点流量。

## 配置类

| 端点 | 方法 | 说明 |
|---|---|---|
| `/app/config` | GET | 全局配置。判定点: RSA 公钥/host 下发。实测无 token → 30000 |
| `/app/config/channel` ⊕ | GET | 频道配置 (apiDecrypt 捕获响应) |
| `/app/config/video` ⊕ | GET | 视频配置 (apiDecrypt 捕获响应) |
| `/app/channel?top-level=true` ⊕ | GET | 顶级频道 (返回频道 ID↔名称映射) |
| `/app/banners/0` ⊕ | GET | 首页 banner 列表 |
| `/app/v2/config/host` | GET | host v2 (404 实测, 已下线) |
| `/app/upgrade` | GET | 版本升级 (GUpdateData, 含 buildSignature 字段) |

## 视频类

| 端点 | 方法 | 说明 |
|---|---|---|
| `/app/video/list` ⊕ | GET | 列表 (见 [video-list](video-list.md)) |
| `/app/video/detail?id=` | GET | 详情 (GVideoDetail) |
| `/app/video/search` | GET | 搜索 |
| `/app/video/play?id=&play=` ⊕ | POST | 播放凭证 (见 [video-play](video-play.md)) |
| `/app/video/play-connect` ⊕ | POST | 播放心跳 |
| `/app/video/record` ⊕ | POST | 观看记录上报 (实测响应 306B 加密) |
| `/app/playaddr/v4/client` | POST | 播放地址解析 (GUrlParsed) |
| `/app/video/key` | GET | 播放密钥交换 |
| `/app/video/authenticatePlayVideo` | GET | 播放鉴权 |
| `/app/video/download` / `gold` / `buy` | GET | 下载/金币/购买 |
| `/app/danmu?vid=&play=mp4` ⊕ | GET | 弹幕 (按 vid+格式) |

## 用户类

| 端点 | 方法 | 说明 |
|---|---|---|
| `/app/video/device-base` ⊕ | POST | 设备静默登录 (见 [device-base](device-base.md)) |
| `/app/users/login` | POST | 账号登录 |
| `/app/users/register` / `smscode` / `captcha` | POST/GET | 注册/验证码 |
| `/app/users/info` / `change` / `update` / `picture` / `clearimg` ⊕ | GET/POST | 资料 |
| `/app/users/logout` | GET | 退出 |
| `/app/users/task` ⊕ | POST | 任务上报 (GTask, coin) |
| `/app/qr_login/scan` / `qrconfirmlogin` | GET | 扫码登录 |

## 内容类

| 端点 | 方法 | 说明 |
|---|---|---|
| `/app/messagebox/give_me` ⊕ | POST | 消息拉取 (body 548/580B) |
| `/app/history/localcahce` ⊕ | GET | 本地历史 (原样拼写) |
| `/app/vod_comment/{captcha,create,getlist,getsublist,gettop,gethitstopH,likes,report}` | GET/POST | 评论 |
| `/app/vip_price/{list,buy}` / `/app/vip_ticket/exchange` | GET | VIP |
| `/api_utils/task/task` | GET | 任务 |
| `/api/league/app/loadAdPositionConfig` 等 | GET | 广告联盟 (去广告版已 stub) |

## 错误码实测

| code | 含义 | 触发 |
|---|---|---|
| 30000 | 解码异常: authentication is empty | 无 authentication 头 |
| 403501 | 校验客户端签名失败 | token 与 ts/nonce 不匹配 |
| 403502 | 设备时间异常 | token 内 ts 过旧 |
| 200 | 成功 | — |

## 实测重放示例 (curl 等价)

```bash
curl 'http://43.145.33.254:27990/app/video/list?channel=1&sort=weight&limit=6&page=1' \
  -H 'appid: com.tudou.tool' \
  -H 'ts: <当前毫秒>' \
  -H 'nonce: <8位随机>' \
  -H 'tcs: 2' \
  -H 'x-version: 2020-09-17' \
  -H 'authentication: <有效X-Token b64>' \
  -H 'User-Agent: Dart/3.6 (dart:io)'
# 有效 token 下返回加密 body (会话 key); 无/错 token 返回上述明文错误码
```
