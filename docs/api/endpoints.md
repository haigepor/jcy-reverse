# 其余端点速查

> 全部端点的请求头见 [总览](overview.md)；POST 端点 body 加密见 [HTTP body](../crypto/http-body.md)。
> `⊕` = 真机 hook 实际捕获到该端点流量。

## 配置类

| 端点 | 方法 | 说明 |
|---|---|---|
| `/app/config` | GET | 全局配置。实测无 auth → 30000；有效 auth → 20000 + 真实配置 |
| `/app/config/channel` ⊕ | **POST** | 频道配置（V14 更正：POST，非 GET） |
| `/app/config/video` ⊕ | **POST** | 视频配置（V14 更正：POST，非 GET） |
| `/app/channel?top-level=true` ⊕ | GET | 顶级频道 (返回频道 ID↔名称映射) |
| `/app/banners/{频道ID}` ⊕ | GET | 各频道 banner 位 (实测 ID 0/1/2/3/26) |
| `/app/video_update_list/{yyyy-mm-dd}?limit=&page=` ⊕ | GET | 排期表 |
| `/app/v2/config/host` | GET | host v2 (**404** 实测, 已下线) |
| `/app/upgrade` | **POST** | 版本升级。**特例**：大写 `Authentication`(magic `905b5ed3`)、**不校验认证**、body 为 160B E 密文（无 RSA 层）。详见 [http-body V14](../crypto/http-body.md) |

## 视频类

| 端点 | 方法 | 说明 |
|---|---|---|
| `/app/video/list` ⊕ | GET | 列表 (见 [video-list](video-list.md)) |
| `/app/video/detail?id=` | GET | 详情 (GVideoDetail) |
| `/app/video/search?key=&limit=` ⊕ | GET | 搜索 (V6 实抓: key=吞噬星空&limit=2, UI 实测 3 结果) |
| `/app/video/play?id=&play=` ⊕ | POST | 播放凭证 (见 [video-play](video-play.md)) |
| `/app/danmu?vid=&play=mp4&part=&start_time_point=&end_time_point=` ⊕ | GET | 弹幕。**V14 更正：必须带 `part`**（集名，URL 编码）→ `code=20000` + 真实弹幕 items；缺 `part` → 明文 `40000`。该端点响应为**明文 JSON**（非 P0.P1） |
| `/app/video/play-connect` ⊕ | POST | 播放心跳。真机 body P1=432B；空 `{}` → 40000（业务参数待补全） |
| `/app/video/record` ⊕ | POST | 观看记录上报 (实测响应 306B 加密) |
| `/app/playaddr/v4/client` | POST | 播放地址解析 (GUrlParsed) |
| `/app/video/key?key=&limit=&page=` ⊕ | GET | 搜索联想词 (2026-09-29 实抓: 与 /app/video/search 成对出现于搜索页, key=输入前缀; 非播放密钥交换) |
| `/app/video/authenticatePlayVideo` | GET | 播放鉴权 |
| `/app/video/download` / `gold` / `buy` | GET | 下载/金币/购买 |
| `/app/danmu?vid=&play=mp4&part=&start_time_point=&end_time_point=` ⊕ | GET | 弹幕 (V6 实抓: 弹幕开关触发; 2026-09-29 修正: 增量参数实为 start_time_point/end_time_point 毫秒, 播放中每 60s 轮询; 精确重放 auth 层接受但业务码 20000) |

## 用户类

| 端点 | 方法 | 说明 |
|---|---|---|
| `/app/video/device-base` ⊕ | POST | 设备静默登录 (见 [device-base](device-base.md)) |
| `/app/history` ⊕ | POST | 观看历史上报 (V6 新发现, 播放启动突发) |
| `/app/history/localcahce` ⊕ | POST | 本地缓存历史 (V6 实抓) |
| `/app/vod_comment/gettop?vid=` ⊕ | GET | 置顶评论 (V6 新发现) |
| `/app/vod_comment/gethitstop?vid=` ⊕ | GET | 评论热度 (V6 新发现) |
| `/app/vod_comment/getlist?vid=&limit=20&page=1` ⊕ | GET | 评论列表 (V6 新发现, UI 评论一致) |
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
| 403501 | 校验客户端签名失败 | token 与 ts 不匹配 / 被篡改 |
| 403502 | 设备时间异常 | token 内 ts 过旧（>2 分钟） |
| 40000 | 业务参数错误 | 缺必填参数（如 `/app/danmu` 缺 `part`） |
| 50008 | 未登录 | `/app/users/info`、`/app/task/task`、`/app/history`（游客态） |
| 20000 | 成功 | —（注意：**不是 200**，该 API 成功码为 20000） |
| 800131 | 通讯失败 | 请求 P1 解不开（会话密钥对错） |

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
