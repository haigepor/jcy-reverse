# 设备静默登录 /app/video/device-base

## 机制

App **无强制注册/登录**。首次启动即通过 `POST /app/video/device-base`
以设备信息静默注册，服务器签发 X-Token (`new-token` 响应头)。
后续所有请求携带该 token (见 [X-Token 机制](../crypto/x-token.md))。

账密/短信登录 (`/app/users/login`、smscode、register) 为可选的账号体系，
设备 token 与账号 token 结构相同。

## 请求

```
POST http://43.145.33.254:27990/app/video/device-base
Headers: (同通用头; 首次无 authentication 或为空)
Body:    "<P0_b64>.<P1_b64>"
```

body 明文 (P1 解密后) 为设备信息 JSON，来源 FFIUtils 系列方法：

```json
{
  "device_id": "<FFIUtils.getDeviceId>",
  "appid": "<FFIUtils.getAppId>",
  "version": "<FFIUtils.getAppVersion>",
  "code_version": "<FFIUtils.getCodeVersion>",
  "app_name": "<FFIUtils.getAppName>",
  "...": "..."
}
```

> 字段名以解密实测为准 (blutter asm/guoguo/api_utils/ 下各 API 方法)。

## 响应

```
HTTP 200
new-token: <112B X-Token, b64>
Body: (会话 key 加密)
{"code":200, "data": {...用户信息...}, "message":""}
```

## P0/P1 加密细节

见 [HTTP body](../crypto/http-body.md)。**这是离线构造任何请求的第一步**——
拿到 device-base 的有效 new-token 后，其余 GET 接口 (列表/详情/横幅) 可直接重放。

## 真机捕获

- device-base 请求/响应均在真机 apiDecrypt hook 捕获 (research/key_log.jsonl)
- 响应密文: 会话 key 加密, 解密需运行时 key
