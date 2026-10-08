# 接口全量矩阵 V5（实抓于 LDPlayer14 + PC MITM 代理）

> 数据来源：`out/v5/proxy_capture.jsonl`（摘要）+ `out/v5/proxy_bodies.jsonl`（完整 hex）。
> 抓包链路：`adb reverse tcp:27990` + 设备侧 `iptables REDIRECT` → `out/v5/mitm_proxy.py`（keep-alive）。
> 采集时间：2026-09-29 01:27–01:37（GMT+8）。主机 `43.145.33.254:27990`，明文 HTTP。

抓到的请求总数：**58**，唯一端点：**16**

## 1. 端点清单

| # | 方法 | 路径 | 次数 | 状态码 | 请求体长度 | 响应体长度 | 带 authentication |
|---|---|---|---|---|---|---|---|
| 1 | GET | `/app/banners/0` | 1 | HTTP/1.1 200 OK×1 | [0] | [7506] | 1/1 |
| 2 | GET | `/app/channel` | 3 | HTTP/1.1 200 OK×3 | [0] | [63, 3901] | 1/3 |
| 3 | GET | `/app/channel/` | 13 | HTTP/1.1 301 Moved Permanently×13 | [0] | [62] | 13/13 |
| 4 | GET | `/app/config` | 1 | HTTP/1.1 200 OK×1 | [0] | [2917] | 1/1 |
| 5 | POST | `/app/config/channel` | 2 | HTTP/1.1 200 OK×2 | [409] | [517, 561] | 2/2 |
| 6 | POST | `/app/config/video` | 2 | HTTP/1.1 200 OK×2 | [409, 433] | [517, 645] | 2/2 |
| 7 | POST | `/app/history/localcahce` | 3 | HTTP/1.1 200 OK×3 | [409] | [517, 581, 645] | 3/3 |
| 8 | POST | `/app/messagebox/dynamic` | 2 | HTTP/1.1 200 OK×2 | [409] | [581, 601] | 2/2 |
| 9 | POST | `/app/messagebox/give_me` | 2 | HTTP/1.1 200 OK×2 | [409] | [537] | 2/2 |
| 10 | GET | `/app/task/sign_rule` | 1 | HTTP/1.1 200 OK×1 | [0] | [985] | 1/1 |
| 11 | POST | `/app/upgrade` | 14 | HTTP/1.1 200 OK×14 | [216] | [1196] | 0/14 |
| 12 | POST | `/app/users/clearimg` | 3 | HTTP/1.1 200 OK×3 | [409, 433] | [497, 625] | 3/3 |
| 13 | POST | `/app/users/task` | 5 | HTTP/1.1 200 OK×5 | [409, 433] | [497, 517, 537, 601] | 5/5 |
| 14 | POST | `/app/video/device-base` | 1 | HTTP/1.1 200 OK×1 | [369] | [409] | 1/1 |
| 15 | GET | `/app/video/list` | 4 | HTTP/1.1 200 OK×4 | [0] | [6078, 9790, 9958, 9982] | 4/4 |
| 16 | POST | `/app/video/record` | 1 | HTTP/1.1 200 OK×1 | [473] | [409] | 1/1 |

## 2. 请求/响应头实测

### 请求头

| 头 | 实测取值（样本） |
|---|---|
| `Host` | 43.145.33.254, 43.145.33.254:27990 |
| `User-Agent` | curl/8.0.1-DEV |
| `Accept` | */* |
| `Connection` | close |
| `Content-Type` | application/json |
| `APPID` | 4150439554430529 |
| `ts` | 1790616501360, 1790616503435, 1790616503444, 1790616503677, 1790616503718, 1790616503828, 1790616566039, 1790616596509, 1790616599161, 1790616599299, 1790616599541, 1790616599666, 1790616599785, 17906 |
| `Authentication` | kFte03yMyDIcYMJLWpgUMCXu9iDOzW+GgkuU4dLy, kFte03yMyDIcYMJLWpgUME39siTEeVdO4fKO59SY, kFte03yMyDIcYMJLWpgUMHmH5NK7mSZ0/qw12MM8, kFte03yMyDIcYMJLWpgUMLPYx7tBhYg6a56Kel3s, kFte03yMyDIcYMJLWpgUMM+666dOqitE |
| `Content-Length` | 216 |
| `x-version` | 2020-09-17 |
| `user-agent` | Dart/3.6 (dart:io) |
| `appid` | 4150439554430529 |
| `accept-encoding` | gzip |
| `authentication` | <b64 152 chars> |
| `host` | 43.145.33.254:27990 |
| `tcs` | 2 |
| `content-type` | application/json; charset=utf-8 |
| `nonce` | 12014912, 13640643, 13782779, 15195994, 16836260, 22360381, 22467868, 22600528, 22741614, 24818561, 25217469, 26633761, 29475083, 30816208, 31637495, 31933157, 32586232, 33394576, 33967693, 41321933,  |
| `content-length` | 369, 409, 433, 473 |

### 响应头

| 头 | 实测取值（样本） |
|---|---|
| `Content-Type` | application/json; charset=utf-8, text/html; charset=utf-8, text/plain; charset=utf-8 |
| `Traceparent` | 00-016d95841d52fad3a10c2a38dad2c8b2-ebe24d10345cc40d-00, 00-036264826ac6b7b89ea8770407a3f4b4-d34b272853aa1b01-00, 00-0614a5b31799afa22fabbc345672a071-e3751b24d63cd9c6-00, 00-06ab9d9761799cf54965144415 |
| `Date` | Mon, 28 Sep 2026 17:27:47 GMT, Mon, 28 Sep 2026 17:28:00 GMT, Mon, 28 Sep 2026 17:28:21 GMT, Mon, 28 Sep 2026 17:28:23 GMT, Mon, 28 Sep 2026 17:28:24 GMT, Mon, 28 Sep 2026 17:29:26 GMT, Mon, 28 Sep 20 |
| `Content-Length` | 1196, 409, 497, 517, 537, 561, 581, 601, 62, 625, 63, 645, 985 |
| `Connection` | close |
| `Location` | /app/channel?top-level=true |
| `Transfer-Encoding` | chunked |

## 3. 请求/响应体加密形态

| 路径 | 请求体形态 | 响应体形态（解 chunk 后） |
|---|---|---|
| `/app/banners/0` | 无 body（GET） | `P0.P1`：P0_b64 344→256B，P1_b64 7148→5360B |
| `/app/channel` | 无 body（GET） | — |
| `/app/channel/` | 无 body（GET） | — |
| `/app/config` | 无 body（GET） | `P0.P1`：P0_b64 344→256B，P1_b64 2560→1920B |
| `/app/config/channel` | `P0.P1`：P0_b64 344→256B，P1_b64 64→48B | — |
| `/app/config/video` | `P0.P1`：P0_b64 344→256B，P1_b64 64→48B | — |
| `/app/history/localcahce` | `P0.P1`：P0_b64 344→256B，P1_b64 64→48B | — |
| `/app/messagebox/dynamic` | `P0.P1`：P0_b64 344→256B，P1_b64 64→48B | — |
| `/app/messagebox/give_me` | `P0.P1`：P0_b64 344→256B，P1_b64 64→48B | — |
| `/app/task/sign_rule` | 无 body（GET） | — |
| `/app/upgrade` | 裸二进制 216B（无点分隔，非本方案） | — |
| `/app/users/clearimg` | `P0.P1`：P0_b64 344→256B，P1_b64 88→64B | — |
| `/app/users/task` | `P0.P1`：P0_b64 344→256B，P1_b64 64→48B | — |
| `/app/video/device-base` | `P0.P1`：P0_b64 344→256B，P1_b64 24→16B | — |
| `/app/video/list` | 无 body（GET） | `P0.P1`：P0_b64 344→256B，P1_b64 5720→4288B |
| `/app/video/record` | `P0.P1`：P0_b64 344→256B，P1_b64 128→96B | — |

## 4. authentication（X-Token）实测结构

`authentication` = **112 字节** → base64 **152 字符**。

```
[0..14]  15B 恒定魔数  e8cb1f120ef5a42c59e22a4d00279e   (主 API 方案)
[15]      1B 计数      取值仅 0x9c/0x9d/0x9e/0x9f
[16..111] 96B 密文    6 个 AES 块
```
- 另见 2 种方案魔数：`905b5ed3…`（/app/upgrade，body 为 160B 裸二进制）、`e9e3af6a…`（/app/v2/config/host）。
- 同 ts 不同 nonce 的两条样本：前 5 个 AES 块完全相同、仅末 2 块不同 → **CBC 传播特征 ⇒ 客户端本地生成**。

## 5. 错误码实测

| code | message | 触发条件 |
|---|---|---|
| 30000 | 解码异常:authentication is empty | 无 authentication 头 |
| 403501 | 校验客户端签名失败，请重启app尝试 | 旧 token + 新 ts |
| 403502 | 检测到设备时间异常… | 旧 token + 旧 ts |
| 200 | — | 成功（响应体仍为密文） |
