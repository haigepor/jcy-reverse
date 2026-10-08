# 囧次元 API 端到端客户端（真实请求 + 离线解密）—— 2026-10-04

> 目标：用 apipost MCP 中已录入的接口定义，跑通**真实请求**并**离线解密响应**，拿到真实数据。

## 一、apipost 项目接口清单

- 团队 `海鸽的群组` → 项目 **囧次元** `project_id = 6ef0f75d8470000`
- 6 个目录 / **38 个接口**（`search_target` 实测），根域名 `http://43.145.33.254:27990`

| 目录 | 接口（方法 路径） |
|---|---|
| 频道与配置 | GET `/app/config`、GET `/app/channel?top-level=true`、GET `/app/channel/`、POST `/app/config/channel`、POST `/app/config/video`、GET `/app/banners/{0,1,2}` |
| 视频与播放 | GET `/app/video/list`、GET `/app/video/detail`、GET `/app/video/search`、GET `/app/video/key`、GET `/app/video_update_list/{date}`、POST `/app/video/record`、POST `/app/video/play-connect`、POST `/app/video/play`、POST `/app/video/device-base` |
| 弹幕与评论 | GET `/app/danmu`、GET `/app/vod_comment/gettop`、`/gethitstop`、`/getlist` |
| 用户与任务 | POST `/app/users/clearimg`、POST `/app/users/task`、POST `/app/history`、POST `/app/history/localcahce`、GET `/app/task/sign_rule` |
| 消息 | POST `/app/messagebox/give_me`、POST `/app/messagebox/dynamic` |
| 特殊端点与登录门槛 | POST `/app/upgrade`、GET `/app/v2/config/host`、GET `/app/users/info`、GET `/app/vip_price/list`、POST `/app/task/task`、GET `/app/playaddr/v4/client`、POST `/app/login/smscode` |

> apipost MCP 仅提供**管理类**工具（查询/建节点/导 swagger），**不具备发请求能力**；
> 因此"发请求 + 解密"由本地脚本完成（下方 `jcy_client.py`）。

## 二、端到端协议（本轮实测闭环）

```
请求头  : appid=4150439554430529 / ts(ms) / nonce(8位) / tcs=2 /
          x-version=2020-09-17 / authentication(=authgen 离线生成) /
          content-type: application/json; charset=utf-8 / UA: Dart/3.6 (dart:io)
GET     : 无 body
POST    : body = CUSTOM_B64(P0) . CUSTOM_B64(P1)
            P0 = RSA-2048-PKCS1v1.5(server_pub, K16)     K16 = 16B 随机
            P1 = E( key=K16, iv=reverse(K16), PKCS7(params) )
响应    : body = CUSTOM_B64(P0) . CUSTOM_B64(P1)   (HTTP 200)
            P0 = RSA(pub_from_go, K16resp)  --priv_from_go.pem-->  K16resp
            P1 = E( key=K16resp, iv=reverse(K16resp), ... )  --decrypt_e-->  明文 JSON
```

要点（本轮新确认）：

- **响应 P1 的密钥 = 响应 P0 解出的 `K16resp`**（不是请求的 K16）。GET 与 POST 皆然。
  这修正了 V11"K16resp 作响应 P1 密钥已证伪"的结论——那是**用 AES 试的**，密码选错，作废。
- 响应 P1 是 **E 分块密文**（带逐块 tweak），**朴素 CBC 解不开**（实测：仅块 0 正确，块 1 起乱码）。
- 服务端错误也返回 HTTP 200，业务码在解密后的 JSON 里。

## 三、交付物

- `research/deliverables/jcy_client.py` —— 端到端客户端
  ```bash
  python research/deliverables/jcy_client.py GET  /app/config
  python research/deliverables/jcy_client.py GET  '/app/video/list?channel=1&sort=weight&limit=6&page=1'
  python research/deliverables/jcy_client.py POST /app/video/device-base '{}'
  ```
  `JcyClient.request(method, path, params)` 返回 `{http, encrypted, k16resp, plain, json}`。
- `research/deliverables/decrypt_e.py` —— 响应 P1 离线解密（E 的逐块逆）。
- `research/captures/live_data/*.json` —— 本轮拉取的真实解密数据 + `INDEX.json`。

## 四、实测结果（2026-10-04）

| 端点 | HTTP | K16resp | 明文 | 内容摘要 |
|---|---|---|---|---|
| GET `/app/task/sign_rule` | 200 | VU37G1W3RNNKQWQ5 | 466B | 签到规则（key/value 列表） |
| GET `/app/video/detail?id=113354` | 200 | 5T5NZRNZ8V9XANVM | 1339B | 视频详情（片名/年份/简介…） |
| GET `/app/config` | 200 | WX8M9CV8H1DXHBD8 | 1913B | 全局配置（mupao 播放器开关等） |
| GET `/app/banners/0` | 200 | CXV2GQ94RRNPZNGW | 4132B | 首页 Banner（图/跳转 vid） |
| GET `/app/channel?top-level=true` | 200 | WT2FATUEV2YQVPYP | 2653B | 频道（日漫/国漫… + 类型标签） |
| GET `/app/video/list?...` | 200 | CP2MHAJPTTKQHKNZ | 8615B | 视频列表 `total=3366`，含 items |
| GET `/app/video_update_list/2026-10-04` | 200 | ANK57HRPY34BJY4N | 2279B | 更新排期 `total=10` |
| POST `/app/video/device-base {}` | 200 | 4PEXKJ6EZR64VF3J | 39B | `{"code":40000,"message":"参数错误"}`（链路通，参数不全） |

8/8 全部解出**合法 JSON 真实数据**。

## 五、已知限制

- **解密速度**：逐块 tweak 的闭式公式未还原，响应解密用**标定法**（同 K 跑一次等长 dummy
  加密 + hook 轮驱动读 x_b），Unicorn 约 **1.3 s/块**。故响应越大越慢：
  8615B（≈556 块）耗时约 496s。要提速需还原 `CONST_b` 生成公式（见 `docs/crypto/http-body.md` V13）。
- `authentication` 有效期约 2 分钟，客户端按 90s 自动续签（本地 `authgen.py`）。

---

## 六、V14 全量覆盖（2026-10-04 续）

本轮把范围从 8 个端点扩到**全部 35 个**，并改用**多进程并行**提速。

### 6.1 并行驱动

`research/tmp_all_endpoints_par.py`（`JCY_WORKERS=6`，12 核；可断点续跑）→
逐条落盘 `research/tmp_all_endpoints.json`；矩阵文档 `docs/api/live-matrix.md`（`gen_matrix.py` 生成）。

### 6.2 结果分布（35 接口）

| 类别 | 数量 | 说明 |
|---|---|---|
| ✅ `code=20000` 真实数据 | 22+ | 含 video/list 8615B、vod_comment/getlist 4488B、banners/1 5506B |
| ⚠ 加密但业务码非 20000 | 6 | 3× `40000`（参数不全）、3× `50008`（游客态） |
| ➖ 非加密响应 | 5 | `/app/channel/`(301)、`/app/upgrade`(特例)、3× 404 |
| ❌ 异常 | 0（已修） | `/app/channel/` 首轮因 301 解析崩，`jcy_client` 已加非信封回退 |

累计解出明文 **38 KB+**。

### 6.3 本轮新增的端点结论

| 端点 | 结论 |
|---|---|
| `/app/danmu` | **必须带 `part`**（集名）→ 20000 + 真实弹幕；响应为**明文 JSON**（非 P0.P1） |
| `/app/video/play` | 参数在 **query**（`?id=&play=&part=`），真机响应 7250B |
| `/app/video/play-connect` | 真机响应 409B（参数待补） |
| `/app/video/device-base` | 真机请求体 P1 仅 16B；响应 409B；`{}` → 40000 |
| `/app/config/{channel,video}` | **POST**（非 GET），`{}` → 20000 |
| `/app/upgrade` | 仅 POST、**不校验 auth**、返回恒定 64B 桩；真机为 896B（独立方案） |
| `/app/history` · `/app/users/info` · `/app/task/task` | `50008 未登录`（游客态） |

### 6.4 Apipost 同步

`research/deliverables/apipost_sync.py update` → **35/35** 接口写入
`pre_tasks`（取签+随机 nonce）+ `post_tasks`（判定+归档+调 `/decrypt` 离线解密）。
验证：`apis=35 pre_ok=35 post_ok=35 bad=0`。
