# Apipost「囧次元」接口库分析（2026-09-30）

> 通过 `apipost-mcp` 拉取接口库，并与**离线生成 auth + 真实请求**的实测结果逐条对照。
> 库地址：团队「海鸽的群组」→ 项目 **囧次元**，`project_id = 6ef0f75d8470000`。

## 一、库概览

| 项 | 值 |
|---|---|
| project_id | `6ef0f75d8470000`（分支/主项目同名，`is_lock=-1`） |
| 根目录 | 6 个 |
| 接口数 | **35**（全部 `http/1.1`，基址 `http://43.145.33.254:27990`） |
| 文档 / 其它节点 | 0 |
| 节点总数 | 41 |

### 目录划分

| 目录 | folder_id | 接口数 |
|---|---|---|
| 频道与配置 | `6ef0f7636c72000` | 8 |
| 视频与播放 | `6ef0f76ca470000` | 9 |
| 弹幕与评论 | `6ef0f775f072000` | 4 |
| 用户与任务 | `6ef0f77f0472000` | 5 |
| 消息 | `6ef0f7884072000` | 2 |
| 特殊端点与登录门槛 | `6ef0f7918072000` | 7 |

### 方法分布

`GET` 19 个、`POST` 16 个。原始拉取结果见
[`research/reports/apipost_tree.md`](../../research/reports/apipost_tree.md) 与
[`apipost_details.md`](../../research/reports/apipost_details.md)。

## 二、统一请求头组

35 个接口共用同一组 8 个头（`request.header.parameter`）：

| key | 值 | 说明 |
|---|---|---|
| `appid` | `4150439554430529` | 恒定 |
| `ts` | 毫秒时间戳 | 与 `authentication` 绑定 |
| `nonce` | 8 位随机数 | 参与绑定 |
| `tcs` | `2` | 恒定 |
| `x-version` | `2020-09-17` | 恒定 |
| `authentication` | 152 字符 | 见 §三 |
| `content-type` | `application/json; charset=utf-8` | POST 必需 |
| `user-agent` | `Dart/3.6 (dart:io)` | Flutter 栈 |

## 三、需要修正的描述（与实测冲突）

### 3.1 `authentication` 的定性错误（最重要）

库中所有 35 个接口对 `authentication` 的描述都是：

> `X-Token; 绑定(ts,nonce,完整path+query); 新鲜窗口内原样重放可用, 窗口∈(120s,252s); 过期403502; 改动任一要素403501`
> 取值 `<152字符 base64, 112字节: 15B魔数e8cb1f120ef5a42c59e22a4d00279e + 1B计数 + 96B AES-CBC密文>`

**三处错误**：

| 旧描述 | 实测结论 |
|---|---|
| 是服务器签发的 **X-Token** | ❌ **客户端本地生成**。算法已完全破解：<br>`authentication = CUSTOM_B64( E( CUSTOM_B64( S ) ) )`，<br>`S = "3.0.0.8-{ts}-Android-1.5.8.0-{device_fp}-default"` |
| **绑定 path + query** | ❌ **不绑定**。同一个 auth 跨 **22 个端点**实测全部通过；旧结论的失败实为**同时改了 `ts`** 或取了过期 auth |
| 前缀是 `e8cb1f12…`（15B）+ 1B 计数 + 96B 密文 | ❌ 那是**用标准字母表误读**的结果。用正确的**自定义字母表**解码，前 16 字节**完全恒定** `23754ae9d0cbe749f5441e769b45143e`，无"计数"字节 |
| 重放窗口 `(120s, 252s)` | 实测更窄：**`(136s, 188s)`** |

**建议替换为**：

```
客户端本地生成的签名头（非服务器 X-Token）。
算法: authentication = CUSTOM_B64( E( CUSTOM_B64( S ) ) )
      S = "3.0.0.8-{ts}-Android-1.5.8.0-{device_fp}-default"  (78B)
      → 104B →(CBC 分组密码 E, 16B 分组)→ 112B → 152 字符
不绑定 path/query，只与 ts 强绑定；同一 auth 可跨端点复用。
ts 过期 → 403502；ts 非法/篡改 auth → 403501。
离线生成器: research/deliverables/authgen.py（已通过服务端实测与 485/485 语料核验）
详见 docs/algorithm-auth.md
```

### 3.2 路径失效

库中 **4 个接口实测 404**：

| 接口 | 库中路径 | 实测 | 建议 |
|---|---|---|---|
| Host 配置(v2 方案) | `GET /app/v2/config/host` | **404** | 标注"当前版本已不存在"，或降级为历史记录 |
| 播放地址v4(登录后) | `GET /app/playaddr/v4/client` | **404** | 同上 |
| 短信验证码(登录) | `POST /app/login/smscode` | **404** | 路径疑似应为 `/app/users/smscode` |
| 弹幕拉取 | `GET /app/danmu?...&start_t=0` | 200 但**明文 code=40000** | 参数名应为 `start_time_point` / `end_time_point`（库中写的是 `start_t`） |

### 3.3 文件路径已迁移

库中多处引用 `out/decrypt_v5/mem_plaintext.py`。项目已于 2026-09-30 重构，
新路径为 **`research/deliverables/decrypt_v5/mem_plaintext.py`**
（对照表见仓库根 [`MIGRATION.md`](../../MIGRATION.md)）。

## 四、与实测一致的部分

库的整体质量较高，以下内容与实测完全一致，无需改动：

| 项 | 说明 |
|---|---|
| 基址与协议 | `http://43.145.33.254:27990`，`http/1.1` ✓ |
| 方法标注 | `/app/config/{channel,video}`、`/app/users/task`、`/app/history*`、`/app/messagebox/*`、`/app/video/{device-base,record,play-connect,play}` **均为 POST** ✓（比旧文档准确） |
| 加密形态 | 请求/响应体 `<P0_b64>.<P1_b64>`；P0 = RSA-2048（256B）；P1 = AES-CBC ✓ |
| 错误语义 | 服务端错误也返回 HTTP 200，业务码在 JSON body ✓ |
| `/app/upgrade` 特例 | 大写 `Authentication`、216B 裸二进制 body、非 P0.P1 ✓ |
| 播放凭证 | 明文含 `url` + `x-time/x-sign1/x-sign2/x-form`；直链一次性 ✓ |

### 本轮新增实测（库中此前未验证的端点）

用**一个**离线生成的 auth 实测 14 个端点，结果：

| 端点 | 实测 |
|---|---|
| `GET /app/banners/1` | 200，8177 B 加密 |
| `GET /app/banners/2` | 200，4401 B 加密 |
| `GET /app/channel/` | **301**（确认为跳转源） |
| `GET /app/video/key` | 200，409 B 加密 |
| `GET /app/vod_comment/gettop` | 200，3801 B 加密 |
| `GET /app/vod_comment/gethitstop` | 200，11609 B 加密 |
| `GET /app/users/info` | 200，409 B（未登录，业务层空数据） |
| `GET /app/vip_price/list` | 200，729 B |
| `POST /app/task/task` | 200，409 B |
| `POST /app/upgrade` | 200，88 B（非 P0.P1，与描述一致） |
| `GET /app/danmu` | 明文 `code=40000`（参数名需修正） |
| `GET /app/v2/config/host` | **404** |
| `GET /app/playaddr/v4/client` | **404** |
| `POST /app/login/smscode` | **404** |

## 五、已执行的更新（2026-09-30 23:5x）

**35 个接口已全部更新**，方式是「删除 + 重建」（Apipost MCP 的 `create_target` **不支持原地更新**，
对已存在节点只返回 `14000 接口已存在`）。

### 更新内容

1. **每个接口的描述**前置一段更正块：

```
【2026-09-30 更正 · authentication】
客户端本地生成的签名头, 不是服务器签发的 X-Token。算法:
  authentication = CUSTOM_B64( E( CUSTOM_B64( S ) ) )
  S = "3.0.0.8-{ts}-Android-1.5.8.0-{device_fp}-default"  (78B)
  → 104B →(CBC 分组密码 E, 16B 分组)→ 112B → 152 字符
CUSTOM_B64 字母表: 5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj
E 的 key="ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"(32B) / iv="WonrnVkxeIxDcFbv"(16B)
- 不绑定 path/query: 同一个 auth 可跨 22 个端点复用(已实测)
- 只与 ts 强绑定: ts 过期 → 403502; ts 非法或篡改 auth → 403501
- 自定义字母表解码后前 16 字节恒定 23754ae9d0cbe749f5441e769b45143e
  (旧描述里的 e8cb1f12… 是误用标准 base64 解码的结果)
离线生成器: research/deliverables/authgen.py (服务端实测通过 + 485/485 语料核验)
原理与判定依据: docs/algorithm-auth.md
```

2. **`authentication` 头参数**：
   - `description` → `客户端本地生成的签名头(非服务器 X-Token)。只与 ts 强绑定, 不绑定 path/query; 同一 auth 可跨端点复用。离线生成: research/deliverables/authgen.py`
   - `value` → `<152字符 base64; 自定义字母表解码后 112 字节, 前16字节恒定 23754ae9d0cbe749f5441e769b45143e>`
3. **`ts` / `nonce` 描述**微调（`nonce` 标注"服务端不参与签名校验"）。
4. **`/app/danmu` 参数名修正**：`start_t` → `start_time_point` / `end_time_point`。
5. **4 个 404 接口**在描述末尾追加实测状态说明。
6. **路径引用**：`out/...` 统一改为 `research/...`。

### 结果

| 项 | 值 |
|---|---|
| API 数 | **35**（更新后回读一致，无增无减） |
| 目录数 | 6（未改动） |
| 失败 | **0** |
| 变更前备份 | `research/reports/apipost_backup_before_update.json` |
| 新旧 ID 对照 | `research/reports/apipost_id_mapping.json` |

> ⚠️ **`target_id` 全部变更**（删除+重建所致）。新 ID 形如 `6f0e7exxxxxxx000`，
> 对照表见 `apipost_id_mapping.json`。若别处引用了旧 ID，需按表更新。

### 工具侧发现（Apipost MCP 的 schema bug）

`create_target` 的 JSON Schema 是**自相矛盾**的：

```json
{ "allOf": [ ... ], "properties": {}, "additionalProperties": false }
```

根节点 `properties` 为空却禁止额外属性 ⇒ **任何字段都会被判为"额外属性"**，
该工具在宿主侧**完全无法调用**（实测：连 `{project_id, target_type, name, tool_version, method, url}` 这 6 个必需字段都会被拒）。
`get_project_tree` / `search_target` / `get_target_detail` / `delete_targets` 的 schema 正常。

因此本次更新改用**直连 JSON-RPC**（`research/toolchain/mcp_client.py`）完成，
服务端本身接受同样的 payload。建议向 Apipost 反馈该 schema 缺陷。

## 六、第二轮更新：写入预执行脚本 + 参数实测（2026-09-30 23:5x）

### 6.1 预执行脚本已内置到全部 35 个接口

**35/35 接口**的 `request.pre_tasks` 已写入「authentication 自动取签」脚本（`enabled=1`），
内容见 [`apipost-testing.md`](apipost-testing.md) §二。用户只需启动本地取签服务，
然后在 Apipost 里直接点发送即可。

### 6.2 关键坑：`pre_tasks` 只在「完整 payload」下才会落库

- ❌ 精简 payload（只给 `project_id/parent_id/name/method/url/request.pre_tasks`）→ **静默丢弃**
- ✅ 完整 payload（含 `protocol` / `request.{auth,body,header,query,cookie,restful,pre_tasks,post_tasks}` / `response` / `tags`）→ **正常落库**

另外两条实测结论：

| 结论 | 说明 |
|---|---|
| **目录级 `pre_tasks` 也可用** | 但目录**不能原地更新**（返回 `14000 已存在`），且**删除目录会级联删除其下所有接口** → 本次不动目录 |
| **API 也不能原地更新** | 带 `target_id` 一律 `14000 接口已存在` → 只能删除 + 重建 |

### 6.3 参数实测（本轮新增）

对库里每个接口的 query 参数做了真实请求验证：

| 接口 | 结论 |
|---|---|
| `/app/video/search` | **参数名是 `key`**（库里写对了）。`key=ai&limit=25&page=1` → **34777 B** 真实数据；写成 `keyword` 只返回 **409 B 空响应** |
| `/app/video/key` | `key=ai&limit=10&page=1` → 1561 B ✅ |
| `/app/video/detail` | `cid` 为可选；`id=103558` 与 `id=103558&cid=2` 均返回 7449 B |
| `/app/vod_comment/gettop` | `cid` 为可选；均返回 3801 B |
| `/app/vod_comment/gethitstop` | `vid=103558&cid=2` → 11609 B |
| `/app/vod_comment/getlist` | `vid=103558&cid=2&page=1` → 7665 B |
| `/app/video/list` | `channel=1&sort=weight&limit=6&page=1` → 10309 B |
| `/app/video_update_list/<date>` | 日期在路径里；无 query 也返回 200（433 B） |
| `/app/danmu` | 必填 `start_time_point` / `end_time_point`（毫秒），缺参返回明文 `code=40000` |

上述结论已作为「【2026-09-30 参数实测】」段落追加到对应接口的描述末尾。

### 6.4 结果

| 项 | 值 |
|---|---|
| API 数 | **35**（回读一致） |
| 目录数 | 6（未改动） |
| 带正确 `pre_tasks` 的接口 | **35/35** |
| header 数 = 8 的接口 | **35/35** |
| 失败 | **0** |
| 变更前快照 | `research/reports/apipost_current.json` |
| 本轮 ID 映射 | `research/reports/apipost_id_mapping_v2.json` |

> ⚠️ **`target_id` 再次全部变更**（`6f0e7e...` → `6f0ea3...`）。两轮映射表：
> `apipost_id_mapping.json`（第一轮）、`apipost_id_mapping_v2.json`（第二轮）。

## 七、第三轮更新：后执行脚本（响应判定 + 离线解密）+ 描述更正（2026-10-04）

### 7.1 背景：响应已可完全离线解密

V13/V14 收官后，响应体 `<P0_b64>.<P1_b64>` **不再需要 App/frida** 即可解出明文：

```
P0 = RSA-2048(pub_from_go, K16resp)  --priv_from_go.pem-->  K16resp
P1 = E(key=K16resp, iv=reverse(K16resp)) 逐块 tweak 密文 --decrypt_e--> 明文 JSON
```

因此旧后执行脚本里「离线无法解出明文」的说明**已过时**，本轮全部替换。

### 7.2 更新内容

| 项 | 旧 | 新 |
|---|---|---|
| `request.pre_tasks` | 取签（ts+auth） | 取签 + **刷新随机 nonce** + 写 `jcy_ts` 变量 |
| `request.post_tasks` | 判定 + 归档（不解密） | 判定 + 归档 + **调 `/decrypt` 离线解密** + 写 `jcy_plain`/`jcy_k16resp` |
| `description` | 末尾无解密说明 | 追加「【2026-10-04 V13 收官 · 响应可离线解密】」段 |

脚本全文见 [`apipost-testing.md`](apipost-testing.md) §二 / §九。

### 7.3 结果

| 项 | 值 |
|---|---|
| API 数 | **35**（更新后回读一致） |
| 目录数 | 6（未改动） |
| `pre_tasks` 已写入 | **35/35**（`enabled=1`） |
| `post_tasks` 已写入 | **35/35**（`enabled=1`） |
| header 数 = 8 | **35/35** |
| 失败 | **0** |
| 变更前快照 | `research/reports/apipost_current_v3.json` |
| 本轮 ID 映射 | `research/reports/apipost_id_mapping_v3.json` |
| 同步工具 | `research/deliverables/apipost_sync.py`（`pull` / `update` / `dry`） |

> ⚠️ **`target_id` 第三次全部变更**（`6f0ea3...` → `6f513...`）。
> 三轮映射表：`apipost_id_mapping.json`、`_v2.json`、`_v3.json`。
>
> 根因未变：Apipost 云端 MCP 仍**无原地更新**工具，只能「删旧 + 建新」。

## 八、第四轮更新：预脚本加固 + 参数校正 + 逐接口备注（2026-10-04 06:2x）

### 8.1 触发：用户实测报 `30000 authentication is empty`

用户点「发送」`GET /app/video/list` 返回 `{"code":30000,"message":"解码异常:authentication is empty"}`。

**根因不是接口未更新，而是本地取签服务（127.0.0.1:8791）没在运行。**
判别特征：请求耗时仅 **159 ms** —— 若预脚本取签成功，至少要 4 s。

### 8.2 本轮修正

| 项 | 说明 |
|---|---|
| 预脚本加固 | `await $.ajax` 为主 + **同步 XHR 兜底**；服务未启动时 `console.error` **明示**（不再静默 30000） |
| 启动方式 | 新增项目根 **`启动本地取签服务.bat`**（双击常驻）；Windows 下 `nohup &` 不跨回合存活 |
| 参数校正 | `/app/video/play`：参数**必须在 query**（`?id=&play=&part=`），body 用 `{}` → 20000 |
| 逐接口备注 | 新增 `EP_NOTE`：play（query 提示）/ danmu（必带 part）/ device-base / play-connect / upgrade |
| 矩阵刷新 | `docs/api/live-matrix.md` 重生成（35 接口，20000 = **24**） |

### 8.3 结果

| 项 | 值 |
|---|---|
| API 数 | **35**（回读一致） |
| `pre_tasks` 已写入 | **35/35** |
| `post_tasks` 已写入 | **35/35** |
| 失败 | **0** |
| 快照 | `research/reports/apipost_current_v4.json` |
| 本轮 ID 映射 | `research/reports/apipost_id_mapping_v4.json` |

> ⚠️ **`target_id` 第四次全部变更**（`6f513...` → `6f51f8...`）。根因不变：MCP 无原地更新。

### 8.4 Apipost 脚本 API 核实结论

对照官方文档（[动态修改 Query/Body/Header](https://wiki.apipost.cn/docs/1000)、
[预执行脚本发请求](https://wiki.apipost.cn/docs/sendrequest/)）：

| API | 结论 |
|---|---|
| `apt.setRequestHeader(k,v)` / `apt.removeRequestHeader(k)` | ✅ 正确 |
| `apt.setRequestQuery(k,v)` / `apt.removeRequestQuery(k)` | ✅ 正确 |
| `apt.setRequestBody({...})` / `apt.setRequestBody(k,v)` | ✅ 正确（7.0.4+） |
| `apt.variables.set(k,v)` / `apt.variables.get(k)` | ✅ 正确 |
| `await $.ajax({method,url,success,error})` | ✅ 正确（7.0.4+ 支持 await 转同步） |

→ 脚本本身无语法/API 错误，问题 100% 出在「本地服务未启动」。

## 九、第五轮更新：请求头默认值去中文（2026-10-04 12:2x）

### 9.1 触发：`Invalid character in header content ["authentication"]`

用户已成功启动本地服务（`/forge` 返回 200），但 Apipost 直接抛：

```
Invalid character in header content ["authentication"]
```

### 9.2 根因

库里 `authentication` 头的**默认值**是早期作者写的一段**中文占位说明**：

```
<152字符 base64; 自定义字母表解码后 112 字节, 前16字节恒定 23754ae9d0cbe749f5441e769b45143e>
```

Apipost 基于 Node/Electron，其 HTTP 客户端（`http.validateHeaderValue`）**不允许 header 值含
非 Latin-1 字符**（中文码位 > 0xFF）→ 直接抛错，请求根本没发出去。

同时说明：预脚本的 `apt.setRequestHeader` 并没有覆盖表里这个默认值。

### 9.3 修法

`apipost_sync.py` 新增 `HEADER_FIX`，把两个「随请求变化」的头改成 **ASCII 变量引用**：

| 头 | 旧默认值 | 新默认值 |
|---|---|---|
| `authentication` | `<152字符 base64; 自定义字母表解码后…>`（含中文） | `{{jcy_auth}}` |
| `ts` | `1790650000000`（写死） | `{{jcy_ts}}` |

预执行脚本 `apt.variables.set("jcy_auth"/"jcy_ts", …)` 注入真值 →
**即使 `apt.setRequestHeader` 不生效，变量替换也能把正确值填进 header**（双保险）。

脚本另加：③ 归一化（`_r` 若是 JSON 字符串则 `JSON.parse`；若被包一层 `data` 则解包）、
清洗 `\r\n\t`、失败时打印 `JSON.stringify(_r)` 便于定位。

### 9.4 结果

| 项 | 值 |
|---|---|
| API 数 | **35**（回读一致） |
| 失败 | **0** |
| 快照 | `research/reports/apipost_current_v4.json` |
| 本轮 ID 映射 | `research/reports/apipost_id_mapping_v4.json` |

> ⚠️ **`target_id` 第五次全部变更**（`6f51f8...` → `6f5714...`）。根因不变：MCP 无原地更新。

### 9.5 经验（写库必守）

**任何写进 Apipost header `value` 的内容必须是纯 ASCII。**
中文只能放 `description`（描述不会随请求发送）。
