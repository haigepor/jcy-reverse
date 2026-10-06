# 在 Apipost 里手动调试「囧次元」接口

> 目标：在 Apipost 里点 **发送** 就能拿到 `200 + 加密业务数据`。
> 依赖：[`research/deliverables/authgen_server.py`](../../research/deliverables/authgen_server.py)（本地取签服务）。

## 一、为什么开箱即用会失败

Apipost 库里 35 个接口的请求头是这样写的：

| key | value | 问题 |
|---|---|---|
| `ts` | `1790650000000` | **2026-09-29 的旧时间戳**，服务端直接 `403502 设备时间异常` |
| `authentication` | `<152字符 base64; ...>` | **占位符，不是真值**，服务端 `403501 校验客户端签名失败` |

`authentication` 是**客户端本地生成**的签名，且只与 `ts` 强绑定、有效期约 2 分钟
（实测窗口 `(136s, 188s)`）。所以每次调试都需要**重新取一份新鲜的 `ts` + `authentication`**。

> 算法与原理见 [`../algorithm-auth.md`](../algorithm-auth.md)；
> 逆向全过程见 [`../reverse-journal-auth.md`](../reverse-journal-auth.md)。

## 二、路线 A（推荐）：本地取签服务（脚本已内置在库里）

### 步骤 1 · 启动本地取签服务

**最省事：双击项目根目录的 `启动本地取签服务.bat`**，保持窗口打开即可（看到 `authgen 服务已启动` 就是就绪）。

等价命令行：

```bash
cd C:/Users/haige/Desktop/instruct/囧次元
./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup
```

输出：

```
预热完成 17.61s, ct0=23754ae9d0cbe749f5441e769b45143e
authgen 服务已启动: http://127.0.0.1:8791/auth
```

服务只监听 `127.0.0.1`，提供两个端点：

| 端点 | 返回 |
|---|---|
| `GET /auth` | `{"ts":1790783579142,"authentication":"6Msf...","input":"...","ct0":"23754ae9...","elapsed":3.74}` |
| `GET /health` | `{"ok":true,"device_fp":"16613a...","boots":1,"auth_len":152}` |

单次取签约 **3.8 秒**（Unicorn 执行 libcore.so 原函数，已复用模拟器实例）。

### 步骤 2 · 直接点发送

**预执行脚本已经写入库里全部 35 个接口**（`request.pre_tasks`，名称「authentication 自动取签」，
`enabled=1`），无需任何手工配置。脚本内容：

```js
// ===== 囧次元 authentication 自动取签 =====
// authentication 客户端本地生成, 只与 ts 强绑定, 有效期约 2 分钟 → 每次发送前重新取签
await $.ajax({
    method: "GET",
    url: "http://127.0.0.1:8791/auth",
    timeout: 60000,          // 本地取签约 4 秒，务必放宽
    success: function (r) {
        apt.removeRequestHeader("ts");
        apt.removeRequestHeader("authentication");
        apt.removeRequestHeader("nonce");
        apt.setRequestHeader("ts", String(r.ts));
        apt.setRequestHeader("authentication", r.authentication);
        apt.setRequestHeader("nonce", String(Math.floor(Math.random() * 90000000 + 10000000)));
        apt.variables.set("jcy_ts", String(r.ts));
        console.log("[jcy] ts=" + r.ts + " auth=" + r.authentication.slice(0, 24) + "...");
    },
    error: function (e) {
        console.error("[jcy] 取签失败: 请先启动 research/deliverables/authgen_server.py --warmup", e);
    }
});
```

它会在发请求前把 `ts` 与 `authentication` 换成新鲜值，然后直接点 **发送** 即可。

> 用的是 Apipost 官方 API：`apt.setRequestHeader` / `apt.removeRequestHeader`
> （见 [预执行脚本文档](https://v7-wiki.apipost.cn/docs/166/)）。
> 先 remove 再 set，避免同名字段出现重复头。

### 若脚本未生效

| 检查项 | 说明 |
|---|---|
| Apipost 版本 | `await $.ajax` 需 **7.0.4+**；低版本请去掉 `await` 改为回调写法（但会异步，可能赶不上发请求） |
| 服务是否在跑 | `curl http://127.0.0.1:8791/health` |
| 端口占用 | 默认 8791，可用 `--port` 改（记得同步改脚本里的 URL） |
| 脚本被禁用 | 在「预执行操作」里确认该脚本 `enabled` 勾选 |

## 三、路线 B（手动，不改脚本）

```bash
# 打印一份新鲜 auth（有效期约 2 分钟）
./.venv/Scripts/python.exe research/deliverables/authgen.py
```

输出形如：

```
ts        = 1790783579142
input     = 3.0.0.8-1790783579142-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default
auth (152) = 6MsfEg71pCxZ4ipNACeen...
```

把 `ts` 和 `auth` 分别粘进 Apipost 的 `ts` / `authentication` 两个请求头，**2 分钟内**点发送。

> 也可用 `curl` 直接取：
> ```bash
> curl http://127.0.0.1:8791/auth
> ```

## 三·B、路线 C（零配置兜底）：一键 `/relay`

完全**不需要**任何请求头、变量或脚本。本地服务替你伪造签名 → 直发真实服务端 → 返回结果：

```bash
# 快速档：只回原始 <P0>.<P1> 信封（大响应秒回，~4s）
curl "http://127.0.0.1:8791/relay?path=%2Fapp%2Fvideo%2Flist%3Fchannel%3D1%26sort%3Dweight%26limit%3D6%26page%3D1&method=GET&decrypt=0"

# 完整档：顺带离线解密（大响应要数分钟）
curl "http://127.0.0.1:8791/relay?path=%2Fapp%2Fvod_comment%2Fgettop%3Fvid%3D113354&method=GET"
```

| 参数 | 说明 |
|---|---|
| `path` | 接口路径（含 query），**必须 URL 编码**（`/`→`%2F`、`?`→`%3F`、`&`→`%26`） |
| `params` | 加密业务参数 JSON，默认 `{}` |
| `method` | `GET` / `POST`，默认 `POST`。**GET 必须显式写 `method=GET`**，否则会带 body → `40000` |
| `decrypt` | `0` = 只回信封（快）；缺省 = 顺带解密（慢） |

返回：`{"ok":true,"status":200,"response":"<P0>.<P1>","decrypted":{...明文JSON...}}`

> **注意**：`GET` 端点**不能带 body**，否则服务端会把 body 当参数解析 → `{"code":40000,"参数错误"}`。
> 本地服务已按此修正（`method=GET` 时不发 body）。若你的 8791 仍是旧进程，请**重启 `启动本地取签服务.bat`** 加载修复。

## 三·C、终端一键取数：`jcy_fetch.py`（最省事，不依赖 .bat）

一条命令跑完「取签 → 发请求 → 离线解密 → 打印数据」，**完全独立**（进程内自己伪造，不需要 8791 服务）：

```bash
# 默认：视频列表（GET，query 参数写在路径里）
./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py

# 指定接口
./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py "/app/video/list?channel=1&sort=weight&limit=6&page=1"

# POST（参数走加密 body）
./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py /app/video/record --method POST --params '{}'

# 只看响应形态，不解密（大响应秒回）
./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py "/app/video/list?channel=1&sort=weight&limit=6&page=1" --no-decrypt

# 打印可粘进 Apipost 的 ts / authentication（2 分钟内有效）
./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py --emit-auth

# 把原始响应与明文存盘
./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py --save research/reports/video_list_demo
```

| 参数 | 说明 |
|---|---|
| `path` | 接口路径（含 query），默认视频列表 |
| `--method` | `GET`/`POST`，默认按是否含 `?` 自动判断 |
| `--params` | 加密业务参数 JSON（POST 用），默认 `{}` |
| `--no-decrypt` | 只回原始信封，不解密（快） |
| `--blocks N` | **只解前 N 块**（秒级，明文截断）——快速看 `code` / 前几条数据 |
| `--emit-auth` | 只打印 `ts`/`authentication`/`body`，不发请求 |
| `--save PREFIX` | 存 `PREFIX.raw`（原始）与 `PREFIX.json`（明文） |

退出码：`0`=成功(20000) / `2`=发送失败 / `3`=没拿到加密数据 / `4`=解密失败 / `5`=认证通过但业务码非 20000。

### 解密为什么慢、能不能达到 App 速度（2026-10-04 实测）

**慢的不是「解密」，是「标定」。** 我们的实现是**用 Unicorn 仿真 ARM64 执行 libcore.so 里的
自研密码 E**，而不是重写算法；App 快是因为它跑原生代码。

| 环节 | 实测速率 | 说明 |
|---|---|---|
| **标定**（Unicorn 仿真，`EDecryptor.calibrate`） | **≈0.53 秒/块**（线性） | 唯一瓶颈：`_enc_big(dummy)` 要把每个块都仿真一遍 |
| **纯 Python 求逆**（`F_inv` 逐块） | **0.0017 秒/块（596 块/秒）** | 快 **300 倍**，基本免费 |

⇒ 所以 `/app/video/list`（539 块）全解约 **5–9 分钟**；`/app/vod_comment/gettop`（约 20 块）几秒。

**能不能达到 App 速度？能——但必须把标定变成纯 Python**，即还原 `CONST_b / Cb_b` 的生成规则：

- 已知：`E(x) = T(SR(SB(AES9(T(x)^rk0)))) ^ C(K)`，`rk` = 标准 AES 调度 —— **纯 Python 完全可算**；
- 已知：`CONST_0 = Cb_0 = 0`（块 0 无 tweak）；
- **未知**：`CONST_b`（只依赖 `(K,b)`）的生成规则，藏在 OLLVM 的 `0x2d9ed0` 里。
- 已做的假设检验（`research/tmp_tweak_hunt.py`）：`CONST_b` **不是** `E(块号编码)` 这类简单形式
  （14 种候选全不中）；`Cb_b = CONST_b ^ CONST_{b+1}` 只对 `b=1` 巧合成立，**不普适**。
- 线索：`0x2d9014` 读常量 `1f 3e 5d 7c 9b ba d9 f8`（= 1..8 × `0x1f`）—— 像「块号计数器 tweak」。

**在那之前，实用的提速（已实现）：**

| 手段 | 效果 |
|---|---|
| **只解前 N 块** `--blocks N` / `/decrypt?blocks=N` / `/relay?...&blocks=N` | `--blocks 8` 实测 **20.7 秒**拿到 `code=20000` + `total=3366` + 首条数据 |
| 解密移出服务进程（子进程） | 再慢也不卡 `/forge`、`/proxy` |
| 大响应自动转后台 + `/plain` | 接口立即返回，结果落 `research/reports/last_plain.json` |
| 标定按 `(K, nblk)` 缓存 | 同一 K 复用（本场景每次 K 都不同，收益有限） |
| 并行 | ❌ 块间链式依赖，标定无法并行 |

## 三·D、路线 D（Apipost 最省事）：本地透明代理 `/proxy`

如果 Apipost 里 `{{jcy_auth}}` 死活替换不成功，**别再跟变量较劲**——把接口 URL 的**前缀**换掉即可：

```
原： http://43.145.33.254:27990/app/video/list?channel=1&sort=weight&limit=6&page=1
改： http://127.0.0.1:8791/proxy/app/video/list?channel=1&sort=weight&limit=6&page=1
```

本地服务会**自动注入新鲜的 `ts` / `authentication`**（POST 还会自动生成加密 body）后转发到真实服务端，
**原样返回** `<P0>.<P1>`。所以：

- ✅ 不需要任何变量、请求头、预执行脚本；
- ✅ 路径 / query / method 全部保留，请求结构不变；
- ✅ 返回的是**真实服务端的原始响应**，后执行脚本（归档/解密）照常工作；
- POST 若想指定业务参数：`?params={"a":1}`（服务会把它从转发路径里摘掉，不会污染真实请求）。

验证（本地 8792 实例实测）：

| 请求 | 结果 |
|---|---|
| `GET /proxy/app/vod_comment/gettop?vid=113354` | 200，433 B 信封 |
| `GET /proxy/app/video/list?channel=1&sort=weight&limit=6&page=1` | 200，11845 B 信封 |

> 需要**重启 `启动本地取签服务.bat`** 才会加载 `/proxy`（旧进程没有这个端点）。

### ⚠ 用 `/proxy` 时请把「预执行/后执行操作」两个脚本关掉

`/proxy` 已经自动注入签名，**预脚本多余**；而**后脚本**里的 `/store` 解密会把事情搞砸——
E 的离线解密靠 Unicorn 仿真（**约 1 秒/块**），`/app/video/list` 约 **539 块 ≈ 9 分钟**，
期间会占住 GIL 让整个服务（含 `/proxy` 本身）无响应，Apipost 就报 `callback timed out`。

**已修**（2026-10-04）：解密改到**独立进程**执行，服务不再被卡死；且大响应自动转后台，
接口立即返回 `{"queued": true, ...}`。读取后台结果：

```bash
curl http://127.0.0.1:8791/plain          # 或直接打开文件
# research/reports/last_plain.json
```

判定阈值：**≤ 40 块**同步解完（明文直接显示）；**> 40 块**转后台。所以：
`/app/vod_comment/gettop`（约 20 块）能直接在 Apipost 里看到明文；`/app/video/list`（539 块）走后台。

> 想看大响应明文，最省事的是终端脚本（后台跑、不卡界面）：
> `./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py`

## 四、实测结果（2026-09-30 23:5x）

用取签服务返回的 auth 打真实服务器：

| 方法 | 路径 | 结果 |
|---|---|---|
| GET | `/app/config` | **200**，2905 B 加密业务数据 |
| GET | `/app/video/list?channel=1&sort=weight&limit=6&page=1` | **200**，10309 B |
| GET | `/app/banners/0` | **200**，7473 B |
| POST | `/app/users/task` | **200**，517 B |

**4/4 通过。**

## 五、判定「成功」的标准（重要）

该服务端**错误也返回 HTTP 200**，业务码在 JSON body 里：

| 现象 | 含义 |
|---|---|
| body 是 `<P0_b64>.<P1_b64>` 密文（几百~几千字节，含 `.`） | ✅ 请求被接受，返回真实业务数据 |
| body 是明文 `{"code":30000,...}` | ❌ `authentication` 为空或格式错 |
| body 是明文 `{"code":403501,...}` | ❌ 签名校验失败（`ts` 与 auth 不配对 / auth 过期 / auth 被改） |
| body 是明文 `{"code":403502,...}` | ❌ 设备时间异常（`ts` 太旧） |
| body 是 3 字节 | ❌ 路径不存在（404），检查方法与路径 |

## 六、常见问题

> **⚠ 必须先声明变量（否则 `{{jcy_auth}}` 不会被替换）**
> Apipost 只对**已声明**的变量做 `{{}}` 替换。请在左侧「环境 / 全局变量」里新增三个变量：
>
> | 变量名 | 值（占位即可） | 说明 |
> |---|---|---|
> | `jcy_auth` | `x` | 预脚本每请求覆盖为新鲜的 authentication |
> | `jcy_ts` | `1` | 预脚本每请求覆盖为当前毫秒时间戳 |
> | `jcy_body` | `x` | POST 接口的加密请求体 |
>
> 未声明时，header 里的 `{{jcy_auth}}` 会**按字面量发出去**，服务端返回
> `{"code":30000,"message":"解码异常:authentication is error"}`（注意是 **is error**，不是 is empty）。
>
> **加在哪一页？——「全局变量 / 环境变量」，不是「全局参数」。**
>
> | 页面 | 用途 | 本任务是否需要 |
> |---|---|---|
> | **环境变量 / 全局变量** | 一个「名字 → 值」的字典，供 `{{名字}}` 取值 | ✅ **就加这里**（加 `jcy_auth` / `jcy_ts` / `jcy_body` 三个） |
> | 全局参数（Header/Body/Query…） | 给**整个项目所有接口**统一拼请求参数 | ❌ 不需要。它会让每个接口都多带一份 header，和接口自带的重复 |
>
> 关键：`jcy_ts` **没有固定值**，它是**毫秒时间戳**，每次请求都不同，且必须与 `authentication`
> 成对（服务器校验 ts 新鲜度，窗口只有分钟级）。所以变量里填**任意占位值**（如 `0` / `x`）即可，
> 预执行脚本每次发送前都会把它覆盖成新鲜值。**填死一个时间戳必然 `is error`。**
>
> **自检：点发送后看 Apipost 下方「控制台」**
> - 出现 `[jcy] pre-script start -> ...` 且随后 `[jcy] ✅ ts=... auth=...` → 预脚本正常；
> - 完全没有 `[jcy]` 开头任何一行 → **预脚本没运行**（脚本被禁用 / 接口节点是旧版），
>   重新从库里打开该接口（本库最近一次全量更新在 2026-10-04 12:29，节点 ID 已变化）；
> - 出现 `[jcy] ❌ 取签失败 ...` → 本地服务没起，跑 `启动本地取签服务.bat`。

> **⚠ 最常见：`{"code":30000,"message":"解码异常:authentication is empty"}`**
> 这是**本地取签服务没在运行**（或已退出），预执行脚本取签失败、`authentication` 头为空导致的，
> **不是接口没更新**。判断特征：请求耗时只有 ~150 ms（若取签成功至少 4 s）。
> 处理：双击项目根目录的 **`启动本地取签服务.bat`**，看到 `authgen 服务已启动` 后，再回 Apipost 点「发送」。
> 自检：`curl http://127.0.0.1:8791/health` 应返回 `{"ok":true,...}`。

| 现象 | 原因与处理 |
|---|---|
| **`Invalid character in header content ["authentication"]`** | 库中 `authentication` 头的**默认值含中文占位说明**，Node/Electron 的 HTTP 客户端拒绝非 Latin-1 的 header 值。**已修**：默认值改为 ASCII 变量 `{{jcy_auth}}`（`ts` 同理用 `{{jcy_ts}}`），由预脚本注入 |
| `30000` + 请求仅 ~150ms | **本地取签服务未启动** → 跑 `启动本地取签服务.bat`（见上框） |
| **`30000` + `authentication is error`** | header 里 `{{jcy_auth}}` **没被替换**（变量未声明）→ 见本节顶部「必须先声明变量」 |
| **`callback timed out`** | **本地服务被长解密卡死了**（不是网络问题）。后执行脚本的 `/store` 会解密响应，而 E 的离线解密靠 Unicorn 仿真（约 1 秒/块），`/app/video/list` 要 **~9 分钟**；期间整个服务（含 `/forge`、`/proxy`）无响应 → Apipost 超时。**已修**：大响应自动转**独立进程**后台解密，接口立即返回。需**重启 `启动本地取签服务.bat`**。 |
| 用 `/proxy` 仍 `callback timed out` | 同上：先重启 .bat；并且用 `/proxy` 时**请关掉预/后执行脚本**（/proxy 已自带签名，后脚本的解密会拖慢） |
| 取签脚本超时 | 本地服务首次调用要 ~18 秒预热；加 `--warmup` 或把 `timeout` 调到 120000 |
| `403501` | `ts` 与 `authentication` 不是同一次取的 —— 必须成对使用 |
| `403502` | `ts` 太旧（>2 分钟）—— 重新取签 |
| `404` | 该接口路径已失效：`/app/v2/config/host`、`/app/playaddr/v4/client`、`/app/login/smscode`；`/app/channel/`（带斜杠）为 301 |
| `code=40000`（`/app/danmu`） | **必须带 `part`（集名）**，如 `part=第1集`；缺则 40000（库中已修正） |
| `code=40000`（`/app/video/play`） | 参数必须在 **query** 上（`?id=&play=&part=`），body 用 `{}` 即可；缺 query 则 40000 |
| `code=40000`（`/app/video/play-connect`、`/app/video/device-base`） | 真机请求体为**加密的设备/播放上下文**（明文结构未还原），当前只能验证「认证层通过」 |
| `50008` | 游客态受限：`/app/users/info`、`/app/task/task`、`/app/history`（需登录态） |

## 七、相关文件

| 文件 | 说明 |
|---|---|
| `research/deliverables/authgen_server.py` | 本地取签服务（含 `/store` 密文归档、`/classify` 形态判定） |
| `research/deliverables/authgen.py` | 命令行取签 / 自检 / 服务端实测 |
| `docs/api/apipost-library.md` | Apipost 库分析与三轮更新记录 |
| `docs/algorithm-auth.md` | 算法原理、判定依据、注意事项 |
| **[`research/reports/handoff/HANDOFF_DECRYPT_RESPONSE.md`](../../research/reports/handoff/HANDOFF_DECRYPT_RESPONSE.md)** | **交接文档：如何拿到客户端 RSA 私钥以解密响应体** |

## 八、响应解密（【2026-10-04 V14 更正】已可完全离线解密）

> **本文档旧版曾断言"响应离线无法解密"，该结论已作废。**

响应体 `<P0_b64>.<P1_b64>` 现已**完全离线可解**：

```
P0 = RSA-2048(pub_from_go, K16resp)  --priv_from_go.pem-->  K16resp   (离线, 100%)
P1 = E( key = K16resp , iv = reverse(K16resp) ) 逐块 tweak 密文
     --decrypt_e 逐块求逆-->  明文 JSON
```

一键（本地服务）：

```bash
curl -X POST http://127.0.0.1:8791/decrypt -d "$(cat resp.txt)"
#  -> {"ok":true,"k16resp":"...","json":{...},"plain":"...","plain_len":N}
```

交付物：`research/deliverables/decrypt_e.py`（`decrypt(P1, K16) -> bytes`）、
`research/deliverables/jcy_client.py`（端到端客户端）。原理见
[`../crypto/http-body.md`](../crypto/http-body.md) 的 V13 / V14 章节。

> 后执行脚本已内置「归档 + 离线解密」，明文写入测试变量 `jcy_plain`（见 §九）。

## 九、后执行脚本（响应判定 + 离线解密 + 归档）

库里全部 35 个接口的 `request.post_tasks` 已写入下述脚本（`enabled=1`）：

```js
// ===== 囧次元 响应判定 + 离线解密 + 归档 =====
// 前置：本机运行  ./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup
// 关闭解密：环境变量 jcy_decrypt = 0（只归档不解密，避免大响应等待）
var text = (response.raw && response.raw.responseText) || "";
var isEnvelope = text.indexOf(".") > 0 && text.length > 400 && text.charAt(0) !== "{";
var wantDecrypt = String(apt.variables.get("jcy_decrypt") || "1") !== "0";
if (isEnvelope) {
    apt.assert('response.raw.responseText.indexOf(".") > 0');   // 加密业务数据 = 通过
    console.log("[jcy] ✅ 认证通过, 返回加密业务数据 " + text.length + "B");
} else {
    console.warn("[jcy] ⚠ 非加密响应(明文错误码或空): " + text.slice(0, 200));
}
await $.ajax({
    method: "POST",
    url: "http://127.0.0.1:8791/store",
    timeout: 900000,        // 大响应离线解密较慢(逐块), 放宽到 15 分钟
    headers: { "content-type": "application/json" },
    data: JSON.stringify({ body: text, decrypt: isEnvelope && wantDecrypt,
                           path: (typeof request !== "undefined" && request && request.url) ? request.url : "" }),
    success: function (r) {
        console.log("[jcy] 归档 verdict=" + JSON.stringify(r.verdict));
        if (r.decrypted && r.decrypted.ok) {
            console.log("[jcy] 🔓 明文: " + JSON.stringify(r.decrypted.json).slice(0, 400));
            apt.variables.set("jcy_plain", JSON.stringify(r.decrypted.json));
            apt.variables.set("jcy_k16resp", r.decrypted.k16resp);
        }
    },
    error: function (e) { console.error("[jcy] 归档/解密失败: 请启动 authgen_server.py", e); }
});
```

作用：

| 步 | 动作 |
|---|---|
| 1 | 判定响应形态：加密业务数据（通过）/ 明文错误码（失败原因） |
| 2 | `apt.assert` 断言 —— 加密体存在即测试通过 |
| 3 | `POST /store` 归档密文到 `research/captures/apipost_responses.jsonl` |
| 4 | `POST /store`（`decrypt:true`）离线解出明文 JSON |
| 5 | 明文写入测试变量 `jcy_plain` / `jcy_k16resp`，供后续接口引用 |

### 更新方式

Apipost 云端 MCP **无原地更新**能力（`create_target` 带 target_id 一律 `14000 接口已存在`），
故用 `research/deliverables/apipost_sync.py` 走「拉详情 → 重建 → 删旧 → 建新」：

```bash
./.venv/Scripts/python.exe research/deliverables/apipost_sync.py pull     # 只读快照
./.venv/Scripts/python.exe research/deliverables/apipost_sync.py update   # 全量更新 35 接口
```

> ⚠️ 更新后 `target_id` **全部变更**，映射表 `research/reports/apipost_id_mapping_v3.json`。

## 十、相关文件

| 文件 | 说明 |
|---|---|
| `research/deliverables/authgen_server.py` | 本地服务：`/auth` `/forge` `/unwrap` **`/decrypt`** `/relay` **`/proxy`** `/store` `/classify` |
| `research/deliverables/authgen.py` | 命令行取签 / 自检 / 服务端实测 |
| `research/deliverables/decrypt_e.py` | 响应 P1 的离线解密交付物（E 的逐块逆） |
| `research/deliverables/jcy_client.py` | 端到端客户端（请求伪造 + 响应解密） |
| `research/deliverables/jcy_fetch.py` | **终端一键取数**（伪造签名 → 直发 → 离线解密 → 打印数据） |
| `research/deliverables/decrypt_cli.py` | 独立进程解密器（stdin 进 `<P0>.<P1>`，stdout 或指定文件出 JSON） |
| `research/deliverables/apipost_sync.py` | Apipost 库预/后脚本同步（拉详情 / 删旧建新） |
| `docs/api/live-matrix.md` | 35 接口端到端实测矩阵 |
| `docs/crypto/http-body.md` | 请求/响应体加密全链路（V12/V13/V14） |
| `docs/algorithm-auth.md` | authentication 算法原理与判定依据 |
