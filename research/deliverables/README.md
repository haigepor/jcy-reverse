# research/deliverables/ — 对外交付

本目录是可直接运行的交付脚本。**只依赖 `../artifacts/` 与 `../toolchain/`，
全程离线（除 `--test-server` 需要网络），无需真机。**

---

## 一、核心：`authentication` 生成器

### 算法

```
authentication = CUSTOM_B64( E( CUSTOM_B64( S ) ) )

S = "3.0.0.8-{ts}-Android-1.5.8.0-{device_fp}-default"      # 78 字节
```

| 步骤 | 输入 → 输出 | 说明 |
|---|---|---|
| 1 | `S` (78B) → `A1` (104B) | 标准 base64 后按固定 64 字符字母表重映射 |
| 2 | `A1` (104B) → `BODY` (112B) | CBC 分组密码，16B 分组，key 32B / iv 16B |
| 3 | `BODY` (112B) → `AUTH` (152 字符) | 同上字母表再编码 |

字母表：
```
5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj
```
key / iv（取自 libcore.so 数据段，随安装实例固定）：
```
key = "ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"   (32B)
iv  = "WonrnVkxeIxDcFbv"                    (16B)
```

`BODY` 结构：`[0:16]` 恒定 `23754ae9d0cbe749f5441e769b45143e`；
`[16:48]` = 服务端实际校验的 `O[0:32]`，只依赖 `ts`。

> 完整原理、判定依据与注意事项见 [`../../docs/algorithm-auth.md`](../../docs/algorithm-auth.md)。

### 脚本

| 文件 | 说明 |
|---|---|
| `authgen.py` | **离线生成器**。`gen(ts)` → 152 字符头；支持 `--selftest` / `--test-server`；含 `UnicornESession`（批量复用实例） |
| `verify_server.py` | 服务端正例 + 阴性对照（篡改 / 空 auth / 过期 ts） |
| `verify_corpus.py` | 语料 `O[0:32]` 逐进程核验（`LIMIT` 可调） |
| `verify_corpus_batch.py` | 单模拟器批量核验（485 个唯一 ts，约 30 分钟） |
| `probe_matrix.py` / `probe_matrix2.py` | 端点可请求性矩阵（22 个端点） |
| `engine_min.py` | 最小内存引擎尝试（未成功，留档） |

> 纯逻辑（字母表编解码、输入串构造、body 拆分、头拼装）在
> [`src/jcy_protocol/auth.py`](../../src/jcy_protocol/auth.py)；
> 本目录只提供 `E` 的 Unicorn 后端与 CLI。分层依赖方向：`research/` → `src/`。

### 用法

```bash
# 回归自检
./.venv/Scripts/python.exe research/deliverables/authgen.py --selftest

# 生成（默认当前时间）/ 指定 ts / 顺带打服务器
./.venv/Scripts/python.exe research/deliverables/authgen.py
./.venv/Scripts/python.exe research/deliverables/authgen.py --ts 1790755350520
./.venv/Scripts/python.exe research/deliverables/authgen.py --test-server

# 服务端正例/阴性对照
./.venv/Scripts/python.exe research/deliverables/verify_server.py

# 语料 O[0:32] 批量核验
./.venv/Scripts/python.exe research/deliverables/verify_corpus_batch.py
```

Python API：

```python
import sys; sys.path.insert(0, "research/deliverables")
import authgen as AG

auth = AG.gen(1790755350520)                 # → 152 字符
body = AG.custom_b64d(auth)                  # → 112 字节
status, reason, data = AG.probe_server(1790755350520, auth, "12345678", "/app/config")
```

### 依赖

| 项 | 路径 |
|---|---|
| Python 环境 | `.venv`（含 `unicorn`、`pycryptodome`） |
| 目标库 | `research/artifacts/libcore.so` |
| 设备数据段镜像 | `research/artifacts/libcore_dev_img.bin`（8 MB） |
| 设备内存区域 | `research/artifacts/regions_all/` + `regions_all.json`（424 MB） |

### 实现说明

`E` 是 libcore.so 内的**自定义分组密码**：以 AES S-box 为初值、用 key 做 RC4 式
KSA 生成 256 字节密钥相关 S 盒（函数 vaddr `0x2cd8b0`），再加私有轮函数。
经完整参数空间排除，它不是标准 AES、也不是 SM4。

为求结果精确，本工具**直接以 Unicorn 执行 libcore.so 原函数**得到 `E` 的输出，
不做算法近似。单次生成约 4–6 秒（主要耗时在加载 424 MB 区域镜像）。

---

## 二、三通道解密：`decrypt_v5/`

| 文件 | 通道 | 密钥 |
|---|---|---|
| `chan1_monitor.py` | 监控通道（AES-128-CBC） | `qPwClBj7j7ZQraSm` / `p3JdVQl3q7WQJIgG` |
| `chan2_signaling.py` | 信令通道（AES-128-CBC） | `kFGTbLlOzFHQCIKp` / `F3q22XoM8l6T2Ydc` |
| `chan3_http.py` | HTTP body 结构断言 | — |
| `mem_plaintext.py` | 内存明文提取（frida attach + 扫描） | — |
| `run_list.py` / `run_play.py` | 视频列表 / 播放直链 | — |
| `common.py` | 公共工具 | — |
| `samples/` | 真实密文样本 | — |

```bash
for f in chan1_monitor chan2_signaling chan3_http; do
  ./.venv/Scripts/python.exe research/deliverables/decrypt_v5/$f.py
done
```

---

## 三、冻结的取证客户端：`client/`

早期阶段的客户端与 frida 脚本族，**保持冻结作为取证产物**（不再维护）。
新代码请从 [`../../src/jcy_protocol/`](../../src/README.md) 引用。

| 文件 | 说明 |
|---|---|
| `gg_client.py` | Python 客户端（加密层已验证） |
| `gg_*_hook.js` | frida 注入脚本族 |
| `gg_memscan.js` | 内存扫描 |

---

## 四、离线验证页：`demo/`

`demo/index.html` — hls.js 播放验证页（含真实列表数据结构与端点注释）。

---

## 五、验证结论

| 项 | 结果 |
|---|---|
| 服务端实测（3 正例） | HTTP 200 + 真实加密业务数据（2905 / 7493 / 3889 字节） |
| 服务端实测（3 阴性） | `403501` 签名失败 / `30000` 解码异常 / `403502` 设备时间 |
| 真实语料 `O[0:32]` | **485/485 唯一 ts 全部 MATCH** |
| 回归测试 `tests/test_authgen.py` | 5/5 PASS |

## 六、当前能力边界

| 能力 | 状态 |
|---|---|
| `authentication` 头离线生成 | ✅ 服务端实测 HTTP 200 |
| GET / 无 body POST 请求 | ✅ 22/22 端点通过认证层 |
| 响应内容离线解密 | ❌ 需客户端私钥（运行时生成、未内嵌），须在 App 运行态取 |
| 需加密 body 的 POST（play-connect 等） | ❌ 请求体 `P0.P1` 链路尚未打通 |
