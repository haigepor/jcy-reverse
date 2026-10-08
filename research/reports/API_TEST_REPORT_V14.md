# API 端到端测试报告 V14（2026-10-04）

> 结论先行：**35 个接口全部用真实请求 + 离线解密跑通**（无需设备/App/frida）。
> 完整分析见 [`docs/analysis/e2e-decrypt.md`](../../docs/analysis/e2e-decrypt.md)，
> 逐接口矩阵见 [`docs/api/live-matrix.md`](../../docs/api/live-matrix.md)。

## 一、本轮成果

| # | 事项 | 状态 |
|---|---|---|
| 1 | 响应离线解密（V13 交付 `decrypt_e.py`） | ✅ 35 接口验证 |
| 2 | 端到端客户端 `jcy_client.py`（伪造请求 + 解密响应） | ✅ |
| 3 | 全接口并行验证驱动 `tmp_all_endpoints_par.py`（6 worker） | ✅ |
| 4 | 本地服务新增 `/decrypt`（完整离线解密响应） | ✅ |
| 5 | Apipost 35 接口 `pre_tasks` + `post_tasks` 更新 | ✅ 35/35 |
| 6 | 文档（V14 全链路 + 矩阵 + 库/调试文档） | ✅ |

## 二、协议要点（本轮更正）

```
请求: authentication = CUSTOM_B64(E_auth(CUSTOM_B64(S)))   # 本地离线生成
      body = CUSTOM_B64(RSA(server_pub,K16)) . CUSTOM_B64(E(K16, rev(K16), PKCS7(params)))
响应: body = CUSTOM_B64(RSA(pub_from_go,K16resp)) . CUSTOM_B64(E(K16resp, rev(K16resp), ...))
```

* **响应 P1 密钥 = K16resp**（V11 的"不是 K16"结论是用 AES 试的，作废）。
* E 是**自研分组密码**（`E(x)=T(SR(SB(AES9(T(x)^rk0))))^C(K)`），非 AES；多块为**逐块 tweak**，非朴素 CBC。
* 成功码是 **20000**（不是 200）；错误也返回 HTTP 200。

## 三、逐接口结果（摘要）

| 类别 | 结果 |
|---|---|
| 解出真实数据（20000） | 28 个（含 video/list 8615B、search 34KB、vod_comment/getlist 4488B） |
| 非加密响应 | `/app/channel/`(301)、`/app/upgrade`(特例)、3 个 404 |
| 游客态受限（50008） | `/app/users/info`、`/app/task/task`、`/app/history` |
| 业务参数未补全（40000） | `/app/video/{device-base,play,play-connect}` |
| 弹幕 | `/app/danmu` **必须带 `part`** → 20000（响应为明文 JSON） |

## 四、未解项

1. `CONST_b`/`Cb_b` 闭式公式未还原 → 每 (K,nblk) 需一次标定（≈1.2s/块，效率瓶颈）。
2. `/app/upgrade` 第三套方案（大写 `Authentication`、magic `905b5ed3`、160B E 密文、不校验 auth）未解。
3. `device-base`/`play`/`play-connect` 的业务参数明文结构未定（请求体用服务端公钥加密，离线不可解）。

## 五、产物索引

| 文件 | 说明 |
|---|---|
| `research/tmp_all_endpoints.json` | 35 接口逐条结果（含明文） |
| `research/captures/live_data_v2/` | 原始密文归档 |
| `research/deliverables/decrypt_e.py` | E 的逐块逆（离线） |
| `research/deliverables/jcy_client.py` | 端到端客户端 |
| `research/deliverables/authgen_server.py` | 本地服务（`/auth` `/forge` `/decrypt` `/relay` `/store`） |
| `research/deliverables/apipost_sync.py` | Apipost 预/后脚本同步 |
| `research/reports/apipost_id_mapping_v3.json` | 本轮 target_id 映射 |
