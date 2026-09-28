# HTTP Body 加密 (apiEncrypt / P0.P1)

## 概要

HTTP 业务 API (视频列表/播放/登录等) 的 POST 请求体为**点分两段的 base64**：

```
<P0_b64>.<P1_b64>
```

| 段 | 内容 | 长度特征 |
|---|---|---|
| **P0** | RSA-2048 加密的"随机会话 key + iv" | **恒定 256 字节** (RSA modulus 长度), 每请求不同 |
| **P1** | AES-CBC(会话 key, iv, 业务 JSON) | 变长, 与业务数据量相关 |

服务器流程: 私钥解 P0 → 取得会话 key/iv → 解 P1 → 处理 → **用同一会话 key 加密响应** → 返回。
客户端 `apiDecrypt` 用内存中留存的会话 key 解响应。
错误响应 (鉴权失败/参数错误) 为明文 JSON。

## 调用链 (反汇编实证)

```
业务代码 → HttpClient.post(url, params) @0x213634 (async)
   │
   ▼
HeadersInterceptor._onRequest @0xa3bdc8        (直接 bl 调用, 地址实证)
   ├─ bl 0x716b7c   FFIUtils.clearKey()        # 清除上一请求的会话 key
   ├─ bl 0x7eee0c   FFIUtils.apiEncrypt(params)
   │     ├─ bl 0x715cb0  getRandomString()     # 随机会话 key
   │     ├─ bl 0x715cb0  getRandomString()     # 随机 iv
   │     ├─ AES-CBC(params)                    # → P1
   │     ├─ RSA-2048(key+iv)                   # → P0
   │     └─ return "<P0_b64>.<P1_b64>"
   └─ JsonCodec.encode({"data": <密文>, "authentication": <X-Token>})
```

- HeadersInterceptor 池引用 (pp+0x1dca8..0x1dcd8):
  `"APPID"` / `"ts"` / `"authentication"` / `"Authentication"` / `"x-version"` / `"tcs"` / `"nonce"` / `"data"`
- `api_encrypt` 亦为服务端下发配置标志 ("本 API 是否启用加密", GSignRuleData)

## 随机源

`getRandomString @0x715cb0` (58 字节小函数) 内部调用 `Random` 系列 stub。
**实测 play-connect 同参数 5 次请求 body 完全相同** → Random 使用**固定种子**
(同参数产生同序列, 种子大概率取自 ts/nonce 组合)。这意味着会话 key 可以离线复算——
种子规则是最后待定项之一。

## 已排除的假设 (不要重复尝试)

| 假设 | 结果 |
|---|---|
| P0/P1 用监控 key qPwC 解 | ✗ (CBC/ECB × 多 IV 组合, printable oracle 0 命中) |
| P0/P1 用信令 key kFGT 解 | ✗ (同上) |
| pp.txt 全部 199 个 16 字符串 × 60 IV 候选 × AES-CBC | ✗ |
| pp.txt 全部候选 × RC4 (P1 非块对齐假设) | ✗ (仅 16B 短样本假阳性) |
| RSA 公钥内嵌 libapp/libcore/libloader/assets | ✗ 未找到 (PEM/DER/b64 全格式) |
| P1 长度 %16==8/12 → 流密码 | RC4 全候选未命中; 具体封装待定 |

P1 长度样本: 24/88/96/432/656/876 (均 %16∈{8,12}) ——**不是 AES-PKCS7 整块**,
推测 P1 b64 串内含额外字段 (长度前缀/签名尾), 或采用非标准分段, 待首装实验定论。

## 响应解密

响应对称使用该请求的会话 key。客户端 `apiDecrypt @0x607518` (async, Future<Map>)。

真机 hex 转储捕获的响应密文样本 (完整 b64, POST /app/video/record):

```
0zmWw/GSuunH9fjrFm0w7rA7APsTryskXva/9K+ZBW120qVXT2eFtR3EZNM4/KGx4nVeRv64ABb/
i80E7hG168gPkJffvuRqvGbh5MB8a/Ushlt9e1rSOZ/+jFoQbyPW93AEDQpUvTF2BHYZxWHEXDIWP
StMhUMVsJOON41lEp+vPRyf4RnxSXMTshU5egIg7fMBJoJ6R2P0JudqwnoHgXLlnDIZWXI+wZtjqX
bTljIIOR8S4jFyuijXIjHwcIBePH5sPzMkEjUDEHSJYQ/lfryFsk5y/jW4H+YoQPLEOpjf...
```

明文 JSON 结构 (来自调用侧类型签名 `Future<Map>` 与 GResponse.from 字段映射):

```json
{"code":200, "data": {...}, "message": "..."}
```

错误响应为明文 (未加密):

```json
{"code":403501,"message":"校验客户端签名失败，请重启app尝试"}
{"code":403502,"message":"检测到设备时间异常，请调整到正确时间后重新打开 App尝试"}
{"code":30000,"message":"解码异常:authentication is empty"}
```

## 抓取/解密方法

```bash
# 1. hook apiDecrypt.enter, dump x1 (密文字符串对象) 1600B hex
# 2. python 端解析: tags@0-3, len(Smi)@8-11, data@16..16+len
# 3. 会话 key 获取: hook getRandomString leave 或运行时内存扫描 (待定)
```
