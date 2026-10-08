# 证据索引

> 每条结论对应的原始产物路径。全部位于仓库内，可独立复核。

## 密钥证据

| 结论 | 证据位置 |
|---|---|
| 监控 key `qPwClBj7j7ZQraSm` | research/ffi_log.jsonl (`AES_KEY_SETUP` 事件, aes_v8_set_encrypt_key, hex 715077436c426a376a375a517261536d) |
| 信令 key 出处 (静态) | research/artifacts/blutter_out/pp.txt `[pp+0x7000]/[pp+0x7008]` (紧邻 pp+0x7010 AESMode{cbc}) |
| 信令 key 验证 (动态) | research/manual_log2.jsonl `sig.call.leave` → 解密 `{"action":"get_app_info",...}` |
| 信令响应完整密文样本 | 本文 signaling-channel.md 内嵌 96 字符 b64 |
| 心跳诱饵 JSON | research/manual_log2.jsonl `sig.call.enter` 416B 解密 (随机 16 字符键值对) |
| HTTP 响应密文 (record/play-connect/play/device-base/config.video) | research/key_log.jsonl apiDecrypt.enter x1 (hex, len 字段 + data) |
| HTTP 响应 URL 配对 | 同上 x2 (完整 `http://43.145.33.254:27990/app/...`) |

## 调用链证据 (静态反汇编)

| 结论 | 证据位置 |
|---|---|
| HeadersInterceptor → clearKey/apiEncrypt | HeadersInterceptor._onRequest @0xa3bdc8 的 bl 目标: 0x716b7c (clearKey), 0x7eee0c (apiEncrypt) |
| apiEncrypt → getRandomString ×2 | apiEncrypt @0x7eee0c bl 0x715cb0 ×2 |
| __call 监控加密用 qPwC | __call @0x6eed7c 池引用 pp+0x1b838/0x1b840 + Encrypter 调用 |
| _loaderCall 用 kFGT 系 | _loaderCall @0x72cf20 池引用 pp+0x7000/0x7008/0x7010 + "call" 字符串 |
| 头集合 (APPID/ts/nonce/tcs/x-version/authentication) | HeadersInterceptor._onRequest 池引用 pp+0x1dca8..0x1dcd8 |
| X-Token / new-token | TokenInterceptor onRequest @0xa3bc20 / onResponse @0xa3c4b8 池引用 pp+0x1dbb0 / pp+0x1dba0 |
| 心跳走 Encrypter.encrypt | backtrace: Encrypter.encrypt ← __call @0x6eed7c (research/manual_run.log) |
| 地址系统互通 | 0xa3bc20 − 0x4b6b40 = 0x5850e0 = reFlutter dump TokenInterceptor.onRequest3 |

## 网络实测证据

| 结论 | 证据位置 |
|---|---|
| 主 API 43.145.33.254:27990 存活 | 重放实验 (requests, 200 响应) |
| authentication 头名 | 无该头 → code 30000 "authentication is empty" |
| token 绑定 ts/nonce | 403501/403502 错误响应 (重放变体) |
| 列表端点完整 query | research/auth_full_rows.json `/app/video/list?channel=1&sort=weight&limit=6&page=1` |
| 列表 GET 无 body | research/auth_samples.json list 行 body_b64=0 |

## 工具产物

| 产物 | 路径 |
|---|---|
| blutter 对象池 (2.6MB) | research/artifacts/blutter_out/pp.txt |
| blutter 函数索引 (102 包) | research/artifacts/blutter_out/asm/ |
| blutter frida 模板 | research/artifacts/blutter_out/blutter_frida.js |
| reFlutter dump (59470 符号) | reflutter_work/dump2.dart + dump2_parsed.jsonl |
| 88 条抓包样本 | research/auth_samples.json |
| 28 条完整头样本 | research/auth_full_rows.json |
| 35 个密文样本 | research/ct_samples/*.hex |
| 组合包 APK (reFlutter+gadget) | reflutter_work/combo.RE-gadget-aligned-debugSigned.apk |
| hook 脚本族 | research/gg_ffi_hook.js, gg_manual_hook*.js, gg_hex_hook.js, gg_key_hook.js |
| 监控日志族 | research/ffi_log*.jsonl, dart_log*.jsonl, manual_log*.jsonl, hex_log.jsonl, key_log.jsonl |
| Python 客户端 (已验证加密层) | research/deliverables/client/gg_client.py |
| 离线验证页 | research/deliverables/demo/index.html |
