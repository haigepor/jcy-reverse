# 加密总览：三通道架构

囧次元客户端 (com.tudou.tool, Flutter/Dart 3.6.0) 存在**三条相互独立的加密通道**，
分别服务 C2 心跳、WebRTC 信令/行为上报、HTTP 业务 API。

## 架构图

```
┌────────────────────────────────────────────────────────────────┐
│                        Dart 层 (libapp.so)                      │
│                                                                │
│  FFIUtils (package:guoguo/utils/ffi_utils.dart)                │
│   ├─ __call @0x6eed7c      通道帧加密 (AES-CBC) + FFI 调用      │
│   ├─ _rawCall @0x6eeca8    → libcore.so!call   (监控通道)       │
│   ├─ _loaderCall @0x72cf20 → libloader.so!call (信令通道)       │
│   ├─ apiEncrypt @0x7eee0c  HTTP body 加密入口                  │
│   ├─ apiDecrypt @0x607518  HTTP 响应解密入口                   │
│   ├─ getRandomString @0x715cb0  每请求随机会话 key/iv           │
│   └─ clearKey @0x716b7c    每请求前清除旧会话 key               │
│                                                                │
│  HeadersInterceptor @0xa3bdc8   HTTP 头/认证/body 组装          │
│  TokenInterceptor @0xa3bc20     X-Token 回传 / new-token 存储   │
│  HttpClient.post @0x213634      dio 封装                        │
└────────────────────────────────────────────────────────────────┘
         │ FFI                      │ FFI               │ dio (dart:io)
         ▼                          ▼                   ▼
   libcore.so!call            libloader.so!call    HTTP 明文传输
   (监控通道)                  (信令通道)            (业务 API)
```

## 三通道对比

| | 通道 1: 监控 | 通道 2: 信令 | 通道 3: HTTP API |
|---|---|---|---|
| **载体** | libcore.so `call`/`init` 导出 | libloader.so `call`/`reload` 导出 | dio → `http://43.145.33.254:27990` |
| **算法** | AES-128-CBC + PKCS7 | AES-128-CBC + PKCS7 | 每请求随机会话 key + RSA-2048 包裹 |
| **key** | `qPwClBj7j7ZQraSm` | `kFGTbLlOzFHQCIKp` | 随机 (getRandomString) |
| **iv** | `p3JdVQl3q7WQJIgG` | `F3q22XoM8l6T2Ydc` | 随机 (getRandomString) |
| **帧结构** | b64(416B 诱饵 JSON) | b64(416B 诱饵 JSON) | `"<P0_b64>.<P1_b64>"` |
| **破解状态** | ✅ 完全破解 | ✅ 完全破解 | 结构完全清楚; 会话 key 运行时获取 |
| **文档** | [监控通道](monitor-channel.md) | [信令通道](signaling-channel.md) | [HTTP body](http-body.md) |

## 诱饵 JSON (通道 1/2 共用格式)

上行帧解密后是一个 **416 字节左右的 JSON 对象**，由十几对**随机 16 字符键值对**
(如 `"h1cV0LZzse1rAtb":"XwysVVGVy8xry..."`) 组成，真实指令/参数以正常字段名
(`"action"` / `"params"` / `"data"` 等) 混在其中。
观察者无法区分哪些字段是真实指令——**真实字段的键名是固定小写单词**，与随机键的
16 字符大写开头形态形成对比，这是识别真实指令的方法。

真实示例 (信令响应，已解密)：

```json
{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}
```

## 密钥常量在二进制中的位置

blutter 对象池 (research/artifacts/blutter_out/pp.txt)：

```
[pp+0x7000] String: "kFGTbLlOzFHQCIKp"     ← 信令 key
[pp+0x7008] String: "F3q22XoM8l6T2Ydc"     ← 信令 iv
[pp+0x7010] Obj!AESMode@b6c821 : { off_10: "cbc" }
[pp+0x7018] TypeArguments: <NativeFunction<(dynamic this, Pointer<Utf8>) => Pointer<Utf8>>>
[pp+0x1b838] String: "qPwClBj7j7ZQraSm"    ← 监控 key (__call 池引用)
[pp+0x1b840] String: "p3JdVQl3q7WQJIgG"    ← 监控 iv
```

运行时确认 (frida hook libcore.so 的 `aes_v8_set_encrypt_key`)：

```
[KEY] aes_v8_set_encrypt_key bits=128 key=715077436c426a376a375a517261536d
     → ASCII "qPwClBj7j7ZQraSm"
```

## Python 实现

见 `research/deliverables/client/gg_client.py` 第二阶段加密层：

```python
from gg_client import channel_encrypt, channel_decrypt, SIG_KEY, SIG_IV, MON_KEY, MON_IV

# 信令响应解密 (真实密文示例)
pt = channel_decrypt(
    "VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L"
    "3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY=",
    SIG_KEY, SIG_IV)
# → b'{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}'
```
