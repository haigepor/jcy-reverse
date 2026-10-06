# 监控通道 (libcore.so, qPwC)

## 概要

App 内置一条 **C2 (Command & Control) 心跳通道**：每 2 秒向控制端发送一条加密指令帧，
并接收远端下发的指令 (如 `get_record` 拉取录制状态、`apk_sign` 检查 APK 签名、`vpn` 检查 VPN 状态)。
该通道与视频业务**完全无关**，属于行为监控/远程控制设施。

## 传输载体

| 项 | 值 |
|---|---|
| native 库 | `libcore.so` (6.8MB, 内含完整 OpenSSL + protobuf) |
| FFI 导出 | `init @0x2fdc24` (116B), `call @0x307a38` (**32KB 巨型分发器**) |
| 调用方 (Dart) | `FFIUtils._rawCall @0x6eeca8` → `__call @0x6eed7c` |
| 周期 | 每 2 秒 |
| 帧方向 | 上行 b64 密文 (~556 字符), 下行 b64 密文 |

## 加密算法

```
算法:    AES-128-CBC
填充:    PKCS7
key:     "qPwClBj7j7ZQraSm"  (16 字节 ASCII, hex 715077436c426a376a375a517261536d)
iv:      "p3JdVQl3q7WQJIgG"  (16 字节 ASCII)
编码:    base64 标准字母表
```

## 加密在 Dart 层完成

关键证据链：`__call @0x6eed7c` 的对象池引用含 `qPwClBj7j7ZQraSm`/`p3JdVQl3q7WQJIgG`
与 `Encrypter.encrypt` (encrypt 包) 调用——**明文 JSON 先在 Dart 层用 encrypt 包
(pointycastle) 加密，密文 b64 后才传给 native `call` 发送**。

native `call` 的第一个参数即 b64 密文字符串 (frida 实测每次心跳 x0 = 556 字符 b64)。

## 帧内容：诱饵 JSON

解密后的明文是约 400 字节的 JSON，结构：

```json
{
  "h1cV0LZzse1rAtb": "XwysVVGVy8xry...",   ← 随机 16 字符键 → 随机 16 字符值 (诱饵)
  "ImUaHCfYWIoe3dvq": "RnHftWFEvY5LDkta",  ← 诱饵 ...
  ...共 ~12 对诱饵...
  "action": "get_record",                  ← 真实指令
  "params": "{\"sta\":...}"                ← 真实参数
}
```

真实指令样本 (真机解密捕获)：

```json
{"list":[{"action":"apk_sign","params":"false"},{"action":"vpn","params":"true"}]}
```

含义：控制端询问"APK 签名校验结果"与"VPN 是否开启"——**反调试/反代理探测指令**。

## 识别诱饵与真实字段

- 诱饵键/值：恒定 **16 字符**，混合大小写+数字
- 真实键：固定小写单词 (`action`, `params`, `data`, `payload`, `status`…)

## Python 复现

```python
from gg_client import MON_KEY, MON_IV, channel_decrypt
# 解密一条真实心跳 (截取自 research/ffi_log.jsonl)
frame = "<556字符b64密文>"
print(channel_decrypt(frame, MON_KEY, MON_IV))
```

## 抓取方法

```bash
# frida hook (见 research/gg_ffi_hook.js)
objection/frida attach 后 hook libcore.so!call 的 onEnter(args[0].readCString())
```
