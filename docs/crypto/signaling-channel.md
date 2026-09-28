# 信令通道 (libloader.so, kFGT) — 本地 native↔Dart IPC

## 语义修正 (重要)

早期假设该通道为"远程 WebRTC 信令服务器通信"。**真机 hook 实证推翻**：

`libloader.so!call` 收到的请求解密后为 416B 诱饵 JSON，返回的
`{"action":"get_app_info","code":200,"payload":{"address":"0x723e214740"}}`
中的 `address` 是 **0x723... 形态的本进程内存地址** (Dart 对象指针)，
且每次进程重启后地址基址随之变化——**通信对端是本进程内的 native 代码，不是远程服务器**。

真实语义：`libloader.so` 的 native 逻辑需要 app 信息 (appId/version/deviceId/host 配置) 时，
通过此 **kFGT 加密的本地 FFI 回调通道**向 Dart 侧查询
(`FFIUtils.dartCallback @0x715844` / `#ffiCallback0` / `getAppInfo / getAppId / getDeviceId /
getHostConfig / getCoreVersion` 系列方法即回调处理端)。

## 通道参数 (不变)

| 项 | 值 |
|---|---|
| native 库 | `libloader.so` |
| FFI 导出 | `call @0x2A3D2C` (5552B), `reload @0x2A49A4` |
| Dart 调用方 | `FFIUtils._loaderCall @0x72cf20` |
| 算法 | AES-128-CBC + PKCS7 |
| key | `kFGTbLlOzFHQCIKp` |
| iv | `F3q22XoM8l6T2Ydc` |
| 编码 | base64 |

key 出处 (blutter 对象池):

```
[pp+0x7000] String: "kFGTbLlOzFHQCIKp"
[pp+0x7008] String: "F3q22XoM8l6T2Ydc"
[pp+0x7010] Obj!AESMode@b6c821 : { off_10: "cbc" }
[pp+0x7018] TypeArguments: <NativeFunction<(dynamic this, Pointer<Utf8>) => Pointer<Utf8>>>
```

## 实测样例

### 上行 (Dart → native，解密后)

416 字节诱饵 JSON (节选):

```json
{"oXaRHrnC2N8oPs60":"9LxGU1p5fnLtHGwV","Sbl0BAoxZ7Sg7wm1":"dgOA3DyDBL8rwBGo",
 "...":"...", "action":"get_app_info", ...}
```

原始密文 (b64, 556 字符):

```
kpxwtis7g1YyGQlWiFw+I4gDz1c88XWC7suwdCpsLmTIdUXZ/JbIYk/Vls7PSAQnj726+ftx3Ngw0E0HKy0T8aNBM2pcweG9x...
```

### 下行 (native → Dart，解密后)

原始密文 (b64, 96 字符):

```
VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY=
```

解密:

```json
{"action":"get_app_info","code":200,"payload":{"address":"723e214740"}}
```

多次捕获响应前 43 字符恒定 (`VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjn`)——
CBC 固定 iv 下相同明文前缀的确定性特征。

## Python 复现

```python
from gg_client import SIG_KEY, SIG_IV, signaling_decrypt_response

pt = signaling_decrypt_response(
    "VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L"
    "3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY=")
# b'{"action":"get_app_info","code":200,"payload":{"address":"723e214740"}}'
```

## 与监控通道的区别

| | 监控通道 | 信令通道 |
|---|---|---|
| 对端 | 远程 C2 (有网络流量) | **本进程 native** (无网络) |
| 库 | libcore.so | libloader.so |
| 用途 | 心跳/指令 (get_record/apk_sign/vpn) | native 查询 app 信息/配置 |
| key | qPwC | kFGT |

## 抓取方法

frida hook `libloader.so!call` onEnter/onLeave，b64 按字母表截断后解密。
