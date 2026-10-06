# out/decrypt_v5 —— 囧次元三通道解密交付

目标：`com.tudou.tool`（囧次元，Flutter/Dart 3.6.0，包名 `guoguo`）的三条加密通道各产出一个
**可独立运行**的脚本，并附**真实样本断言**。

所有脚本均为纯本地运行；除 `mem_plaintext.py` / `run_list.py` / `run_play.py` 需要
frida + 运行中的 app 外，其余仅依赖 `pycryptodome`。

```
out/decrypt_v5/
├── common.py              公共原语 (AES-CBC/PKCS7、b64、密钥常量)
├── chan1_monitor.py       通道1 监控 (libcore.so)   —— 密钥双证 + 算法往返 + 判别性
├── chan2_signaling.py     通道2 信令 (libloader.so) —— ★真实密文断言
├── chan3_http.py          通道3 HTTP body 结构     —— 17 端点 / 41 真实响应结构断言
├── mem_plaintext.py       内存明文提取器 (frida)   —— 通道3 的可用解密路径
├── run_list.py            端到端: 视频列表
├── run_play.py            端到端: 播放直链 (m3u8/mp4)
└── samples/
    ├── http_responses.json      17 个端点的真实 P0/P1 密文
    ├── play_url.json            真实播放地址 JSON (含鉴权头)
    └── playaddr_response.json   真实 playAddr 响应
```

## 运行

```bash
cd out/decrypt_v5
python chan1_monitor.py
python chan2_signaling.py
python chan3_http.py
python chan3_http.py --list

# 需 frida + app 在运行 (frida-server on 127.0.0.1:27042 / adb 设备)
python run_list.py --limit 20
python run_list.py --json list.json
python run_play.py --extract --verify
python mem_plaintext.py --marker '"items":[{"id":' --json
```

## 三通道状态

| | 通道1 监控 | 通道2 信令 | 通道3 HTTP API |
|---|---|---|---|
| 载体 | libcore.so `call` | libloader.so `call` | dio → `http://43.145.33.254:27990` |
| 算法 | AES-128-CBC/PKCS7 | AES-128-CBC/PKCS7 | 每请求随机会话 key + RSA-2048 包裹 |
| key | `qPwClBj7j7ZQraSm` | `kFGTbLlOzFHQCIKp` | 随机 (运行时) |
| iv | `p3JdVQl3q7WQJIgG` | `F3q22XoM8l6T2Ydc` | 随机 (运行时) |
| 帧 | b64(诱饵 JSON) | b64(诱饵 JSON) | `"<P0_b64>.<P1_b64>"` |
| 破解 | 密钥+算法已证 | ✅ 真实密文验证 | 结构 100% 明; 明文走内存路径 |
| 脚本 | `chan1_monitor.py` | `chan2_signaling.py` | `chan3_http.py` + `mem_plaintext.py` |

## 通道2 的真实样本（★）

```
密文 (b64, 108 字符) :
VuVH8nti+EBD+8IsQy5T0VSfsJhWfysCQf+hyZ2ssjnfhfVK8BHxy4JnZgs5oU9L3MKaF8hUWpsiJ19C+DOZrwc8DiKYVehRQBgJpdSP5zY=
明文 :
{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}
```

来源：真机 frida hook `libloader.so!call` 捕获（`docs/crypto/signaling-channel.md`）。
密文 80 字节 = 5 个 AES 块，PKCS7 padding = `0x09 × 9`。

## 通道3 的明文获取路径

请求/响应体为 `<P0>.<P1>`：`P0` = RSA-2048(会话 key‖iv) 恒 256 字节且每请求唯一，
`P1` = AES-CBC(业务 JSON)。**P0 由服务端用 app 的 RSA 公钥包裹**，app 侧私钥为运行时生成、
未内嵌，且 ARM64 库在 houdini 转译层下对 `Process.enumerateModules()` 不可见，无法 hook
`apiDecrypt`。已实测的负结果：
- 用两条通道密钥解 `P0` / `authentication` 密文 → 全部失败；
- 内存滑动窗口暴力搜 AES 会话 key → 吞吐仅 ~110 KB/s（全量 1.4 GB 需数小时），锚点邻域 16 MB 内 0 命中。

**可用替代路径**：`mem_plaintext.py` 从进程内存取回 `apiDecrypt` 产出的明文 JSON（已验证）。

## 端到端成果

- `run_list.py` → 真实列表：`total=2142`，含 `id/cid/name/year/continu` 等字段。
- `run_play.py` → 真实播放直链：

```
步骤2  {"url":"http://yh.jx.xajtl.com/vo1v03.php?url=...&t=1790620905",
        "header":{"x-time":"1790620905","x-sign1":"63a7e5...","x-sign2":"f079c9...","x-form":"Android"}}
步骤3  带上述 header 请求 url → {"data":{"playAddr":[
         {"title":"高清","desc":"1080P","vcodec":"H265",
          "addr":"/458572a2161f4e099efd354b10212b47/.../ocIAXTDVEFTqERB08SEN92RLAf91fZ7TpNpzgC/",
          "m3u8FileDomain":"https://v9.douyinvod.com","format":"MP4"}, ...]}}
步骤4  最终直链 = m3u8FileDomain + addr
       实测 HTTP 200 / Content-Type: video/mp4 / Content-Length: 146,763,786
       响应体首 16 字节 0000001c6674797069736f6d = "ftypisom" (合法 MP4)
```

注意：`url=` 中的令牌是**一次性**的，重放同一 url 会被服务端拒绝（返回 144 字节密文）。
故 `--extract` 必须"新提取 → 立即解析"。

## 诚实标注（未达成项）

- 通道1 **真实密文未留档**：`out/ffi_log.jsonl` / `manual_log2.jsonl` / `hex_log.jsonl` 在磁盘上
  均不存在；本机重采受 houdini 限制失败。`chan1_monitor.py` 以密钥双证 + 算法往返 + 与通道2
  的判别性对比作为替代断言。
- 通道3 的**离线会话密钥恢复未达成**（见上"负结果"）。
- 未产出 `out/ggcap_v5.pcap`；抓包以 `out/v5/proxy_capture.jsonl`（146 条）+ `proxy_bodies.jsonl` 形式留档。
