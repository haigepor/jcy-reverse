# 播放链接 /app/video/play 与播放链路

## 请求

```
POST http://43.145.33.254:27990/app/video/play?id=113244&play=mp4
```

| 参数 | 说明 |
|---|---|
| id | 视频 ID (列表/详情返回) |
| play | 播放格式偏好: `mp4` 等 (弹幕接口同参数形态) |

body: `"<P0_b64>.<P1_b64>"` (会话 key 加密, 见 [HTTP body](../crypto/http-body.md))

## 播放完整链路 (静态反汇编 + 抓包)

```
详情页点击集数
  → POST /app/video/play?id=<vid>&play=<fmt>     (播放凭证/地址)
  → 响应解密 (会话 key)
  → (必要时) GET /app/video/key                  播放密钥交换 (RSA/AES)
  → POST/GET /app/playaddr/v4/client             播放地址解析主接口
        返回 GUrlParsed { name, raw_play_url, m3u8FileDomain }
  → 拼接 m3u8 地址: <m3u8FileDomain>/<path>/hls.m3u8
  → HLS 播放:
      #EXTM3U / #EXT-X-STREAM-INF (多码率)
      #EXT-X-KEY: METHOD=AES-128,URI="keyuri",IV=<hex>   ← 片段级加密
      片段 AES-128-CBC 解密后由播放器渲染
  → 同时: POST /app/video/play-connect            播放心跳 (间隔上报)
           POST /app/video/record                 观看记录上报
```

## 播放数据源: WebRTC 代理 (P2P)

App 内置 **GWebRTCProxyServer** (`g_webrtc_proxy_server.dart`)：

```
播放起播时:
  FFIUtils init → libloader so 加载
  PeerManager.initSignalServer / signalUrl
  每次调用信令: libloader!call → {"action":"get_app_info"} → payload.address (本地回调地址)
  md5Convert/getMd5 (SliceData)                 # P2P 分片校验
  addHttpCount/addShareCount                    # P2P 统计
```

- 弹幕/部分流可能经由 **本地 HTTP 代理** (`127.0.0.1:<port>`) 中转
- P2P 通道失败时回落直连 CDN (m3u8FileDomain)

## 片段解密 (m3u8 #EXT-X-KEY)

若 m3u8 含 `#EXT-X-KEY:METHOD=AES-128`：

```python
# hls.js 自动处理 (浏览器 MSE); 命令行:
from Crypto.Cipher import AES
key = <URI 下载>            # 16B
iv  = <IV hex> or segment_sequence
seg = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_ts_segment)
```

## 播放器

- 主播放器: 阿里播放器 (`libsaasCorePlayer.so`) + `libalivcffmpeg.so`
- 备用: flutter_webrtc (P2P 场景)

## 真机捕获

- `/app/video/play` 响应密文已捕获 (out/key_log.jsonl, 409 字符 b64 ≈ 306B)
- 解密需会话 key (运行时), 明文含 raw_play_url 或 m3u8 直链
