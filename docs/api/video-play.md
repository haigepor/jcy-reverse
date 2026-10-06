# 播放链接 /app/video/play 与播放链路

## 现役全离线播放链（2026-10-05 实测收官，无需设备/frida）

完整链路 **list → detail → play → 解析器 → 直链** 全部离线打通并实测可播：

```
1) GET  /app/video/list?channel=1&sort=weight&limit=6&page=1
      → data.items[] 选定 id（实测 113459「来自远方」）
2) GET  /app/video/detail?id=113459
      → data.parts[] = [{play:"mp4", play_zh:"线路3", part:["第1集"], single_clarity_display:0}]
      → data.source  = "cms10"
3) POST /app/video/play?id=113459&play=mp4&part=第1集      （query 传参，body = {} 的伪造信封）
      → data[0].url   = source 串: "6157c9c16182997848431|f1b1811956986|0101c304d5f96|9214e904e808e2"
      → data[0].parse = 服务器下发的现役 Lua 解析脚本（盐/aes_key/aes_iv/解析器列表/头规则全在里面）
4) GET  http://yh.jx.xajtl.com/vo1v03.php?url=<source>&t=<ts>
      头: x-time=<ts毫秒>  x-form="Android"
          x-sign1 = md5(app_version + 盐 + ts) = md5("1.5.8.0" + "pzizhsqjjt" + ts)
          x-sign2 = md5(source + 盐 + ts)
      → 明文 JSON: {code:200, data:{playAddr:[...]}}（密文时 AES128-CBC 解，见下）
5) 直链 = playAddr[i].m3u8FileDomain + playAddr[i].addr
      头: User-Agent = ""（空），Referer = 直链自身（toutiaovod.com 的 Referer 置空，规则见下）
```

### 多清晰度（1080p/4K）= playAddr 数组

playAddr 每项 `{title, desc, vcodec, addr, m3u8FileDomain, format}`；
Lua 拼装 `name = desc + " " + title`，返回 `type="multi"` 的 url 数组，App 侧按 name 出清晰度选择菜单。

实测样例（id=113459 第1集，2026-10-05）：

| # | name | vcodec/format | CDN | 实测 |
|---|---|---|---|---|
| 0 | 1080P 高清 | H265 / MP4 | `https://1251413404.vod2.myqcloud.com` | HTTP 206, video/mp4, ftyp isom ✓, 217,168,708 B, 0.3s |
| 1 | 4K 超清 | H265 / MP4 | `https://v3.toutiaovod.com` | HTTP 206, video/mp4, ftyp isom ✓, 459,730,607 B, 0.5s |

**切换清晰度 = 换 playAddr 数组索引**（两条直链相互独立，均为完整视频文件）。
同一 playAddr 直链间隔 1 分钟两次 Range 实测均 206 —— 直链非一次性。

### 现役 Lua 关键参数（来自 data[0].parse，勿再用旧情报）

| 项 | 值 |
|---|---|
| 签名盐 | `"pzizhsqjjt"`（**已更换**，go-jocy 旧情报的 `v50gjcy` 已失效） |
| app_version | `"1.5.8.0"`（device_info["app_version"]，auth S 串同源） |
| platform | `"Android"`（device_info["platform"]） |
| aes_key | `"rdcibneoapyspqlt"`（解析器响应 AES128-CBC 兜底解密） |
| aes_iv | `"fyoofrebaxjwioxn"` |
| 解析器 | `["http://yh.jx.xajtl.com/vo1v03.php?url="]`（响应处理：先按明文 JSON，失败再 AES 解密） |

custom_head 直链请求头规则（Lua `custom_head()`）：`User-Agent` 置空；`Referer` = 直链自身，
域名特例：`aliyuncs.com→https://www.piccopilot.com`、`toutiaovod.com→(空)`、
`kwimgs.com→https://www.kuaishou.com`、`dcarvod.com→https://www.dongchedi.com`、
`douyinvod.com→https://www.douyin.com`。

### 复现与 Apipost 节点

- 驱动脚本：`research/tmp_w1_playchain.py`（链路 1-4）+ `research/tmp_w1_playtest.py`（直链 Range 校验）
- 结果留档：`research/tmp_w1_playchain_out.json`（含完整 Lua）、`research/tmp_w1_playtest_out.json`
- Apipost（project 6ef0f75d8470000 → 视频与播放）：
  - **播放凭证**（既有节点，V14 收官版）：预脚本取签+伪造信封，后脚本离线解密
  - **播放解析器**（2026-10-05 新增）：预脚本内联 md5（RFC1321，与 hashlib 交叉验证）现算
    x-time/x-sign1/x-sign2；url 填 `{{jcy_source}}` 或手填 source 串；后脚本校验 code=200 并打印各清晰度直链
  - 一键兜底：`GET http://127.0.0.1:8791/relay?path=/app/video/play&params={"id":"113459","play":"mp4","part":"第1集"}&method=POST`

---

# 以下为历史记录（早期轮次，结论以现役章节为准）

## 请求

```
POST http://43.145.33.254:27990/app/video/play?id=113244&play=mp4
```

| 参数 | 说明 |
|---|---|
| id | 视频 ID (列表/详情返回) |
| play | 播放格式偏好: `mp4` 等 (弹幕接口同参数形态) |

body: `"<P0_b64>.<P1_b64>"` (会话 key 加密, 见 [HTTP body](../crypto/http-body.md))

## 播放完整链路 (静态反汇编 + 抓包，旧版模型)

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

> 注：旧模型中的 /app/video/key 与 /app/playaddr/v4/client 在现役实测中未出现；
> 现役路径为 play 响应直接下发 source 串 + Lua 脚本，由客户端本地请求外链解析器。

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

## 真机捕获（frida 时代）

- `/app/video/play` 响应密文已捕获 (research/key_log.jsonl, 409 字符 b64 ≈ 306B)
- 解密需会话 key (运行时), 明文含 raw_play_url 或 m3u8 直链

---

## 第三阶段实测 (2026-09-29, frida 内存提取) —— 播放链路首次端到端打通

```
1) app: POST /app/video/play?id=<vid>&play=mp4&part=<集>   → 响应 <P0>.<P1> 密文
2) app 解密得到播放地址 JSON:
   {"url":"http://yh.jx.xajtl.com/vo1v03.php?url=<tok>|<tok>|<tok>|<tok>&t=<ts>",
    "header":{"x-time":"<ts>","x-sign1":"<md5>","x-sign2":"<md5>","x-form":"Android"}}
3) 带上述 header 请求 url → 200:
   {"code":200,"msg":"success","data":{"playAddr":[
     {"title":"高清","desc":"1080P","vcodec":"H265","format":"MP4",
      "addr":"/458572a2161f4e099efd354b10212b47/6abace64/video/tos/cn/tos-cn-v-e874c6/ocIAXTDVEFTqERB08SEN92RLAf91fZ7TpNpzgC/",
      "m3u8FileDomain":"https://v9.douyinvod.com"},
     {"title":"超清","desc":"4K","vcodec":"H265","format":"MP4", ...}]}}
4) 最终直链 = m3u8FileDomain + addr
   实测: HTTP 200 / Content-Type: video/mp4 / Content-Length: 146,763,786
        响应体首 16 字节 0000001c6674797069736f6d = "ftypisom" (合法 MP4)
```

**注意（当时观察）**：`url=` 中的令牌是**一次性**的 —— 首次请求返回明文 JSON，重放同一 url
会被服务端拒绝（返回 144 字节密文）。2026-10-05 复测中 fresh source 均成功、直链可重复 Range；
source 令牌的一次性窗口未再专门复测，使用时始终现取现用即可。

**复现脚本**：`research/deliverables/decrypt_v5/run_play.py`（`--extract` 从进程内存取步骤 2 的 JSON，
`--from-sample` 用留档样本走步骤 3+4，`--verify` 用 Range 请求校验直链）。
