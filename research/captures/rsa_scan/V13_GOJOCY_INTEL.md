# go-jocy 开源后端情报（2026-10-03 网络侦察）

来源：github.com/nuanxinqing123/go-jocy（已归档，囧次元网页版后端，Go+Gin+gopher-lua）
克隆于 research/tmp_go_jocy。fork 6 个均无续作；作者无新协议仓库。

## 旧版协议（App 1.5.7.0 时代，auth 格式版本 2.4.6.5）
- 请求：**明文 JSON/明文 query**，无 P0.P1 体加密（体加密层是 1.5.8.0 新增）
- authentication = AES-CBC-StdB64("2.4.6.5-{ts毫秒}-Android-1.5.7.0-{fp16hex}", key=ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv, iv=WonrnVkxeIxDcFbv)
  注意：S 串无 "-default" 后缀、fp 只有 16 hex；对比我们的 3.0.0.8 格式（78B、双重 custom-b64、E 管线）
- 头清单：User-Agent: Dart/2.17 (dart:io)；Accept-Encoding: gzip；x-version: 2020-09-17；
  appid: 4150439554430529；ts: 毫秒；authentication；tcs: 2；x-token（登录后）
- API 路径样例：/app/users/captcha 等（BaseURL 来自配置 yaml，仓库无默认值）

## 播放链完整参数（与我们 lua_play.txt 捕获吻合）
- 签名：x-sign1 = md5(appVersion + "v50gjcy" + ts)；x-sign2 = md5(source + "v50gjcy" + ts)（hex 小写）
- x-time = ts 毫秒；x-form = "Android"
- parser 模板（域名轮换）："http://yh.jx.xajtl.com/vo1v03.php?url="、"http://yhhy.xj.zshtys888.com/vo1v03.php?url="、
  "https://jocy-jx.6b7.xyz/vo1v03.php?url="；请求 = parser + source + "&t=" + ts
- parser 响应：明文 JSON（code=200, obj.data→playAddr）或 **AES128-CBC 加密**
  （test/req_play_addr.lua 样本 key/iv: wcyjmnnnawozmydn / wcivwyjmlnzbhlmq；
  生产 key/iv 从 lua 脚本内 `aes_key="..."/aes_iv="..."` 正则提取，或配置 play_aes_key/play_aes_iv）
- 返回 obj.type ∈ {multi, mp4, m3u8, hls, flv}

## 侦察结论
- 新协议（auth 3.0.0.8 + P0.P1 体加密 + E 管线）无任何公开实现/破解文章
- 旧协议兼容性未验证：用 1.5.7.0 头 + 明文参数打现行 API 是一个低成本高回报实验
