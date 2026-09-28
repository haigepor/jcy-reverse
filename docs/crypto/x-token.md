# X-Token 认证机制

## 机制总结

App **没有本地登录态加密**。`authentication` 头 (俗称 X-Token) 是**服务器签发的不透明令牌**：

```
┌──────────┐  POST /app/video/device-base   ┌──────────┐
│  客户端   │ ─────────────────────────────→ │  服务器   │
│          │ ←── 响应头 new-token: <112B> ── │          │
│ 存入      │                                │ 签发 token│
│ UserToken │                                │ (绑定    │
│ (riverpod)│  之后每请求: authentication: <> │  ts/nonce)│
└──────────┘                                └──────────┘
```

- 客户端**不解析、不加密** token——收到什么回传什么
- TokenInterceptor.onResponse (@0xa3c4b8) 检查响应头 `new-token`，有则更新 `userTokenProvider`
- TokenInterceptor.onRequest (@0xa3bc20) 每请求把 token 放进 `authentication` 头

## Token 结构 (观察值, 服务器侧加密)

```
[0..14]  15 字节常量前缀: e8cb1f120ef5a42c59e22a4d00279e
[15]     1 字节代次 flag (9c..9f 区间, 低 2bit 随签发轮次变化)
[16..111] 96 字节密文 (6 个 AES 块; 服务器侧加密, 含绑定信息)
```

同一 token 内、不同请求间，第 1 个 AES 块恒定；不同 token 代次之间整体不同。

## 与 ts/nonce 的绑定 (重放实验)

用抓包样本重放 `GET /app/video/list` (服务器 43.145.33.254:27990 存活):

| 实验 | 结果 |
|---|---|
| 无 authentication 头 | `{"code":30000,"message":"解码异常:authentication is empty"}` |
| 旧 token + **旧 ts/nonce** (原样重放) | `{"code":403502,"message":"检测到设备时间异常，请调整到正确时间后重新打开 App尝试"}` |
| 旧 token + **新 ts/nonce** | `{"code":403501,"message":"校验客户端签名失败，请重启app尝试"}` |

**结论**: token 内含签发时的 ts/nonce (服务器解密校验)，**离开真机无法纯重放**；
离线自动化必须先复现 device-base 登录 (见 [http-body](http-body.md) 的公钥遗留项)。

## 抓取真机有效 token

```python
# hook TokenInterceptor.onRequest (@0x58507c dump offset), 从 RequestOptions.headers
# 或 HeadersInterceptor 参数中取 authentication 值 (b64 字符串)
# 配合相同 ts/nonce 在数秒内重放, 服务器时间校验 (允许秒级偏差) 可通过
```
