# 视频列表 /app/video/list

## 请求

```
GET http://43.145.33.254:27990/app/video/list?channel=1&sort=weight&limit=6&page=1
```

| 参数 | 说明 | 实测值 |
|---|---|---|
| channel | 频道 ID (对应 /app/channel?top-level=true 返回) | 1=日漫, 2/3=国漫区, 26 等 |
| sort | 排序 | `weight` (默认推荐序) |
| limit | 每页数量 | 6 (app 首页每栏 6 个) |
| page | 页码 | 1 起 |

**无请求 body** (GET 纯 query)。请求头见 [总览](overview.md)。

## 响应 (预期结构)

响应加密 (会话 key)。解密后 JSON 对应 Dart 模型 **GVideoPage**:

```json
{
  "code": 200,
  "data": {
    "total": 1234,
    "list": [
      {
        "id": 113244,
        "name": "海贼王",
        "score": "10.0",
        "year": "2014",
        "area": "日本",
        "type": "搞笑,经典,热血,战斗,冒险,励志",
        "update_cycle": "周日23:30",
        "episode_total": 1180,
        "cover": "<cdn url>",
        "weight": 100
      }
    ]
  },
  "message": ""
}
```

> 字段名以解密响应实测为准 (GVideoPage/GVideo 模型, blutter asm `asm/guoguo/api_utils/`)。
> 首页 UI 实拍确认的数据: 海贼王(1180|周日23:30, 10.0分)、无职转生III(14全, 10.0)、
> 转生贵族(1|周日23:00更)、二十世纪电气目录(13全, 5.5)、Re:ゼロ 4th、100人の彼女。

## 逻辑链路

```
App 首页/频道页
  → GET /app/channel?top-level=true        拿频道列表
  → GET /app/video/list?channel=N&sort=weight&limit=6&page=P
  → 响应 (会话 key 加密) → apiDecrypt → GVideoPage
  → 首页"推荐·日漫"等分栏渲染 (每栏 limit=6, 查看更多→翻页)
```

## 复现状态

| 方式 | 结果 |
|---|---|
| 离线重放 (旧 token) | ✗ 403501/403502 (token 绑定 ts/nonce) |
| 真机 hook 捕获响应密文 | ✅ 已捕获 (research/key_log.jsonl, /app/config/video 与列表同族) |
| 完整解密 | 需会话 key (见 [HTTP body](../crypto/http-body.md) 遗留项) |
