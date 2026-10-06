# 囧次元 API 端到端实测矩阵（35 接口）

> 生成时间：2026-10-04 · 驱动 `research/tmp_all_endpoints_par.py`（6 worker 并行）

> 数据源：`research/tmp_all_endpoints.json`（真实请求 + 离线解密，无需设备/App/frida）


判定：响应体解出 `{"code":20000,...}` + 真实 data = ✅ 通过；明文错误码 / 404 = 业务或路径问题。


| # | 方法 | 路径 | 名称 | HTTP | 结果 | 明文 | code | 备注 |
|---|---|---|---|---|---|---|---|---|
| 1 | GET | `/app/config` | 全局配置 | 200 | ✅ 通过 | 1913B | 20000 | 弹窗/开关/风控等全局配置 |
| 2 | POST | `/app/config/channel` | 频道配置 | 200 | ✅ 通过 | 106B | 20000 | POST 上报/拉取 |
| 3 | POST | `/app/config/video` | 视频页配置 | 200 | ✅ 通过 | 179B | 20000 | 播放器配置 |
| 4 | GET | `/app/video/detail?id=113354` | 视频详情 | 200 | ✅ 通过 | 1339B | 20000 | 单部番剧详情 |
| 5 | GET | `/app/channel?top-level=true` | 频道列表 | 200 | ✅ 通过 | 2653B | 20000 | 首页频道聚合 |
| 6 | GET | `/app/banners/2` | Banner(国漫) | 200 | ✅ 通过 | 3020B | 20000 | 频道 2 |
| 7 | GET | `/app/video/key?key=ai&limit=10&page=1` | 搜索联想 | 200 | ✅ 通过 | 911B | 20000 | 搜索框联想词 |
| 8 | POST | `/app/video/record` | 播放记录上报 | 200 | ✅ 通过 | 40B | 20000 | POST |
| 9 | POST | `/app/video/play-connect` | 播放连接 | 200 | ⚠ 业务码 | 39B | 40000 | POST；需真机加密上下文 → 40000 |
| 10 | GET | `/app/banners/0` | Banner(首页) | 200 | ✅ 通过 | 4134B | 20000 | 频道 0 |
| 11 | POST | `/app/video/device-base` | 设备信息上报 | 200 | ⚠ 业务码 | 39B | 40000 | POST；真机 body 仅 1 块(明文≤15B)，结构未还原 → 40000 |
| 12 | GET | `/app/vod_comment/gettop?vid=113354` | 热评置顶 | 200 | ✅ 通过 | 50B | 20000 |  |
| 13 | GET | `/app/video_update_list/2026-10-04` | 更新排期表 | 200 | ✅ 通过 | 2279B | 20000 | 按日期 |
| 14 | POST | `/app/users/clearimg` | 清图上报 | 200 | ✅ 通过 | 167B | 20000 | POST |
| 15 | GET | `/app/vod_comment/gethitstop?vid=113354` | 热评命中 | 200 | ✅ 通过 | 1346B | 20000 |  |
| 16 | POST | `/app/users/task` | 用户任务 | 200 | ✅ 通过 | 182B | 20000 | POST |
| 17 | POST | `/app/history` | 观看历史 | 200 | ⚠ 业务码 | 42B | 50008 | POST |
| 18 | GET | `/app/banners/1` | Banner(日漫) | 200 | ✅ 通过 | 5506B | 20000 | 频道 1 |
| 19 | POST | `/app/history/localcahce` | 本地缓存上报 | 200 | ✅ 通过 | 205B | 20000 | 官方拼写 localcahce |
| 20 | GET | `/app/task/sign_rule` | 签到规则 | 200 | ✅ 通过 | 466B | 20000 |  |
| 21 | POST | `/app/messagebox/give_me` | 收件箱 | 200 | ✅ 通过 | 126B | 20000 | POST |
| 22 | POST | `/app/messagebox/dynamic` | 动态消息 | 200 | ✅ 通过 | 184B | 20000 | POST |
| 23 | GET | `/app/v2/config/host` | Host 配置(v2) | 404 | ➖ 非加密 | - | - | 路径已失效 '404' |
| 24 | POST | `/app/upgrade` | 升级检查 | 400 | ➖ 非加密 | - | - | 特例: 大写 Authentication + 216B 裸二进制 '400 Bad Request' |
| 25 | GET | `/app/users/info` | 用户信息 | 200 | ⚠ 业务码 | 42B | 50008 | 游客态 |
| 26 | POST | `/app/task/task` | 任务列表 | 200 | ⚠ 业务码 | 42B | 50008 | POST |
| 27 | GET | `/app/playaddr/v4/client?vid=113354` | 播放地址 v4 | 404 | ➖ 非加密 | - | - | 路径已失效 '404' |
| 28 | POST | `/app/login/smscode` | 短信验证码 | 404 | ➖ 非加密 | - | - | 路径已失效 '404' |
| 29 | GET | `/app/vip_price/list` | VIP 价格 | 200 | ✅ 通过 | 285B | 20000 |  |
| 30 | GET | `/app/vod_comment/getlist?vid=113354&page=1` | 评论列表 | 200 | ✅ 通过 | 4488B | 20000 |  |
| 31 | GET | `/app/video/list?channel=1&sort=weight&limit=6&page=1` | 视频列表 | 200 | ✅ 通过 | 8615B | 20000 | 核心列表接口 |
| 32 | GET | `/app/video/search?key=ai&limit=25&page=1` | 搜索 | 200 | ✅ 通过 | 26295B | 20000 | 参数名 key(非 keyword) |
| 33 | GET | `/app/channel/` | 频道列表(301) | 301 | ➖ 非加密 | - | - | 301 跳转源, 无加密体 '<a href="/app/channel">Moved Permanently</a>.\n\n' |
| 34 | GET | `/app/danmu?vid=113354&play=mp4&part=%E7%AC%AC1%E9%9B%86&start_time_point=0&end_time_point=60000` | 弹幕拉取 | 200 | ✅ 通过 | 1468B | 20000 | **必带 part（集名）**；响应为明文 JSON 请求成功! |
| 35 | POST | `/app/video/play?id=113354&play=mp4&part=%E7%AC%AC1%E9%9B%86` | 播放凭证 | 200 | ✅ 通过 | 5154B | 20000 | **参数在 query**（?id=&play=&part=），body 用 `{}`；返回播放直链 |

## 汇总

| 项 | 值 |
|---|---|
| 接口总数 | 35 |
| 解出真实数据(20000) | 25 |
| 加密但业务码非 20000 | 5 |
| 非加密响应(301/特例/404) | 5 |
| 异常 | 0 |

> 服务端错误也返回 HTTP 200，业务码在 JSON body。`/app/upgrade` 为特例（非 P0.P1）；`/app/channel/` 为 301 跳转。
