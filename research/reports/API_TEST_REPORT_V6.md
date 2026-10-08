# 囧次元 (com.tudou.tool) 接口测试报告 V6

日期: 2026-09-29 ｜ 环境: LDPlayer 14 / emulator-5554 / Android 14 (API 34, x86_64 + houdini)
工作区: `out/v6/` ｜ 前序: out/API_MATRIX_V5.md, out/decrypt_v5/, out/v5/

---

## 1. 环境健康检查（P0, 6 项）

| # | 检查项 | 结果 |
|---|---|---|
| 1 | `adb devices` | ✅ emulator-5554 device |
| 2 | `su -c id` | ✅ uid=0(root) context=u:r:magisk:s0 |
| 3 | frida-server | ✅ root 运行, 127.0.0.1:27042 |
| 4 | `adb reverse --list` | ✅ tcp:27990 tcp:27990 |
| 5 | app 进程 | ✅ com.tudou.tool（进程名 囧次元） |
| 6 | chan2_signaling 自检 | ✅ 全部断言通过, exit=0 |

异常处理记录: V6 开场时 PC 侧 mitm 代理已死（27990 无监听、无 python 进程），
以受管后台任务重启 `out/v5/mitm_proxy.py`；设备侧 iptables REDIRECT 与 adb reverse 原本在位，未重配。
P1 复跑中 frida-server 一次进入坏态（可 attach 但 create_script 超时），kill -9 重启后恢复。

## 2. 接口测试矩阵（A5）

自动生成: `out/v6/replay/runner_matrix.md` / `runner_matrix.json`（脚本 `out/v6/api_test_runner.py`，
流程: 读 proxy_capture → 逐端点精确重放 → 判定 → 出报告）。

本轮累计 28 个端点具备「构造 → 发送 → 响应 → 判定」记录（超过 A5 要求的 12 个）:

| 端点 | 方法 | 构造 | 发送 | 响应 | 判定 |
|---|---|---|---|---|---|
| /app/channel/ | GET | app 实抓+精确重放 | ✅ | 200 P0.P1 | ACCEPTED（重放窗口内） |
| /app/channel | GET | 同上 | ✅ | 200 P0.P1 | ACCEPTED |
| /app/video/list | GET | 同上 | ✅ | 200 P0.P1 | ACCEPTED; 明文 total=2142 |
| /app/banners/0 | GET | 同上 | ✅ | 200 P0.P1 | ACCEPTED |
| /app/banners/1, /2 | GET | 同上 | ✅ | 403502 | EXPIRED（超窗） |
| /app/config | GET | 同上 | ✅ | 200 P0.P1 | ACCEPTED |
| /app/config/channel | POST | app 实抓 | ✅ | 200 P0.P1 | ACCEPTED |
| /app/config/video | POST | app 实抓 | ✅ | 200 P0.P1 | ACCEPTED |
| /app/history | POST | app 实抓 | ✅ | 200 P0.P1 | ACCEPTED（本轮新发现端点） |
| /app/history/localcahce | POST | app 实抓 | ✅ | 200 | OK |
| /app/users/clearimg | POST | app 实抓 | ✅ | 200 | OK |
| /app/users/task | POST | app 实抓 | ✅ | 200 | OK |
| /app/video/device-base | POST | app 实抓 | ✅ | 200 | OK |
| /app/video/record | POST | app 实抓 | ✅ | 200 | OK |
| /app/video/play-connect | POST | app 实抓 | ✅ | 200 | OK |
| /app/video/play | POST | app 实抓 | ✅ | 200 P0.P1 | OK（播放凭证链路完整） |
| /app/messagebox/give_me | POST | app 实抓 | ✅ | 200 | OK |
| /app/messagebox/dynamic | POST | app 实抓 | ✅ | 200 | OK |
| /app/video/detail | GET | app 实抓+重放 | ✅ | 403502 | EXPIRED（明文已内存提取） |
| /app/task/sign_rule | GET | app 实抓 | ✅ | 403502 | EXPIRED |
| /app/video/search | GET | app 实抓 | ✅ | 403502 | EXPIRED（UI 实测 3 结果） |
| /app/video_update_list/2026-09-29 | GET | app 实抓 | ✅ | 403502 | EXPIRED（新发现: 排期表） |
| /app/vod_comment/gettop | GET | app 实抓 | ✅ | 403502 | EXPIRED（新发现） |
| /app/vod_comment/gethitstop | GET | app 实抓 | ✅ | 403502 | EXPIRED（新发现） |
| /app/vod_comment/getlist | GET | app 实抓 | ✅ | 403502 | EXPIRED（新发现, UI 评论一致） |
| /app/danmu?vid=1239&play=mp4&part=第1集&start_t=… | GET | app 实抓 | ✅ | code 20000 | auth 被接受, 业务参数拒（start_t 语义未明） |
| /app/upgrade | GET | app 实抓 | ✅ | 明文 | 特例(大写 Authentication) 与 V5 一致 |

注: POST 精确重放需原 body（proxy_bodies.jsonl 存 hex），runner v1 对 POST 仅重放请求头；
带 body 的 POST 精确重放列为后续增强，见 §6。

## 3. authentication 复用边界（A6, E1–E6 全部完成）

原始证据: `out/v6/replay/e5_battery.json`, `window_test.json`, `e1_e3_replay.json`。

| 实验 | 构造 | 实测 | 结论 |
|---|---|---|---|
| E1 | 数小时旧 auth 原样重放 | 403502 时间异常 | ts 过期 |
| E2 | 同 auth + 新 ts/nonce | 403501 | auth 绑定签发时 ts/nonce |
| E3 | 同 auth + 新 ts/nonce + 换端点 | 403501 | 且绑定端点 |
| **E5** | **新鲜 auth 原样精确重放（+0.2s）** | **200 + P0.P1 密文 9945B** | **短窗口重放可行 ✅** |
| E4a | 精确重放 ×3 | 全部 200 P0.P1 | 无 nonce 缓存 / 无次数限制 |
| E4b | 同 auth + 新 ts/nonce ×3 | 全部 403501 | 与 E2 一致 |
| E6 | 新鲜 auth + page=1→2 | 403501 | auth 绑定完整 query 串 |
| E5b/E5c | 精确重放 +12s / +35s | 200 P0.P1 | 窗口 ≥35s |
| 窗口上界 | +120s / +300s | 200 P0.P1 / 403502 | **窗口 ∈ (120s, 300s)** |

**决定性结论**: 「短窗口精确重放」可行 —— 代理侧捕获请求后原样重放（不改 ts/nonce/auth/path/query 任一字节）
在签发后 120s~300s 内必然得到有效响应；任何修改 → 403501；过期 → 403502。
无重放缓存、无频次限制。接口重放式测试以「app 自发请求 + 旁路截获 + 窗口内精确重放复测」为可用模式；
**离线伪造 authentication 不存在**（V5 E1-E3 + 本轮 E2/E4b/E6 再次证实）。

## 4. 明文提取记录（P4）

工具: `out/decrypt_v5/mem_plaintext.py`（内存明文）, `out/v6/tools/{parse_mem_json,salvage_items,best_copy,watch_play}.py`

| 端点 | 触发方式 | marker | 产物 | 判定 |
|---|---|---|---|---|
| /app/video/list | 频道 tab 切换后 1s 内扫描 | `"items":[{"id":` | `out/v6/decrypted/video_list.json` (total=2142, 9 items×18字段), `video_list_runlist.json` | 字段完整; UI 海报/更新时间一致 ✅ |
| /app/video/detail | 进详情页后立即扫描 | `"ename":"` | `video_detail.json` (id=113490 黑暗机器, 18字段) | ✅ |
| /app/video/play | **watcher 常驻扫描**（见下） | `"url":"http` | `watch_1790650763.json` (url + x-time/x-sign1/x-sign2/x-form) | ✅ 播放凭证明文 |
| /app/vod_comment/getlist | 评论 tab 热扫描 | `"content":"` | `vod_comment.json`(抢救 2 条) + mem_comment.json | 字段 id/pid/oid/vid/vname/content ✅ |
| /app/video/search | 热搜词点击 | — | 流量已抓(密文), 明文未命中 | 部分 |
| /app/danmu | **弹幕开关 关→开 触发** | — | 流量已抓(密文×2), 明文未命中 | 部分 |

**A7 达成**: 视频详情 + 频道列表(视频列表) + 评论 3 个接口取得字段级真实数据；
弹幕为「密文已留档、明文未提取」的部分达成（见 §6）。

关键工程结论: 明文 JSON 在内存仅存活 ~15s 即被 GC。单次扫描（attach~15s）经常赶不上。
解决方案 = `out/v6/tools/watch_play.py` 常驻 watcher（attach 一次 + rpc 循环扫描 0.6s/轮）,
先挂 watcher 再触发请求 —— 该模式对播放地址、弹幕等短生命周期明文通用。
内存脏字节会导致 json.loads 失败, 配套 `parse_mem_json.py`(控制字符+非法转义清洗) 与
`best_copy.py`(多拷贝择优) 解决。

## 5. 播放链路全链证据 + 播放崩溃根因分析与修复

### 5.1 链路证据（A4 ✅）
1. `POST /app/video/play?id=1239&play=mp4&part=第1集` → 200 P0.P1（app 侧解密）
2. 明文凭证（内存提取 `watch_1790650763.json`）: `{"url":"http://yh.jx.xajtl.com/vo1v03.php?url=…&t=1790650763","header":{x-time,x-sign1,x-sign2,x-form}}`
3. app 携带该 url+header 取回 playAddr（douyinvod 直链, 令牌一次性）—— 播放器探针 JSON 亦被 watcher 捕获（`watch_1790653940.json` 等含直链与耗时指标）
4. **直链 Range 验证**: `GET (Range: bytes=0-63)` → **HTTP 206, video/mp4, 首 16 字节 `00000020 66747970 69736f6d` = `ftypisom`**（`out/v6/replay/range_0-63.bin`）

### 5.2 播放必崩的根因（用户问题）与修复 ✅

**现象**: 任何视频点播放后 1~60s 内 app 必死；与本轮全部 8 次播放尝试一一对应（dumpsys dropbox 8× data_app_native_crash）。

**崩溃签名**（/data/tombstones/tombstone_17/18, 8 次完全一致）:
```
tid: <N> name: ApsaraPlayerSer  >>> com.tudou.tool <<<
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1378
#01 android::GenerateCodecId()::$_0::operator()()   libstagefright.so
#03 android::MediaCodec::MediaCodec(...)            libstagefright.so
#05 android::MediaCodec::CreateByComponentName(...)  libstagefright.so
#07 android::JMediaCodec::JMediaCodec(...)           libmedia_jni.so
```

**因果链**（三层, 层层实证）:
1. **ROM 层**: `/vendor/etc/media_codecs.xml` 被模拟器厂商注入两个幽灵硬解条目
   `OMX.qcom.video.decoder.avc/.hevc`（XML 内注释原文 `add fake IjkMediaPlayer` —— 假条目）,
   但 x86_64 镜像不存在对应 OMX 实现。
2. **App 层**: 播放器为阿里云 ApsaraPlayer（线程名 ApsaraPlayerSer）, 硬解优先。
   源流为 H265（douyinvod）→ MediaCodec 按名创建解码器命中幽灵条目 → 无实现 → 空指针 → SIGSEGV。
   崩溃与 frida/代理/抓包链路无关（无任何插桩时同样复现）。
3. **系统层佐证**: 服务异常期间 `service list` 无 media.codec/C2 注册项、
   `dumpsys` 显示 `Decoder infos` 为空 —— 且对 HAL 服务 `kill -9` 后 init 拉起但不重新注册
   （修复 XML 后仅杀服务仍崩, tombstone_22 实证）, 必须整机重启才重建注册表。

**修复步骤**（已执行, 全部留档 `out/v6/rom_fix/`）:
1. `cp /vendor/etc/media_codecs.xml` 备份 → 删除两个 `<MediaCodec name="OMX.qcom…">` 块（4→2 条目）→ 回写并恢复 SELinux context `u:object_r:vendor_configs_file:s0`；
2. **完整重启模拟器**（仅 kill 服务无效）；
3. 重启后验证: `OMXStore makeComponentInstance(OMX.google.hevc.decoder)` 成功（LDDec 软解组件）；
4. 复测: 点播放 → **视频正常播放、app 存活、无新 tombstone**（out/v6/shots/p4_after_fix.png）。

**连带收益**: 播放器能初始化后, 弹幕开关（关→开）即触发此前一直抓不到的
`GET /app/danmu?vid=&play=mp4&part=&start_t=` —— 弹幕端点由「阻塞点」转为「已实测」。

## 6. 失败用例与阻塞点

| 项 | 状态 | 说明 |
|---|---|---|
| /app/danmu 明文提取 | 未达成 | 端点+触发条件+密文已留档; 响应明文存活<15s 且 GDanmakuItem 字段名未在 AOT 池明文出现, watcher 标记未命中。下一步: 以『配置下发 JSON 命中( min_danmu_length 等)』同区域扩大上下文窗口再扫 |
| POST 精确重放（带 body） | 未执行 | runner v1 只重放请求头; 需从 proxy_bodies.jsonl 解 hex 回填 body 后重放 |
| 登录门槛端点 | 未触发 | /app/users/info, /app/vip_price/*, /app/task/task, /app/video/key, /app/playaddr/v4/client, /app/users/login|smscode —— 均需登录或特定入口（我的页各入口点击无跳转, 游客态） |
| 弹幕 replay 20000 | 待解释 | auth 层接受但业务码 20000, 疑似 start_t 增量参数校验; 需用完整原始 query 重试 |
| 播放页 H265 之外的线路 | 未测试 | 修复后未遍历各线路/清晰度组合 |

## 7. 审计条目索引（out/VERIFICATION.txt）

[F28] E4/E5/E6 电池与短窗口结论 ｜ [F29] 窗口上界 (120s,300s) ｜ [F30] P2 补覆盖 6+ 新端点
[F31] run_list 补丁与 A3 ｜ [F32] A4 直链 Range 验证 ｜ [F33] 播放崩溃根因与 ROM 修复
[F34] api_test_runner 28 端点矩阵 ｜ [F35] E1-E3 V6 复现补档 ｜ [F36] 弹幕触发与明文边界

## 8. 验收对照

| 编号 | 验收项 | 结果 |
|---|---|---|
| A1 | 环境健康 6 项 | ✅ §1 |
| A2 | 三通道脚本 PASS | ✅ §7 F27/F28 前置 |
| A3 | run_list total+items | ✅ total=2142, items 6 条表格输出 + JSON 落盘 |
| A4 | 播放直链可下载 | ✅ 206 + ftypisom |
| A5 | ≥12 端点四步记录 | ✅ 28 端点 |
| A6 | E4/E5/E6 + 短窗口结论 | ✅ 重放可行, 窗口 (120s,300s) |
| A7 | ≥3 接口真实数据 | ✅ 详情/列表/评论（弹幕密文已抓, 明文部分达成） |
| A8 | 报告产出 | ✅ 本文档 |
