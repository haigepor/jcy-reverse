# 囧次元 接口响应速度优化·续轮2交接（接自 2026-10-07 会话，接 HANDOFF_PROMPT_V13）

## 项目链路（一分钟上下文）
- Web 前端 src/web（React+Vite, :5174）→ FastAPI 桥 src/web/server/main.py（:8792，
  由 node scripts/web-server.mjs 监督、python 死了自动重生）→ jcy_api（research/deliverables/）
  → 明文主 API(43.145.33.254:27990, 纯HTTP无TLS) + E 解密。
- E 解密 = C 转译引擎 research/engine_c/jcy_fuse24.dll（V24 --cprop，ARM64→C 1:1 复刻
  libcore.so），body/PC-trace 已逐位验证；CONST_b 生成器(0x2d9ed0 churn)无闭式，
  标定=引擎全量跑一遍零明文。报告 research/reports/V24_cprop.md 必读。
- POST 请求加密目前走 EOracle（Unicorn 模拟, research/captures/rsa_scan/e_oracle.py）；
  GET 无请求体不走加密。auth 走 authgen 子进程 + 磁盘缓存 80s TTL（.auth_cache.json）。

## 本轮已完成的实测（全部有数据，脚本都在 research/ 下）

### ① /resolve 拆段（tmp_resolve_timing.py，桥外直连 JcyApi，稳态 iter2/3）
- play 全链路：**1225~1281 ms**（iter1=2886ms 含 EOracle 冷启动 boot）
- 拆段（稳态，按大小排）：
  | 段 | 耗时 | 说明 |
  |---|---|---|
  | 解析器 HTTP yh.jx.xajtl.com:80 | **620~740ms** | conn 100~160 + 服务端 wait 430~521（nginx, X-Cache: MISS），read≈0 |
  | E 标定 calibrate（引擎churn, 323块） | **382~398ms** | jcy_decrypt(C) 仅 0.1ms，成本全在标定 |
  | 主 API HTTP 43.145.33.254:27990 | **~190ms** | conn ~91 + wait 82~97 + read ~5 |
  | encrypt_p1（EOracle 请求加密） | **~65ms** | iter1 181ms 含 Unicorn boot |
  | auth_header | 0.4ms | 盘缓存命中 |
- 注意：脚本的 conn/send 计时重叠（send 包含 connect），真实发包 <1ms。
- 上游波动大（iter3 曾 3435ms）：单次测量噪声高，对比必须多次取中位。

### ② keep-alive 实测（jcy_client.py:129 与 jcy_api.py:232 均为每请求新建 HTTPConnection+close）
- 主 API：支持 keep-alive（同连接第2请求 99~101ms vs 新连接 173~195ms）→ **每请求省 ~75~95ms**；响应头无 Connection: close，HTTP/1.1 默认复用实测成功。
- 解析器（nginx）：响应头 `Connection: keep-alive`；同连接第2请求 **省 ~144ms**。
- TCP connect 主 API 中位 ~78~91ms。

### ③ 实验A：c_engine 替代 EOracle（POST 请求加密）——已证逐位等价
- `c_engine.encrypt(K16, pt)` ≡ `EOracle.enc(pt, K16, K16[::-1])`，1/2/4/8/16 块全部逐位相同。
- 稳态 **5.7ms vs 104.6ms**（每 POST 省 ~99ms，且消灭 Unicorn 冷启动）。
- pt 对齐语义一致：jcy_client 先补空格到 4 字节对齐，两侧内部 PKCS7 到 16 的行为相同（实测 8B 输入同样输出 32B 全等）。
- ⚠️ 桥 main.py 的 DLL 锁定清单目前是 ("encrypt_with_x","encrypt_with_iv","init","load")，
  **替换后必须把 "encrypt" 加进去**，否则多线程并发进 DLL 单例态会崩（历史事故：并发基准 ConnectionReset）。

### ④ 实验B：play 响应部分解密（blocks=N）——/resolve 的大砍刀
- play 响应 P1=5168B=**323 块**；全解 613~620ms。
- 字段位置（明文偏移）：code@0，**url(source)@140~211（块 8~13）**，parse(lua)@213 起，lua 全长 3993B 到块 ~305。
- **lua 里没有 `salt = "..."` 字段**——盐硬编码在 sign() 函数体（`utils.md5(data .. "pzizhsqjjt" .. ts)`）；
  `_lua_params` 的 salt 正则一直 miss、回退默认 `pzizhsqjjt`，恰好正确（aes_key/aes_iv 同样=默认值）。
- 部分解密扫描（每次新 decryptor=模拟全新 K16resp）：N=8/16/24/32 ≈ **154~205ms**，N=128 ≈ 351ms，全解 613ms。
  N≥16 即可 regex 抽出 `"url":"..."`（source）。
- ⚠️ 抽参数时注意 JSON 转义：明文里 lua 是 `\"` 转义形式，`aes_key\s*=\s*"` 会 miss（本轮扫描 aes_key=False 就是这个原因），
  需用 `\\"` 或先 json 解码。
- 结论：/resolve 的 play 半程只需 **blocks≈16~24 + 默认 lua 参数（盐/aes/parser 全部与默认一致，本轮实测核实）**，
  标定成本 613→~180ms；默认失效时回退全解走 lua，保险丝必须留。

### ⑤ source/urls 跨请求稳定——/resolve 可缓存
- 同 vid/part 连续 3 次全链路：**source 相同、urls 相同**（3/3）。
- → 桥层可给 POST /resolve 加短 TTL 结果缓存（建议 60s，key=vid|play|part），重复解析/换清晰度秒回。
- 前端 TanStack Query queryKey=["resolve",vid,line?.play,part] 已有客户端缓存，桥缓存是二道保险。

## 本轮五个方向的定论
1. /resolve 3346ms 拆解：**完成**（见①；桥实测值含冷启动，稳态链路 ~1250ms）。
2. 标定增量外推：**跨请求不成立**（K16resp 每响应都是新的，实测 3 次全不同）；同请求内 decrypt_e.calibrate
   的 _base 切片机制已就位。真正有效的落地形式=④的部分解密（标定成本 ∝ N）。
3. 上游连接复用：**主 API 与解析器都支持 keep-alive，双方每请求分别省 ~90/~144ms**（见②），待实施。
4. 引擎 hub 直化：**未执行**（仅评估：hub 动态分发 ~10% 指令；对 video_list 1750 块标定 ~2400ms 的场景有效；
   改 gen_engine.py 重生成+重编 ~8min，须全量验证）。本轮优先做桥/客户端层，引擎后置。
5. GET 缓存 TTL 分级：**未实施**。建议 config/channel/banners/sign_rule → 300s，其余 30s；另加 ⑤ 的 resolve 缓存。

## 下一步实施清单（按性价比排序，新会话照此执行）
1. **play 部分解密 + 默认 lua 参数**（-420ms）：jcy_client.request 增加 blocks 参数透传给
   _decrypt_p1→EDecryptor.decrypt(P1,K16,blocks=N)；JcyApi.play 中 POST /app/video/play 走 blocks=24，
   regex 抽 `"url":"([^"]+)"` 得 source，lua 参数用类默认（SALT/AES_KEY/AES_IV/PARSER）；
   解析器失败或参数校验不过 → 回退全解+lua。注意 ④ 的转义坑。
2. **keep-alive 持久连接**（主API -90ms / 解析器 -144ms）：jcy_client.request 复用 HTTPConnection
   （坏线重建，捕获 http.client.RemoteDisconnected/BadStatusLine 重试一次）；jcy_api.play 解析器连接同理。
   桥是 4 线程池、每线程独立 JcyApi（thread-local），连接放实例属性即可，无需跨线程共享。
3. **EOracle→c_engine.encrypt**（-60ms/POST 且消灭冷启动）：jcy_client._encrypt_p1 改为
   优先 c_engine（import 失败/异常回退 EOracle）；**main.py 锁定清单加 "encrypt"**。
4. **/resolve 结果缓存**（重复→~0ms）：main.py resolve() 加 key=vid|play|part、TTL 60s 的缓存
   （复用 _RESP_CACHE 机制）；注意缓存前先剥离 lua/play（现有逻辑已做）。
5. **GET TTL 分级**：main.py _RESP_TTL 改按前缀分级（config/channel/banners/sign_rule 300s，其余 30s）。
6. 每步完成后重启桥复测：kill python（node 自动重生）→ curl /health → research/tmp_bridge_timing.py。
7. （后置）引擎 hub 直化：改 research/gen_engine.py → build_fuse.sh 重编 → verify_cprop.py + bench_iso.py 639 15（≥15轮）。
   仅当 1-5 落地后仍需要压 video_list 冷耗时才动。

## 预期收益（稳态 /resolve ~1250ms →）
- 2+3+1 合计约 **-650ms** → ~600ms；重复解析靠 4 → ~0ms。上游解析器服务端 wait 430~520ms 是不可压的硬底。
- video_list(24条,1750块) 冷 ~3831ms：标定占 ~2400ms（1.37ms/块线性），部分解密不适用（需全量 JSON），
  唯一杠杆=引擎提速（方向4）。

## 硬约束（违者前功尽弃）
- 任何引擎改动必须过：python research/verify_cprop.py（body 1/128/639 逐字节）
  + python research/bench_iso.py 639 15（≥15 轮！7 轮中位数会被噪声翻案）
- 金料上限=被测上限：新负载规模必须冒烟（曾因只测到 639 块漏掉堆窗口溢出，已修：engine_grow_heap 256MB）
- 改引擎/重编 DLL 前先停桥：kill node(scripts/web-server.mjs) + python（Windows 锁已加载 DLL，
  且 node 会自动重生抢 8792 端口）；编完再 node scripts/web-server.mjs 后台拉起
- 引擎源码勿手改：改 research/gen_engine.py 后重新生成+重编（build_fuse.sh，~8分钟）
- 本轮未改引擎：verify_cprop/bench_iso 未执行（也无需执行）；交付物 jcy_api/jcy_client/桥改动后
  至少跑一次 play 全链路冒烟（code=20000 + urls 非空）
- https://api.zxcbug.com/ 是本工具中转资产，严禁任何探测/攻击
- 未执行的步骤明写「未执行」，禁止虚构计时结果；进度播报用
  「当前进度：N%｜已完成：…｜下一步：…」
- 计时对比必须同会话多次取中位（上游波动可达 2.5×，本轮 iter3 曾 3435ms vs 稳态 1225ms）

## 本轮新增脚本（research/ 下，均已跑通，结论已提炼在上文）
- tmp_resolve_timing.py — /resolve 分段解剖 + 主API keep-alive 实测（monkeypatch 类方法+http.client 钩子）
- tmp_play_partial.py — play 响应全解/截断扫描第一版
- tmp_play_fields.py — 字段跨度定位 + 解析器 keep-alive 复用实测（省 144ms）
- tmp_partial_minN.py — 最小 N 扫描 + source/urls 跨请求稳定性（3/3 相同）

## 常用命令
- 重启桥：cd 囧次元根目录 && (node scripts/web-server.mjs > logs_bridge.log 2>&1 &)
  （只改 python 侧可仅 kill python 让 node 重生：netstat -ano | grep 8792 找 PID，taskkill //F //PID <pid>）
- 健康检查：curl http://127.0.0.1:8792/health
- 桥层计时：.venv/Scripts/python.exe research/tmp_bridge_timing.py
- /resolve 分段：.venv/Scripts/python.exe research/tmp_resolve_timing.py
- 引擎基准：cd research && python bench_iso.py 639 15 && python bench_e2e.py 3
- 正确性：cd research && python verify_cprop.py（trace 版需 jcy_fuse24_trace.exe，已存在）
- venv python：.venv/Scripts/python.exe（httpx 已装）
- 主 API 直连参数：HOST=43.145.33.254 PORT=27990（jcy_client.py:41），解析器 yh.jx.xajtl.com:80
