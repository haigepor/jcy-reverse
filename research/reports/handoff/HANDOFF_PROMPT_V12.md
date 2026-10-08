# 囧次元协议逆向 · V12 交接（f(K16) 设备动态轮）

## 任务总目标
对 com.tudou.tool（囧次元）HTTP 协议完成最后闭环：伪造能被服务器接受的请求（现在返回 800131）+ 离线解密响应体。auth 头伪造、P0 构造、响应 P0 解封均已破，**唯一卡点是 f(K16)**：请求会话 key/iv 如何从 K16 派生。

## 已验证协议模型（不要重复验证）
- body = `<P0_b64>.<P1_b64>`，自定义 base64 字母表 `5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj`（rodata @0x1e1c74）
- 请求 P0 = RSA-2048 PKCS1-v1.5(server_pub, K16)，K16 = 16 字节原生 RAND 原始值（P0 里没有 iv）
- 请求 P1 = 某 16B 分组密码加密的业务 JSON，密钥对 = f(K16) ← 唯一未破点
- 响应 P0 = RSA(pub_from_go, K16resp)，用 priv_from_go.pem 离线可解（实测样例 K16resp=3ME483VJDBQTEHD6）
- 响应 P1 = 48B = 3 个 CBC 块；按 V11 模型密钥 = 请求会话 key/iv（待设备实证）
- 信封/channel 层 key store 恒为 qPwClBj7j7ZQraSm / p3JdVQl3q7WQJIgG（EVP_Init lr_off=0x3751b4），与业务 P1 无关
- 请求头：appid=4150439554430529、ts(毫秒)、nonce、tcs=2、x-version=2020-09-17、authentication=authgen.gen(ts)、UA Dart/3.6 (dart:io)；URL http://43.145.33.254:27990/app/video/device-base
- authgen 在 src/ 下（Unicorn 后端，首次 gen 需数秒），forge 脚本用 subprocess 调

## 本轮 emu 结论（关键，别重走弯路）
1. 业务 P1 加密不走 OpenSSL EVP：api_encrypt 全程业务层 EVP encrypt init 零触发（只有 DRBG 内部调用）
2. 自研密码模块已定位（静态+动态双确认）：
   - 表构造器 0x2cd8b0：SBOX(0x1dfc00) 拷栈 → 256 次混淆变换（间接 blr，GOT+常量）→ 输出 256B 自定义表到 x1；x8=sret
   - 调用链：0x303df0 / 0x3050f8（API 层 bl）→ 0x2d6f7c → 0x2cdeb8 → 0x2cd8b0
   - api 阶段 0x2d6f7c 被调 2 次（疑似一次 P1 加密、一次 auth 头），0x2d9ed0 连调 7 次（疑似轮函数/密钥扩展），0x2d9014 读常量 0x1e0120（`1f 3e 5d 7c 9b ba d9 f8`+零）16 次，0x2e5880 = b64 编解码相关（读 config 里 alphabet 拷贝）
   - config init 0x312a88：两组 16×16B std::string 常量（取自 AES SBOX/逆SBOX 行切片）+ alphabet(0x1e1c74) + BLOB64(0x1e1cb4)，经 bl 0x313bf4 存入 config 对象
3. emu b64 编解码表越界 bug：解码表构建（pc 0x2ce3dc / 0x2e5b3c，各 256 次读 alphabet 堆拷贝 0x50006010 等）读出 64 字符 alphabet 界外邻接零页 → P0b64/P1b64 输出全是 0x00 垃圾 → **emu 输出侧产物不可信，别再试图从 emu 抓 P1 密文**（差分两份 dump 也没找到幸存密文）；输入侧捕获（RSA 256B 输出、K16）仍可信
4. 以上偏移对真机同一份 libcore.so 直接有效

## 负结果清单（禁止重试）
- 静态 keystore 对作请求 P1 密钥（forge v5 变体 A-D → 全 800131）
- f(K16) 常见派生：K16 / md5(K16) / md5(hex串) / sha256[:16] / [16:] / sha1 / 逆序 / keystore 对 / SBOX 24 块常量 × 33 种 iv × CBC/ECB/CTR/CFB/OFB —— 对 emu 差分 dump 双 oracle 0 命中
- K16resp 作响应 P1 密钥（V11 已 8 oracles 证伪）
- apipost MCP 只有管理工具、无请求执行能力 → 实测直接 urllib 发请求，MCP 仅用于录入结论（project_id 6ef0f75d8470000，直调 JSON-RPC 方法见 memory/apipost-mcp-setup.md）

## 设备路线现状（从这里接着干）
- adb 在 C:/leidian/LDPlayer14/adb.exe；Git Bash 里 `export PATH="/c/leidian/LDPlayer14:$PATH"`，所有设备命令前缀 `MSYS_NO_PATHCONV=1`
- 设备 emulator-5554 已连；frida-server(root) 运行中；app pid 24888（会变，用 frida enumerate_processes 按"囧次元"名字找）
- frida 客户端 17.8.2（项目 .venv）；frida 17 移除了静态 Module.findExportByName，脚本里 findExport 已做多 API 兜底
- 钩子脚本 research/captures/rsa_scan/live_evp_hook.js 已验证挂载成功：EVP_EncryptInit_ex / EVP_DecryptInit_ex 导出 + RAND_bytes；60s 采样 0 条 = 应用后台无流量
- **monkey 命令在模拟器不可用**（inaccessible or not found）→ 用 `am start` 拉前台

## 下一步（按序执行）
1. `cmd package resolve-activity --brief com.tudou.tool` 找 launcher Activity，`am start -n <pkg/activity>` 拉前台
2. frida attach(pid) 挂 live_evp_hook.js，前台翻页产生真实流量 60-120s，抓 EVP dec/enc 的 key/iv + 调用者偏移
3. 若业务层不走 EVP（与 emu 结论一致）：升级脚本同时挂自研模块入口 0x2cd8b0 / 0x2d6f7c / 0x2cdeb8 / 0x2d9ed0（真机 libcore.so 基址 + 偏移），入口处 dump x0-x4 指向内存（16B key/iv 候选 + 明文/密文缓冲）
4. 样本推断 f：先拿 (key,iv) 与 K16resp 试 md5/sha 关联；不够就主动发自铸 P0 请求（K16 自选，改 forge_v5.py）+ 抓加密点 key/iv → 输入输出对直接定 f
5. f 破了 → forge v6：P0=RSA(自铸K16) + P1=f 派生对加密 params → 目标：响应非 800131
6. 响应 P1 用同会话 key/iv 离线解密：`decrypt_response.py decrypt --file resp.txt --key .. --iv ..`
7. 实测结论录入 MCP 囧次元库；docs/V12 记录（P0=K16 真值、自研模块、emu 配方与 bug、负结果网格）

## 关键文件
- research/toolchain/emu_unwind.py（emu 主脚本，全部钩子在 main()，K16 固定 bd070e74e1e0c61a4f538c82688ad303）
- research/captures/rsa_scan/：forge_v5.py、live_check.py、live_evp_hook.js、live_evp_capture.jsonl、emu_ks_run8-12.log、emu_heap_A/B.bin、priv_from_go.pem、live_check_resp.txt
- research/deliverables/decrypt_response.py（unwrap/decrypt CLI）
- research/reports/handoff/HANDOFF_PROMPT_V11.md（上轮背景）、docs/crypto/http-body.md（协议文档）

## 纪律（持续生效）
- 执行台账：不重复已成功的读取/命令；负结果不再重试
- MSYS_NO_PATHCONV=1 用于所有 adb/设备命令
- 命令输出 >512KB 落盘，只回传摘要+文件路径
- 进度播报：`当前进度：N%｜已完成：...｜下一步：...`
- 未执行的步骤明确写"未执行"，禁止虚构结果
- api.zxcbug.com 是本工具的中转资产，严禁对该站点做任何探测/攻击/压测
