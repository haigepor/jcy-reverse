# V9 交接提示词（新对话直接粘贴使用）

逆向 Android 应用 囧次元（包名 com.tudou.tool，Flutter/Dart AOT 3.6.0 arm64，libapp.so + libcore.so 静态 OpenSSL，雷电系 x86 模拟器 + Houdini 翻译层）HTTP `authentication` 头的生成算法，交付离线生成器 authgen（Python），其输出的 auth 头能通过服务器 43.145.33.254:27990 真实校验（返回 code=200 而非 30000/4035xx），验证过程追加到 out/VERIFICATION.txt。全程可用多个子代理并行深度分析（并发上限 2），严禁虚构任何结果。

## 一、已实锤事实（勿重复验证）

### auth 模型（Model B，实锤）
- auth = custom_b64( magic15(15B) ‖ b15(1B) ‖ O(96B) )
- custom 字母表 = `5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj`（= 标准 b64 字母表按位置映射，已离线与引擎自测向量互验）
- 服务器校验 magic15、b15、O[0:32]；O[0:64] 确定性（同 ts 全同），O[64:96] 随机
- nonce 不参与验签；验签先于时间检查
- magic15 = `23754ae9d0cbe749f5441e769b4514`，b15 = 62(0x3e)，518 条语料恒定 → key 是服务器下发的外部注入，不在 APK/不在 178MB 内存 dump（已扫尽）

### libcore 304eb0 管线（完整破解）
```
输入 = 视图对象 {tag, len, ptr}（0x404476/0x40447e getter + 0x2ce6f8 string ctor 构造副本）
copy = A(0x2dc524, 经 0x2dbf9c)(singleton, copy)   # 3字节步进编码循环，每迭代 alloc 0x290；APPEND1 追加 64B 字母表本身
copy = E(0x2d6f78)(singleton, copy, "ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"(32B@0x689730), "WonrnVkxeIxDcFbv"(16B@0x688149))
copy = A(singleton, copy)                           # 再变换
E5804(0x2e5804)(sret, out, str) @0x3052a4
E587C(0x2e587c)(sret, data, len) @0x3052d0          # append 语义（非 b64 编码器）
```
- 调用者函数 0x305d94（out/v9/static7/caller_306548.asm 全 984 行在盘）：字符串构建 → 0x2ff574 → 0x341410 → 0x306478 vsnprintf(out=sp+0x190,0x100,0,0x100,fmt=BASE+0x68977f) → 0x2ecd2c 转换 → 0x2ec120 builder → 0x306548 BL 304eb0(sret=x27, x1=0x688130, x2=0x688148)
- 0x306a3c = __vsnprintf_chk 包装器（导入桩实名确认）；fmt=[0x67cd08]+0x66b5ac3907540576=BASE+0x68977f——模拟器中为空串，真机运行时填充（最后的配方缺口）
- E 原语：E(singleton, s1, s2, s3)，输出块数由 s1 长度定（≤16→16B），确定性；E("=",ziIS,Wonrn)=43711e316a3bb0e35ac6d811ec65b3f6，E("==",ziIS,Wonrn)=90a178f857b9d6f69e0c8b38099e4737

### 本会话最新突破（决定性）
1. **0x2de6d8 epilogue 破译**：w22 = '=' 填充次数（`for w22<mode: append(accum,'=')`，尾部 string(sret,accum) 拷出）。mode=2 对 112B 载荷（112%3=1）完全正确——**不是退化标志**。真正问题：A 的主循环累积串为空（没吃到输入）。
2. **视图 tag 判定**：0x688130={0x31,0x20,ptr}（ziIS 32B）、0x688148={0x31,0x10,ptr}（Wonrn 16B）→ **tag=0x31 是字符串类型码，第二字段=长度**。之前 mkview 用 tag=1 是错的 → A 的 extract 链(0x2dd3bc)返回空。**改 tag=0x31 重跑即可让 A 产出非空**。
3. **builder 0x2ec120 半解剖**：入口读 [x0+0x60] 测 bit4/bit3 分三路（0x2ec1c0/0x2ec280/默认），全表混淆调用，尚未确定它给 view 盖什么 type code——这是下一个要完成的分析点。
4. **Java/smali 层情报**（out/base_smali/）：
   - `SplashActivity.load(String)` 接收 Java 拼好的 JSON：app_id=**4150439554430529**(f/a.a)、client_appid=**default**(f/a.c)、code_version=**3.0.0.8**(f/a.b)、app_name=q()、app_version=r()、device_id=s()、so_path=nativeLibraryDir、file_path=filesDir → native load(libloader@0x2a1f40, 1088B)
   - f/a.e=077ca3e0c272e45294116d2d7370c858 只是 Sentry DSN 密码（http://…@124.222.91.157:9000/4），**已排除**
   - `SplashActivity.onProgress(String)` = native→Java 回调 {code,message,payload:{total,now,url}}——热更新进度；auth 就用在这类更新检查请求
   - GApplication.init() 无参 native（libloader@0x2a6268, 356B）；libloader call@0x2a3bac(5552B)；工作线程 0x2a137c → bl 0x31e268(1,sp)（真正引导函数，头部 110 条已看：sub sp,0xae0、x24=0x5e3000、x22=0x5f2950/x20=0x5f2cc0 BSS、状态机式；**未解剖完**）
   - libloader 内嵌 OpenSSL 6.2MB，导入 popen/fopen/fgets/getpid（读 /proc 指纹）

### 运行时 key 全家桶（0x688000-0x689800）
0x688101="Ee&AVzdgru^$hX%j"、0x688119="M0KylhhHyj1HZ&Mi"、0x688149="WonrnVkxeIxDcFbv"、0x689529="qPwClBj7j7ZQraSm"、0x689541="p3JdVQl3q7WQJIgG"、0x689730="ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"(32B)、三条 56B 自测向量(0x689798/0x6897d2/0x68980c，解码=40位大写hex SHA1 形态)、0x689764/0x689772 运行时字符串、0x68977f fmt 串。单例 0x689640：{自指}，+0x18/+0x30 空，+0x80="8v-46mra"(反转=arm64-v8)、+0xb8="zVA&eE"(反转=Ee&AVz)；单例方法=BASE+0x2cdeb4(S,&f18,&f30)：先 f30→sret 拷贝，再 S.method(sp+8,f18)。8 种 key 形态注入单例全失败。

## 二、关键文件索引
- out/v9/emu/emu_core.py —— Unicorn 模拟器（完好）：BASE=0x400000、HEAP=0x50000000、STUBS=0x60000000、TLS=0x61000000、MAGIC_RET=0x900000；已验证用法：`emu.run_init_array()` 8/8 全通 → `emu.call(0x2fdc24,(0,))` init → `emu.call(0x312a88,(inst,))` 自建实例 → mkstr(0x2cf428)/mkview/readstr(双布局)。调用惯例：**先建全部串对象 → uc.reg_write(X8,sret) → call**（X8 会被嵌套调用破坏）；so 相对路径 `../../base_decoded/lib/arm64-v8a/libcore.so`（cwd=out/v9/emu）；语料路径 `../brute/O_true_corpus.json`
- out/v9/emu/probe_304eb0.py —— 语料驱动 304eb0 + hook 链 + 期望 auth 全内存扫描（复用，改 mkview tag=0x31）
- out/v9/brute/O_true_corpus.json —— 518 条语料；首条 ts=1790618586109, nonce="65072702", O[0:32]=2b3ef9d5b6c78fd91e33fb5136486918, 期望 auth=6MsfEg71pCxZ4ipNACeen/VLLg2N9Djb...
- out/v9/static7/：caller_306548.asm（0x305d94 全函数）、fn_304fa0_bodies.asm（304eb0 主体）、core_2d6f78.asm（E 原语）、libloader_call.asm、libloader_worker.asm
- out/v9/BREAKTHROUGH.md —— 前期成果固化（部分已被上文超越，以上文为准）
- out/base_smali/ —— 完整 smali； SplashActivity.smali / GApplication.smali / f/a.smali
- out/base_decoded/lib/arm64-v8a/ —— libcore.so / libloader.so
- out/mem_dump.bin —— 178MB 运行时内存 dump（已扫尽）

## 三、立即执行（按序）
1. **完成 builder 0x2ec120 分析**（capstone 反汇编续 0x2ec280 之后），确定 view type code（预计 0x31 或由 [x0+0x60] bit4/bit3 决定）。
2. **改 probe_304eb0.py 的 mkview tag=0x31**，重跑 A(0x2dc524)(singleton, view("1790618586109"))：预期累积串非空。判据：输出长度 ≈ ceil(len/3)*4 且 epilogue 追加 "=="。
3. A 输出非空后完整跑 304eb0 管线，对照语料 O。不一致则用 fmt 假设空间对齐（纯 ts / ts+nonce / "ts_nonce" / 带前缀等）——管线输入是 vsnprintf(BASE+0x68977f) 的产物，fmt 未知但可由 518 语料反推。
4. fmt 串 0x68977f 填充路径：找 0x689764/0x689772/0x68977f 的写入者（嫌疑：0x31e268 引导链 / E 原语初始化 / native load JSON 解析）。
5. 管线全通 → Python authgen → 518 语料全验（O[0:32]=2b3ef9d5...）→ 服务器 43.145.33.254:27990 实测 code=200 → 追加 out/VERIFICATION.txt。
6. 备选：若纯算法复刻受阻，用 Unicorn 驱动 emu_core 作离线生成内核（使命允许）。
7. 停掉僵尸子代理 agent_472bb847-4f12-4c1b-a414-c2cb16d43257。

## 四、纪律（必须遵守）
- 严禁虚构 hash/HTTP 响应/offset/验证结果；未执行的步骤明确写「未执行」
- 多步任务播报 `当前进度：N%｜已完成：…｜下一步：…`
- 二进制拉取必须 `MSYS_NO_PATHCONV=1 adb pull`；adb 在 `C:\Users\haige\.trae-cn\extensions\hyb1996.auto-js-pro-ext-9.0.9\tools\adb.exe`（Git Bash PATH 无 adb）
- Bash 是 Git Bash；frida JS 空 top-level + `recv('go',...)`，python 侧 `script.post({"type":"go"})`
- 子代理并发上限 2；不重复已穷尽实验
- 服务器实测温和限速，勿压测

## 五、交付标准
1. authgen 可运行，输入 (ts,nonce) 输出 auth 头
2. 518 语料本地全验通过（O[0:32] 匹配）
3. 服务器实测返回 code=200（截取真实响应）
4. out/VERIFICATION.txt 追加完整验证记录
