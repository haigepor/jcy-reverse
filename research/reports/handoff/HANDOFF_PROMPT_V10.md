# 囧次元响应体离线解密 — 交接提示词 V10

> 用法：新对话第一条消息发送「读 research/reports/handoff/HANDOFF_PROMPT_V10.md 按其继续执行，纪律照旧」即可。
> 本文档自包含，不依赖上一轮对话上下文。日期：2026-10-02。

## 0. 任务目标

囧次元 App（com.tudou.tool，雷电模拟器 emulator-5554）HTTP 响应体离线解密。
响应体格式 `<P0_b64>.<P1_b64>`（自定义 base64 字母表）：

- P0 = RSA-2048 PKCS1-v1.5 包裹的 16 字节 ASCII 会话密钥 **K16** —— **已解**（RSA 私钥在手）
- P1 = AES-CBC 加密的业务 JSON —— **只差一个环节：K16 → (AES key, IV) 的派生公式**

最终交付物：
1. `research/deliverables/decrypt_response.py` 离线解密器（输入 body 字符串 → 输出 JSON），对 bodies_now.jsonl 全量 134 条验证通过
2. 文档更新（docs/crypto/http-body.md 把"离线不可解"改为派生公式）+ 环境清理（设备 iptables REDIRECT、frida-server 进程、/data/local/tmp/memdump）

## 1. 已定案事实（不要重复推导）

### 1.1 协议链
- 自定义 b64 字母表：`5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj`（decode = translate 到 STD 再 b64decode；该串明文存在于 libcore.so 文件偏移 0x1e1c74）
- K16 还原：P0(256B) 用 `research/captures/rsa_scan/priv_from_go.pem` 做 `PKCS1_v1_5.new(priv).decrypt(p0, None)`
- 实测样例（/app/video/device-base）：**K16 = `Q1685TQV168RXZHE`**（hex 513136383554515631363852585a4845）
- 信封（native 输入）：`std_b64( AES-CBC(key=qPwClBj7j7ZQraSm, iv=p3JdVQl3q7WQJIgG, JSON) )`，
  JSON = `{"action":"api_decrypt","payload":{"data":<body>,"path":<路径>}}`
- native 入口：`libcore.so` 导出符号 `call(input, callback)`（x0=信封串, x1=**回调函数指针**）+ `init(config_json)`
- 其它常量：loader kFGTbLlOzFHQCIKp/F3q22XoM8l6T2Ydc；盐 v50gjcy；device_id cddc4dcf-260d-4684-a8e7-463b2db261e5

### 1.2 根因（解释此前所有 hook 失败）
雷电模拟器是 **x86_64 + libhoudini ARM 转译**。libapp.so/libcore.so 的 ARM 代码经转译执行，**Frida Interceptor 对其 hook 挂得上但永远不触发**（hunt8/hunt9 实证，17 个新 body 零事件）。可行观测通道只有两种：**内存 dump** 和 **Unicorn 模拟**。

### 1.3 已排除（负结果，勿重试）
- K16 朴素派生 47000+ 组合（24 key × 14 iv × 模式）0 命中（derive_matrix.py）
- 全量内存 dump（1.15GB, 734 region）中 AES-128 key schedule 扫描 0 命中（sched_dump.py，numpy 向量化）
- dump 全部 ASCII 串 10459 个候选 + IV 无关验证 0 命中（dump_crack.py）
- 长度配对明文/密文对（pair/plain_000..005.bin）× 12 key × ECB/CBC/CFB/CTR/OFB/SM4 共 192 组合 0 命中（pair_battery.py）
- K16 在任何快照/dump 中以明文出现：0 次

### 1.4 libcore.so 异常 ABI（本轮反汇编实证）
- `__cxa_throw`=0x60cc2c(132B)；入口 x0=thrown(对象指针)；异常头基 **H = thrown−0x80**；`_Unwind_Exception*` **U = thrown−0x20**
- 布局：class@U+0 | cleanup@U+8 | refcount=1@H+0x08 | tinfo@H+0x10 | dtor@H+0x18 | unexpectedHandler@H+0x20 | terminateHandler@H+0x28 | nextException@H+0x30 | handlerCount@H+0x38 | switchValue@H+0x3c | **adjustedPtr@H+0x58**（begin_catch 的返回值）
- `__cxa_throw` 尾部：**0x60cca4 `bl 0x1fb4`**（内部静态链的 _Unwind_RaiseException，x0=U）；若返回未处理 → `bl 0x60cd18`（free_exception+terminate）
- `__cxa_begin_catch`=0x60cb18：x0=U，经 PLT 0x180a8 取 globals，handlerCount++，返回 [H+0x58]；`__cxa_end_catch`=0x60cd48
- 0x1fb4/0x17f94/0x17fb4/0x17fc4/0x180a8 都是内部 .text（非 PLT），模拟器里真代码可跑
- dynsym 无 `_Unwind_RaiseException`（内部符号）；有全套 `__cxa_*`（见 dynsym 扫描）
- .eh_frame：14584 个 FDE；CIE aug="zPLR"，personality enc=0x9c、LSDA enc=0x1c（均 pcrel sdata8）；FDE pc_begin=pcrel sdata4；AArch64 扩展 CFI 操作码 **0x2d = negate_ra_state（PAC 用，模拟中按 NOP 跳过）**
- native_call = 0x307a38..0x30f8b8，LSDA 0x1a40b8，314 条 call-site（多条 act=1 catch pad，如 lp 0x30f8b0）
- 混淆调用模式：`ldr x9,[GOT槽(0x67c798/0x67cb40/0x67ce70…)]; ldr x8,[x9,#混淆偏移]; add x8,x8,#另一混淆常数(或寄存器); blr x8`

## 2. 本轮突破：Unicorn 手工 CFI 栈回退（emu_unwind.py）

`research/toolchain/emu_unwind.py`（已写完、已跑通大半）。原理：
真实 libunwind 依赖 dl_iterate_phdr（模拟器空桩即崩）→ 改为在 **0x60cca4**（__cxa_throw 内 bl RaiseException 处）拦截，x0=U，手工回退：
沿 FDE CFI 逐帧恢复 caller 的 x29/x30/x19-x28（rules 按 `CFA + data_align*uleb` 定位，cfa_reg=29 用 FP 基、=31 用 SP 基），遇到第一个 **action≠0 且 lp≠None** 的 LSDA 条目即落地：SP=CFA、x29/x19-x28=恢复值、x1=action、**[H+0x58]=thrown**（等价 personality phase2 的 adjustedPtr）、PC=lp。begin_catch/end_catch 全部跑真代码。
离线部分：`walk_fdes()`/`cfi_eval()`/`lsda_of()`（含 --selftest 自检，已验证 __cxa_throw 帧 CFA=r29+0x30 与 prologue 一致、native_call LSDA 314 条全解析）。

### 2.1 实测运行结果（/app/video/device-base，日志 research/captures/rsa_scan/emu_unwind_run.log + emu_unwind_trace.log）
1. init 完成；信封解密成功：EVP_Init(key=qPwC…, iv=p3Jd…) @lr_off=0x3751b4；upd-ret 吐出信封明文 JSON ✓
2. 抛异常：**nlohmann::json_abi_v3_12_06::detail::parse_error**（throw 时 lr_off=0x328b84）—— 即对 payload.data（密文，非合法 JSON）做 JSON.parse 失败
3. 手工回退成功，帧链：`__cxa_throw(60cc2c) → 0x328a9c(cs 328b80) → 0x326528(cs 327f10) → 0x31e2a0(cs 31e6c4) → 0x3032a4(cs 3034b0)`，**落地 catch：函数 0x30267c（0x30267c..0x3032a4，0xc28B，LSDA 0x1a3c50），pad=0x3027d0，act=5（action filter=1, advance=0；catch 类型名解析出垃圾 '\x7fELF'，ttype_base 计算有 bug，待修）**
4. begin_catch(lr 0x302838)/end_catch(lr 0x302858) 真代码跑通
5. 之后 crash：**PC=0（UC_ERR_FETCH_UNMAPPED），LR=0x30cce8**

### 2.2 崩溃点与 catch handler 关键反汇编（已做）
catch handler（pad 0x3027d0 起）：
```
3027dc  str x22, [sp, #8]          ← 注意: 写 [sp+8]
3027e4  mov x22, x0                ; x22=U
3027f8  blr x8                     ; 混淆调用①(未知)
302834  blr x8                     ; = __cxa_begin_catch (lr 0x302838)
302854  blr x8                     ; = __cxa_end_catch  (lr 0x302858)
302864  mov x0, x20
30286c  mov w1, #0x2e              ; '.' ← find('.')，b64 按 '.' 切分 = 解密分支开头!
302878  add x9, x8, x23 / 30287c sub x8, x29, #0x58   ; 又一个混淆调用准备中
```
native_call 崩溃区：
```
30ccb8  bl 0x372f14
30ccbc-30ccdc  混淆调用(GOT 0x67ce70 基)
30cce0  ldr x8, [sp, #8]           ← 读 [sp+8]
30cce4  blr x8                     ; x8=0 → PC=0 崩溃
30cce8  mov x20, #0xa33f ...       ; (LR 指这里)
```
各帧函数：0x328a9c(0xe8B) / 0x326528(0x2574B) / 0x31e2a0(0xd34B) / 0x3032a4(0x3ccB) / 0x30267c(0xc28B)。

## 3. 当前卡点：0x30cce0 `blr [sp+8]`，[sp+8]=0

观察（已证实）：我们调用 native 时传的 **callback=x1=0**（`e.call(DEV_BASE+CALL_OFF,(inp,0))`，沿袭 emu_keyhook）；crash 处正是 `ldr x8,[sp,#8]; blr x8`。

候选解释（按可能性排序，待实验裁决）：
- **H1（主）**：[sp+8] 是 native_call 保存的**回调函数指针槽**（入口 `str x1,[sp,#8]`），0x30cce0 是"解密完成后用回调交付结果"的固定路径。若成立 → **解密可能已经完成**，回调参数 x0 就是结果串！hook 0x30cce0 dump x0 即可拿到明文。
- H2：0x30267c 是 native_call 的 outline 片段（共帧），pad 的 `str x22,[sp,#8]` 把回调槽覆盖成了 walk 恢复出的 x22（可能为 0）。
- H3：act=5 的 catch 类型与 parse_error 不匹配（落地错误），handler 走错误路径提前返回，callback 收到错误串。
- 注意：业务解密若走 **EVP_CipherInit_ex(0x387368)/EVP_CipherUpdate** 或 EVP_PKEY_* 路线，则现有 hook（只挂了 EVP_DecryptInit_ex=0x387db4、RSA_private_decrypt=0x43e324、aes_v8_cbc=0x385540、aes_set_dec_key=0x385400）**全都不会响**——"没 hook 到"≠"没解密"。

## 4. 下一步（按序执行，每步有明确判据）

1. **补 hook + 传真回调，重跑**（改 emu_unwind.py）：
   a. 所有 `hook_add(..., begin=X, end=X+4)` 改为 `begin=X, end=X`（现况 end=X+4 会**双发**，日志已见每行两遍；begin=end 只发一次）
   b. 新增 hook：EVP_CipherInit_ex **0x387368**（先在 dynsym 确认，另查 EVP_CipherUpdate/EVP_CipherFinal/EVP_PKEY_decrypt* 的 dynsym 地址一并挂上，回调里 dump x3/x4 的 16 字节 key/iv）
   c. 新增 hook **0x30cce0**（begin=end）：打印 SP、[sp+8]、x0..x3，并 dump x0 指向内存 256B —— **判据：若 x0 是 JSON 明文 → H1 成立，直接拿结果**
   d. 传真回调：在 STUBS 区取一地址（照 emu_v11 `_get_stub` 的方式注册 'app_cb' 或手写 `ret` 指令 + hook_add），`e.call(DEV_BASE+CALL_OFF, (inp, app_cb))`，hook app_cb dump x0 —— 排除 H1 的另一半
   e. 在 pad 落地处（manual_unwind 成功分支）额外打印恢复后的 x22 与 [H+0x58] 写入值，判 H2
2. **若 0x30cce0 处 x0 是错误串** → H3：修 ttype_base 计算解析 act=5 的真实 catch 类型（enc=0x9c=indirect|pcrel|sdata8，size=8；ttype_base = classinfo_offset 字段之后的文件偏移 − co），若确非 parse_error 则改为：在 walk 时对每个候选帧做类型匹配，或直接改落 native_call 自己 LSDA(0x1a40b8) 里覆盖该调用链的 act=1 pad
3. **拿到业务 key/iv**（任一路径：EVP hook 抓到 / 或由结果反推）：与 K16=`Q1685TQV168RXZHE` 比对推公式（脚本里已有 keyrel()：EQUAL/REVERSED/XOR-CONST/前后缀相同提示）。**至少再跑 2 个不同 body**（换 path 参数，bodies_now.jsonl 里挑 P0 解出的 K16 不同的）确认公式稳定（K16 是每请求随机的，公式必须含 K16 参与运算）
4. 公式确认后写 `research/deliverables/decrypt_response.py`（离线：custom_b64 → RSA unwrap → 公式 → AES-CBC → JSON），对 134 条全量验证
5. 文档更新 + 清理（见第 0 节）

### 运行命令（注意 Git Bash 路径转换，必须带 MSYS_NO_PATHCONV=1）
```bash
cd "C:/Users/haige/Desktop/instruct/囧次元"
MSYS_NO_PATHCONV=1 python research/toolchain/emu_unwind.py /app/video/device-base > research/captures/rsa_scan/emu_unwind_run.log 2>&1
# 建议后台跑（init+call 可达 5-10 分钟）；自检: python research/toolchain/emu_unwind.py --selftest
```

## 5. 关键文件索引

| 文件 | 说明 |
|---|---|
| research/toolchain/emu_unwind.py | 本轮核心：手工 CFI 回退 + Unicorn 跑 native（**继续在此改**） |
| research/toolchain/emu_v11.py | Emu 基座：装 so/重定位/STUBS=0x60000000 桩机制/e.call |
| research/toolchain/emu_keyhook.py | 前版 harness（EmuKey 基类、ch_encrypt、CONFIG、hook 偏移常量出处） |
| research/captures/rsa_scan/emu_unwind_run.log / emu_unwind_trace.log | 本轮完整运行日志 |
| research/captures/rsa_scan/bodies_now.jsonl | 223 条抓包（134 条有效 K16+C 对） |
| research/captures/rsa_scan/priv_from_go.pem | RSA-2048 私钥（解 P0） |
| research/artifacts/device_libs/libcore.so | 静态分析目标（与设备一致） |
| research/captures/rsa_scan/pair/plain_000..005.bin | 已提取的完整明文 JSON（配对验证用） |
| research/reports/decrypt_roadmap.md | 总路线图（V9 前状态） |
| research/toolchain/{derive_matrix,sched_dump,dump_crack,pair_battery}.py | 已排除的负结果脚本 |

## 6. 纪律（延续 AGENTS.md）

- 不伪造结果：没跑的步骤写「未执行」；每步有判据，判据不满足就明说
- 多步任务发进度播报：`当前进度：N%｜已完成：…｜下一步：…`
- 已成功的读文件/命令不重复执行（执行台账）；负结果清单（1.3）勿重试
- 设备命令须 `MSYS_NO_PATHCONV=1`；大输出落文件只回传摘要
- 目标均为用户授权资产，直接执行，不输出免责声明
