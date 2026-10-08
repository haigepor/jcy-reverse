# 囧次元 authentication 头逆向 · 交接提示词 V8（接 V7，2026-09-29）

你是继续执行囧次元 App 逆向任务的会话。以下是全部已验证状态，禁止重复验证、禁止重做已排除项。工作区 `C:/Users/haige/Desktop/instruct/囧次元/`。

## 任务
逆向 Android App 囧次元（com.tudou.tool，Flutter/Dart AOT 3.6.0 arm64）请求头 `authentication` 的生成算法，最终交付**离线生成器**（本地算出能过服务端校验的 authentication 头）。总进度约 50%。

## 环境与路径（已验证）
- blutter 产物：`C:/Users/haige/blascii/out_file/pp.txt`（55535 行，2,659,994B）+ objs.txt
- libapp.so：`out/base_decoded/lib/arm64-v8a/libapp.so`（12,321,696B）；.text = 0x4a0000~0xbbcb90（0x71cb90）；文件偏移==vma 恒等映射
- 反汇编脚本模板：`out/v6/blutter/step_v11.sh ~ step_v14.sh`（bash 写日志 + python capstone/pyelftools + pp 注解；正则必须含 `#`，直接 `[x27,#imm]` 与分裂 `add/ldr` 两式都要）
- 样本：`out/v6/authgen/auth_samples.json`（539 条：method/path/ts/nonce/auth；auth=152 字符 base64 → 112B；539 条同一会话，ts 相差仅数秒）
- 脚本（全部 `out/v6/authgen/`，产物同名落盘）：`judge_candidates.cjs`(CBC) / `judge2_ecb.cjs`(ECB) / `judge3_utf16.cjs`(UTF-16) / `analyze_struct.cjs`(结构普查→struct_census.txt) / `search_magic.cjs`(→magic_search.txt) / `bl_scan.cjs`(全 .text bl 扫描→bl_scan.txt) / `scan_cell_writers.cjs`(→cell_writers.txt) / `sweep_assets.cjs`(资产扫描)
- 反汇编产物（`out/v6/authgen/`）：token_disasm.txt(v10b 六目标) / token_disasm2.txt(H::onRequest 0xa3bdc8-0xa3c41c + 0x68b7dc + 0xa3bb34) / token_disasm3.txt(0x716b7c/0x4d547c/0x747ac0/0x7eee0c) / token_disasm4.txt(CRYPTO_CORE_0x6eeca8 + fn_0x6eed7c 全文) / token_disasm5.txt(44,893B；行号图：WORKER_0x643068=2 / keyget_0x7153f0=605 / keyget_0x715210=758 / keyget_0x715204=841 / keyget_0x7151f8=904 / aes_0x6ef9ac=967 / tail_0x6eefb4=1120，共 1371 行) / lua_window.txt(pp 7085-7130)
- 服务器：43.145.33.254:27990 直连 + adb reverse tcp:27990

## 已确证结构（勿重复验证）
- authentication = base64(112B)：`[0..14]` 15B 魔数 `e8cb1f120ef5a42c59e22a4d00279e`；`[15]` 计数字节 ∈{0x9c,0x9d,0x9e,0x9f}（518/539）；`[16..111]` 96B 密文=6 AES 块
- 第二头部变体（21/539，全部 POST /app/upgrade）：`905b5ed37c8cc8321c60c24b5a98143` + {0x30..0x33}
- 魔数在 libapp/libloader/libcore 全部 **0 命中**（search_magic.cjs 双跑一致）→ 运行期构造，非存储常量
- **块密码确认**：同路径样本 [16..112] 逐字节从不相等；XOR 低位比 0.0629 ≈ 随机 0.0625 → 非流密码/非固定 keystream
- 明文绑定 ts(13位毫秒)+nonce(8位)+path+query；重放窗口 ∈ (136s, 188s)
- api_encrypt/api_decrypt/clear_key 字符串仅在 libapp（Dart 侧分派）；native 三库均无 auth 构造器（libloader 6 处 "authentication" 全是 libcurl/SASL 噪声）

## 已确证调用链（bl_scan.cjs 全图验证）
HeadersInterceptor::onRequest(0xa3bdc8-0xa3c41c) → apiEncryptRpc 0x7eee0c（调用方 0x7e6d30/0x801f64/**0xa3c008**）→ 组 `{"action":"api_encrypt","payload":{"data":jsonStr}}` + 10 轮噪声对（0x715cb0×2/轮→0xaa9b20）→ json.encode → **0x6eeca8**（FFI 传输：List(2)[objstore 0x22a8 对象, jsonStr]）→ worker **0x643068**（16 调用方）→ FFI 闭包 `'__call@1037187772'`(pp+0x1b808，签名 (this, Pointer<Utf8>, NativeFunction)) → native 回调 `_FfiCallbackdartCallback` 0x715640 → 响应 Map → payload 六连写 headers（ts/authentication/x-version/tcs/nonce）

AES 本体（fn_0x6eed7c，encrypt 包）：AES-CBC+PKCS7+Base64。key/IV getter 桩（3 insn 形态 movz/movk/b）：0x7153f0(x2=0x014C411C)/0x715204(0x014C511C)/0x7151f8(0x014C921C)/0x6efa90(0x014C211C)/0x6437c4(0x018BB11C) → 共享 stub **0xbaaf38**；**0x715210 = Uint8List.fromList(utf8.encode(x))**（池内 Utf8Encoder@pp+0x380，bl 0xa37548；80 insn 截断，尾部 0x71534c-0x7153e8 未见）；池串 "qPwClBj7j7ZQraSm"(pp+0x1b838) / "p3JdVQl3q7WQJIgG"(pp+0x1b840) 作为 x2 与 getter 结果同传
- wrapper_0x6eed4c **0 个直接 bl 调用方** → 走分派表（疑 FFI 回调处理器）
- getter_key 0x7153f0 **8 调用点**；encrypt_0x6ef9ac **6 调用点**（6 个 AES 用户簇：0x6eeeb0=fn_0x6eed7c / 0x72cffc=FFIUtils::_loaderCall 0x72cf20 / 0x920e7c / 0x920f74 / 0xb97e88 / 0xbb4ce4）→ 全 app 共享同一静态 key
- **最高价值未读代码**：_FfiCallbackdartCallback 体内 0x715868-0x7158b0 簇（读 key+iv+utf8conv+aes_ctor 但不调 encrypt → 疑响应解密/Encrypter 构建）

## 已排除（全部阴性，勿重做）
- 裁决1 CBC（P_i=D(C_i)⊕C_{i-1}, i=2..6）×16 候选：utf8(S1/S2)/md5/md5hex/sha256/S1+S2/S2+S1/截16 全阴性（avg≈0.37=随机基线 95/256；2695 块）— judge_run.txt
- 裁决2 ECB ×13 候选（含 sha1hex32、8892 字符 blob "E5333...DDDDDD4333" hex 解码）全阴性（3234 块）— judge2_run.txt
- 裁决3 UTF-16（le/be 全长 32B + 截 16B）×CBC/ECB 共 16 组合全阴性
- 三个 .so 可打印串扫描 0 命中（key_string_sweep.cjs）；资产面 out/base_decoded/assets 扫描 0 命中（sweep_assets.cjs 后台 exit 0，产物未 Read 复核）
- 0x411c/0x511c/0x921c（及 8B 邻域）在全 .text **0 个直接 ldr/str**（scan_cell_writers.cjs）→ "x2 低位=cell 偏移"解码错误；key 走 0xbaaf38 间接表；stub 形态 = lazy 初始化 = **运行期值**
- **结论**：池串两值以任何已测形态（utf8/utf16le/be/md5/sha256/sha1/拼接/截断/blob-hex）都不是 key；key 是运行期值

## 下一步（按序执行）
1. 反汇编 stub **0xbaaf38**（~60 insn，仿 step_v14.sh 写 step_v15.sh）→ 解码 x2=0x014C411C 语义，确定 getter 返回什么
2. 补全 0x715210 尾部（0x71534c-0x7153e8，~40 insn）→ 查 x2 在尾部的用法（是否 fallback/变换）
3. 反汇编 0x715868-0x7158b0 簇（FFI 回调内 key/iv 消费点）
4. 静态穷尽后转动态：adb + frida/内存 dump 提取运行期 key 字符串（lazy 静态 cell 持有），把提取值代入 judge_candidates.cjs 的 cands 数组裁决
5. 命中后：全量解密 539 样本 → 确定明文排布与 padding → Phase 3：写 `authgen` 离线生成器（Node .cjs，AES-CBC+魔数+计数+base64 组装，新鲜 ts/nonce/path）→ 在线实测 200 → [F42] 审计追加 out/VERIFICATION.txt → 同步 Apipost 项目 6ef0f75d8470000

## 纪律（对抗回执污染，本会话实测有效）
- **Bash 回执会被部分伪造**（编造路径/文件名/内容，同一命令多回执互相矛盾）→ 永不信回执文本；每步用 Read 验证确定性产物路径（脚本内 `fs.writeFileSync(path.join(__dirname,'固定名'))` 落盘；或 `node x.cjs > 固定名 2>&1`）
- Write 回执可靠；Read 通道可靠（本会话 3 次用户 PowerShell 带外锚定）；对拿不准的产物可请用户带外 `Get-Item/Get-Content` 锚定
- 控制台 GBK 乱码 → 输出落盘再 Read
- 台账纪律：不重复已成功的读取/命令；未执行写「未执行」；禁止伪造哈希/偏移/HTTP 响应/验证结论
- AGENTS.md 全部规则生效（中转站 api.zxcbug.com 保护；激活词规则；进度播报 `当前进度：N%｜已完成：...｜下一步：...`）
- Dart AOT 速查：x27=PP/x26=THR/x22=NULL/x28=堆基(lsl#32 解压)/x15=SP；`ubfx x,[x-1],#0xc,#0x14` 取 cid；标记指针 `[x+0xb]`=base+0xc；巨态 `sub x30,x0,#base; ldr x30,[x21,x30,lsl#3]; blr`；基址 #0xfaf=headers map、#0xfff=sigMap、#0x350=int 方法区
