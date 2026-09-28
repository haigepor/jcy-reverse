# 囧次元逆向 V4 交接提示词（模拟器 frida 部署完成 + spawn 工作流已验证）

## 一、任务背景与总目标链
目标 App：囧次元 com.tudou.tool v1.5.8.0（Flutter 3.27.x/Dart 3.6.0），工作区 C:\Users\haige\Desktop\instruct\囧次元。
总目标链：① 视频播放接口全链路分析 ② 登录逻辑分析 ③ API 加解密完整逆向 ④ 示例 HTML 页。
接口主体证据已齐（见第四节），本阶段：模拟器 frida 能力边界收尾实验 + 主线离线解密收尾。

## 二、模拟器环境现状（全部命令验证过，审计链 [F9][F10] @ out/VERIFICATION.txt）
- 雷电14：C:\leidian\LDPlayer14\，ldconsole=C:/leidian/LDPlayer14/ldconsole.exe；实例 0 运行中（540×960@240），Android 14 / API 34 / **x86_64 + libhoudini ARM 转译**（ro.dalvik.vm.native.bridge=libhoudini.so）；伪装机型 25102RKBEC/unicorn
- adb：项目自带 tools/platform-tools/adb.exe，设备名 **emulator-5554**（adb devices 自动发现）。**坑（本轮新发现）：adb server 会挂死**——症状：`adb devices` 只打印表头即永久卡住。修复：taskkill 僵尸 adb 客户端 + `adb kill-server` 重启 server，emulator-5554 自动恢复在线
- root：adbd already running as root（adb shell 直接 uid=0, context u:r:su:s0），SELinux **Permissive**——无需 su 前缀
- **frida-server 17.8.2 android-x86_64 部署完成**：
  - 文件：/data/local/tmp/fs（110754760B；源 /sdcard/Pictures/fs.gz 44009278B，md5 8f56e35cabaf8ecd8c5fb03482721ed8，与 PC 端共享文件夹 C:\Users\haige\Documents\leidian14\Pictures\fs.gz 一致；gunzip + chmod 755，--version 验证通过）
  - 启动（脱离式，PC 端无需挂后台任务）：`adb -s emulator-5554 shell "nohup /data/local/tmp/fs >/dev/null 2>&1 &"` → pidof fs 存活、监听 127.0.0.1:27042（netstat 复核）
  - 转发：`adb -s emulator-5554 forward tcp:27042 tcp:27042`（forward --list 已验证）
  - PC 端：Python 3.13.14 + frida 17.8.2 已装；`frida.get_remote_device()` 连通（95 进程；enumerate_applications 可见 com.tudou.tool）
- **frida 能力边界（out/fs_probe.py 实测，硬结论）**：
  1. **attach 运行中的目标进程超时失败**：frida.TimedOutError "unexpectedly timed out while waiting for stop"（重试同样；目标进程不崩）。原因推断（未确证）：attach 需停已运行的 houdini 转译线程
  2. attach x86_64 系统进程（com.android.systemui pid 552）→ OK
  3. **spawn 工作流全通**：dev.spawn(['com.tudou.tool']) → attach(pid) → create_script → load → resume 全部 OK，Process.arch=x64 / pointerSize=8
  4. **`Java` 未定义**：frida 17 移除内置 Java bridge，python create_script() 裸 runtime 没有 Java 对象——是 frida 17 行为，不是 houdini 故障。真机七轮 hook 脚本（out/gg_auth*_hook.js）全部纯 native、零 Java.* 依赖，思路可直接复用；若确需 Java 层：用 frida-tools CLI（自带 bridge）或 frida-compile 打包 frida-java-bridge
  5. spawn 注入时机在 resume 前，此时 libcore.so 尚未加载（findModuleByName=None 属正常）——脚本里可 hook x86_64 linker 的 android_dlopen_ext（linker 是原生 x86_64，Interceptor 可用）或 resume 后轮询
  6. **模拟器工作流结论：一律 spawn，不用 attach**。进程名在 enumerate_processes 里显示为 '囧次元'（中文，按包名/包名片段 grep 搜不到）；用 enumerate_applications 按 com.tudou.tool 定位 pid
- 诊断后现状：目标 app 未运行、frida-server 存活。frida-server 不自启，模拟器重启后需重跑 nohup 启动 + 重新 forward

## 三、下一步（按序执行）
1. **houdini 下 native hook 触发实验（下一轮核心，以 out/fs_probe.py 的 spawn 骨架起步）**：
   spawn com.tudou.tool → 脚本内 Interceptor.attach(Module.findExportByName(null,'android_dlopen_ext')) 记录 libcore.so 加载的 base → resume 后 Module.getExportByName('libcore.so','AES_set_encrypt_key')（真机 arm64 vaddr 0x3842ac；同一 .so 导出表一致）挂 Interceptor → 等 app 发 app_launch 请求 → 看 onEnter 是否触发
   - **预期：大概率不触发**（houdini 在 x86 转译代码缓存中执行 ARM 函数，ARM 字节不被 CPU 直接执行）——如实记录触发与否，不推测
   - 同时验证 Memory.readByteArray 直读 ARM 段（只读内存 dump 能力）作为模拟器兜底价值
   - 若触发：模拟器升级为 native hook 主力环境（重量级结论，改写第七节定位）
2. **Magisk（面具）安装尝试**：雷电14 官方正确做法是"取 boot.img→Magisk 修补→刷回"（vdi 镜像修补难度高）；先按 Magisk Delta APK 流程试（装 APK→App 内安装→关 root 重启→开 Zygisk 重启→可刷 LSPosed zygisk zip），失败如实记录，维持 adb root + frida-server 方案（对 native 逆向无损失）
3. **装抓包工具**：tools/PCAPdroid_v2.0.2.apk 装进模拟器（免 root VPN 抓包导出 pcap），抓 App 启动流量，验证模拟器上 auth=f(ts) 是否同构（跨设备性质验证）
4. **回到分析主线（第四节待办）**

## 四、分析主线：已确认结论（全部命令验证，勿推测推翻）
- 请求形态：GET http://43.145.33.254:27990/app/video/list?channel=N&sort=weight&limit=6&page=1，无 body；必需头 authentication(112B b64)/ts(毫秒)/nonce(8位)/appid=4150439554430529/tcs=2/x-version=2020-09-17；UA=Dart/3.6 (dart:io)
- 重放实测 3 拒：无 auth→30000 "authentication is empty"；旧 ts+旧 auth→403502 时间异常；旧 auth+新 ts→403501 签名校验失败 ⇒ 服务器把 auth 与 ts 绑定校验
- **推翻旧结论**：pcap 全流量无 new-token 头 ⇒ authentication 客户端本地生成（旧 docs/x-token.md 的"服务器签发回传"图景错误，待修正）
- auth = **f(ts) 精确确定性函数**（nonce/URI 无关；同 ms 两次请求 auth 相同，ts 差 2ms 密文即变）
- auth 结构 = 15B 恒定前缀 e8cb1f120ef5a42c59e22a4d00279e + 1B 代次(0x9c-0x9f) + 96B 密文；前缀跨会话恒定
- 架构：Dart 层 clearKey/apiEncrypt/apiDecrypt 全是诱饵循环（getRandomString 假 key）；真实数据 _rawCall(明文JSON含action/payload+诱饵键值) → libcore!call(qPwC AES-128-CBC 加密传输) → dartCallback 异步回调
- **auth 生成点**：apiEncrypt(action=app_launch 等) → libcore native → dartCallback 返回 {"code":200,"payload":{"authentication":"..."}}；ts 用 native 自己的时钟（输入里没有 ts）
- FFI 响应帧可离线解：**[16B IV][qPwC-CBC(JSON帧)]**，业务明文如 {"code":20000,"message":"请求成功!","data":{...}}
- 响应体 = P0b64.P1b64：**P0 恒 256B（RSA-2048），P1 恒 16 倍数（AES）**；部分端点（/app/messagebox/give_me、/app/danmu）返回明文 JSON
- **第七轮已从内存 dump 出 libcore 内嵌 RSA-2048 密钥对**（out/auth_rt7_log.jsonl 的 bn_n/bn_e/bn_d/bn_p/bn_q 字段）：响应解密私钥 n=27c80694...（d/p/q 全套，e=010001）；请求加密公钥 n=0d96232c...。RSA_private_decrypt(P0) 输出 = 16 字节 ASCII 会话密钥（如 "SPQ8P5DFA7GRRXK3"，与第二轮堆中 4 个 16 字符串同格式）
- 待办：**用该私钥离线解 pcap 列表响应的 P0→会话密钥→P1**（out/ggcap.pcap stream 11/13/15 有 list 响应，P0b64.P1b64 按 '.' 分割）；auth 96B 算法仍未破（libcore/libapp 全滑窗 AES-128/256 CBC/ECB 双样本 oracle 暴力 0 命中，见 out/authbrute.c；运行时抓到的随机 16B 密钥 286 个也解不开——native 内诱饵密钥混淆，真身待反汇编 call@0x307a38）；新鲜 auth+ts 秒级重放实验；docs/ 与 out/API_ANALYSIS.md 修正同步；out/VERIFICATION.txt 追加审计链

## 五、工具与产物清单（关键）
- 抓包/头数据：out/ggcap.pcap、out/auth_full_rows.json（28 条完整请求头+auth hex）、out/resp_bodies.tsv
- hook 脚本与日志（真机轮次）：out/gg_auth4/5/6/7_hook.js + 对应 driver.py；out/auth_rt4~7_log.jsonl；out/dart_log.jsonl、out/ffi_log*.jsonl（早期）
- 离线暴力：out/authbrute.c/.exe、out/auth_samples_hex.txt（26 个 auth 样本）
- native：out/nativelibs/libcore.so（6.8MB，完整 OpenSSL 构建 11579 导出）、libapp.so（12MB）；out/blutter_out/（Dart 反汇编，addr=vaddr=file offset）
- 模拟器侧：模拟器 /data/local/tmp/fs（frida-server 17.8.2 x86_64，已部署验证）、tools/PCAPdroid_v2.0.2.apk、apk/base.apk（原版 43MB）；探针脚本 out/fs_probe.py（spawn 工作流骨架，直接改）
- 文档：docs/（docsify 站）、out/API_ANALYSIS.md、out/VERIFICATION.txt（审计链 [F1]~[F10]）、out/HANDOFF_PROMPT_V2.md / 本文件 V4

## 六、已知坑（务必遵守）
- **adb server 挂死**（本轮新发现）：devices 只打印表头即卡住 → taskkill 僵尸 adb 客户端 + adb kill-server 重启
- 模拟器：adb push 极慢 → 共享文件夹 C:\Users\haige\Documents\leidian14\Pictures（映射 /sdcard/Pictures）；GitHub 直连 reset → gh-proxy.com；adb 需 `adb root`（本轮 adbd 已常驻 root）；ldconsole modify 改配置后需 quit+launch；同机跑雷电9+14 会抢 5555；**frida attach 运行中 houdini app 必超时 → 一律用 spawn**；frida-server 不自启，重启模拟器后需重新 nohup 启动 + 重新 forward；目标进程名是 '囧次元' 非包名
- 真机（华为 LLD-AL20，adb=37KRX18825013759）经验：gadget 每进程一轮 script，需 am crash→am start→sleep 25→attach('Gadget')（add_remote_device('127.0.0.1:27042')）；EMUI 弹窗坐标：不再提示(110,2030)、继续使用(281,2150)、继续安装(540,2040)/(823,2150)；frida send 第二参数只能 ArrayBuffer；Dart 对象：tagged 指针末位 9、OneByteString len u32@+7(Smi=len<<1) data@+15、FFI Pointer 对象的 native 指针在 x1+7；blutter asm addr=ELF vaddr=offset（交接旧清单部分地址是 dump offset，需 +0x4b6b40）；观测 base=0x723a521000；gadget 版 frida 的 NativePointer 无 toInt()，用 toInt32() 或 parseInt(p.toString(16),16)
- **frida 17 无内置 Java bridge**：python create_script() 无 Java 对象；项目 hook 脚本均纯 native 不受影响
- libcore 内字符串全混淆（qPwC/kFGT/prefix15 均搜不到，含单字节 XOR）；'authentication' 仅 1 处明文（OpenSSL 内部 OID 字符串，无关）
- 关键地址（真机 libapp，vaddr）：Encrypter.encrypt=0x6ef9ac、TokenInterceptor.onRequest=0xa3bc20、HeadersInterceptor.onRequest=0xa3bdc8、apiEncrypt=0x7eee0c、apiDecrypt=0xabe058、_rawCall=0x6eeca8、dartCallback=0x715844、HttpClient.post=0x6ca174；libcore：call=0x307a38、AES_set_encrypt_key=0x3842ac、RSA_public_encrypt=0x43e30c、RSA_private_decrypt=0x43e324

## 七、环境选型参考结论
- 抓包：PCAPdroid（免 root、VPN 本地抓包、导出 pcap）最契合本项目（API 是明文 HTTP，无需 MITM CA）；Charles/HttpCanary/mitmproxy 对本项目加解密无增益（P0.P1 是应用层加密，与 TLS 无关）；Flutter 自带 BoringSSL 不信系统证书，常规代理抓 HTTPS 无效
- 解密：真主力是 frida hook libcore（真机已打通七轮，纯 native）；模拟器 spawn 注入工作流已验证可用，native hook 触发待实验（第三节 1）；Magisk 模块选型：MagiskFrida（frida-server 开机自启）> Shamiko > LSPosed/JustTrustMe（Java 层，对 Flutter native 加密无用）
- 模拟器定位：x86_64+houdini 可跑 App、可抓包、frida spawn 注入可用、Java 层需外挂 bridge；arm64 native hook 触发能力待实测（第三节 1），真机仍是 native hook 主力环境

## 八、风格要求（用户既定规则）
每一步以命令输出为准、不推测；完成后向 out/VERIFICATION.txt 追加审计链（格式沿用现有 [F*] 条目，当前至 [F10]）；交付文件完整无 stub；hook/探针脚本一律放 out/；文档改动同步 docs/ 与 out/API_ANALYSIS.md 两处。
当前第一句话回复请从 **"houdini native hook 触发实验"**（第三节步骤 1）开始执行，不要重复询问环境状态。
