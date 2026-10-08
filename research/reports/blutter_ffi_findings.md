# blutter_rt Dart 侧 FFI 分析（B 线）

> 2026-10-04。输入：research/artifacts/blutter_rt/（libapp.so AOT 反编译）、device_libs/*。
> 目标问题：响应 P1 的 E 解密在哪一层？

## 1. FFIUtils 全符号（asm/guoguo/utils/ffi_utils.dart，128 行全读）

| 方法 | 地址 | 大小 | 说明 |
|---|---|---|---|
| check | 0x6eeb1c | 0x18c | async |
| _rawCall | 0x6eeca8 | 0xa4 | 统一 FFI 调底层 |
| __call | 0x6eed7c | 0x200 | **async 核心**：Dart 侧用 encrypt 包 AES-CBC(qPwC) 加密信封 → b64 → native call@0x307a38 |
| dartCallback | 0x715844 | 0x144 | native→Dart 回调（0x30cce4 blr x8 的落点） |
| clearKey | 0x716b7c | 0x114 | 每请求前清 store |
| _loaderCall | 0x72cf20 | 0x22c | **走 libloader.so 的另一套 RPC**（closure #ffiClosure3 @0x72d4c8） |
| init | 0x747600 | 0x300 | |
| apiEncrypt | 0x7eee0c | 0x328 | |
| apiDecrypt | 0xabe058 | 0x35c | |
| loadSo | 0xbb71c0 | 0x9c | DynamicLibrary.open('libloader.so') |
| loadCore | 0xbb725c | 0xa0 | 加载 libcore |
| getCore | 0xbb72fc | 0x98 | |

- 两个 NativeCallback 类型均为 `(dynamic, Pointer<Utf8>) => Pointer<Utf8>`（0x715470/0x7482ac），
  印证 native 回调传 C 字符串（与 emu 实测一致）。
- completer/reloadCompleter 字段：__call 是 Future 异步闭环。

## 2. 关键字符串池（pp.txt）

- `[pp+0xca38] "libloader.so"`、`[pp+0xca58] "libcore.so"`、`[pp+0xca90] Type: DynamicLibrary`
  → FFIUtils 双库加载。
- `[pp+0x1dc10] "api_decrypt"`、`[pp+0x1dc38?] "api_encrypt"`（action 名在 Dart 侧引用）。
- `[pp+0x3bf18] "Can't decrypt without a private key, null given."` —— encrypt 包（RSA）错误文案，
  说明 Dart 侧存在 RSA 私钥解密调用点（响应 P0 解封可能在 Dart 或仅错误处理引用，未证实归属）。
- `[pp+0xbba8]` 起的大段 **Lua VM plugin 脚本**：`utils.aes128cbc_decrypt(key,iv,data,...)` →
  `vmplugin.invoke_method('utils_aes128cbc_decrypt', ...)` —— 播放解析 Lua 的 AES 能力走 native utils，
  标准 AES，与 E 无关。

## 3. 库角色判定（device_libs/ 实测）

| 库 | 大小 | 正S盒 | 逆S盒 | 自定义b64 | api_* 字符串 | 判定 |
|---|---|---|---|---|---|---|
| libloader.so | 0x5ef048 | 0x166690 | 0x166ce0 | 0x19b442 | 无 | BoringSSL+下载器；两表**零代码引用**（死数据/自带AES表） |
| libcore.so（=APK=运行中，md5 a0dc80256c） | 0x685c50 | 0x1dfc00 | 0x1e03b0 | 0x1e1c74 | 有 | E 加密宿主；逆表零代码引用（已定论） |
| libcore2.so（files/ 目录历史版本，md5 6f287a6490） | 0x68d308 | 0x1e1340 | 0x1e1a60 | 0x1e3144 | ？ | 与运行版差 +0x76b8；0x1ac66c/0x1ac684 的 adrp 双表命中**为字面量池假阳性**（后续指令解码为 SVE 乱码） |
| libapp_runtime.so | 0xbc03a0 | - | - | - | - | =libapp.so（APK 内 assets/libapp.so 同 md5 485401ee16） |
| libcore_runtime.so | 0x685c50 | 同 libcore.so | | | | 拷贝 |

- base_runtime.apk 的 libcore.so == device libcore.so == libcore_runtime.so（md5 一致）→ 运行版即 APK 版。
- libcore2.so 不在 APK，是 device files/ 目录的另一版本（疑为服务端热更新版本或旧版）。

## 4. 结论

1. **Dart 侧（libapp.so）没有 E 解密实现**：apiDecrypt 只是信封包装 + _rawCall 透传，
   transformResponse 的 Uint8List 闭包是流式接收（无分组密码查表结构）。
2. **libloader.so 没有 E 解密**：BoringSSL 字符串库 + S 盒零代码引用；无 api_decrypt。
3. 响应解密只可能在**运行中 libcore.so 内部**（native api_decrypt 真机已实证返回明文），
   被 store 状态门控 —— 与 A 线 emu 种子实验、C 线通道注入互补。
4. 热更新链路存在（loader 下载 libcore 版本、get_version/get_abi 动作、bootloader 字符串），
   libcore2.so 即证据；不排除服务端可下发"带解密版" libcore —— 离线破解应针对运行版 libcore。

## 5. 遗留

- pp+0x3bf18 的 RSA 私钥错误文案归属函数未定位（blutter 无交叉引用索引）；
  不影响主线（响应 P0 解封已可离线，priv_from_go.pem）。
- _loaderCall 的 libloader 侧 RPC 方法名未枚举（对 D-oracle 无关键影响）。
