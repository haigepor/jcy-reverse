# out/ — 分析工作区

逆向分析过程中的产出与脚本工作区。**入库部分**：脚本、客户端库、文档产物、样本数据；
**不入库部分**：解包目录、大二进制、截图（见根目录 `.gitignore`）。

## 入库内容

| 路径 | 说明 |
|---|---|
| `client/gg_client.py` | 离线 Python 客户端（监控/信令双通道解密已验证） |
| `client/gg_*.js` | Frida hook 脚本族（虚拟机插件/加密层/Java 探针/内存扫描） |
| `demo/index.html` | 离线验证页：hls.js 播放还原出的视频流 |
| `blutter_out/pp.txt` | Dart 对象池（2.6 MB，类/字符串全量） |
| `blutter_out/objs.txt` | Dart 对象导出 |
| `blutter_out/blutter_frida.js` | blutter 自动生成的 Frida 模板 |
| `API_ANALYSIS.md` | 静态+动态分析主文档 |
| `VERIFICATION.txt` | 两阶段审计链（验证记录） |
| `HANDOFF_PROMPT_V4.md` | 交接提示词（最新 V4） |
| `auth_samples.json` / `auth_full_rows.json` | 真机抓包样本（88 条）与分析结果 |
| `RSA_PUBLIC_KEY.pem` / `gg_rsa_pub.pem` | 提取的 RSA 公钥 |
| `gg_*.js` / `gg_*.py` | 加密/信令/内存/Ffi hook 脚本族（含迭代版本） |
| `cscan.c` / `authbrute.c` | C 分析工具源码（内存扫描 / 认证暴力测试） |
| `signkeys.txt` / `gmodels.txt` / `sm4_sbox.bin` | 密钥线索、模型列表、SM4 S 盒 |
| `http_*.tsv` / `lua_*.txt` | 抓包表格与 Lua 块分析 |

## 不入库内容（本地完整保留）

| 路径 | 体积 | 说明 |
|---|---|---|
| `base_decoded/` | 102 MB | apktool 完整解包 |
| `base_smali/` | 368 MB | 原始 smali |
| `base_smali_patched/` | 403 MB | 打过补丁的 smali |
| `base_nores/` | 395 MB | 无资源解包 |
| `jadx_src/` | 189 MB | jadx 反编译 Java 源码 |
| `blutter_lib/`、`blutter_out/asm/` | 51 MB | blutter 中间库与 1410 个 asm 文件 |
| `mem_dump.bin` | 178 MB | 进程内存转储 |
| `libapp_strings*.txt` 等 | 3.3 MB | so 字符串导出（可重新生成） |

## 复现要点

- 客户端验证：`python -c "import sys; sys.path.insert(0,'out/client'); import gg_client"`（见根 README 快速上手）
- 字符串导出重新生成：`out/strdump.py`（针对 `libapp.so` / `libcore.so`）
- 解包重新生成：`java -jar tools/apktool.jar d apk/base.apk -o out/base_decoded`
