# SO 文件加密/解密 — 技术资料调研 + GitHub 工具对比 + 可行性分析

> 调研时间：2026-10-08
> 主题：Android `.so` 文件的加密保护方案，及其对应的解密/脱壳工具链
> **说明**：用户提供的掘金原文 `https://juejin.cn/post/7638465686507601972` 已返回 404（页面被删或需登录），
> 无法直接读取其场景描述。因此本报告按「SO 加密/解密」这一主题做了**全覆盖分档调研**，
> 并给出**分档判定法**，便于与链接场景对号入座。所有结论均标注了来源与验证状态。

---

## 0. 结论速览（TL;DR）

| # | 结论 | 依据 |
|---|---|---|
| 1 | 现有开源工具链**只覆盖「档 1 整体加密」和「档 2 段加密」**；对「档 3 函数级/不固定位置加密」只能部分命中，对「档 4 VMP/自定义 Linker + 反 dump」基本无效 | §3 工具能力矩阵 |
| 2 | 工具失效的三个硬原因：**① 解密结果不写回原址（新分配内存 + 改写 GOT/函数指针）；② 抹头移表（phdr/`.dynamic`/`.dynsym`/`.dynstr` 被移走）；③ 二次加密 + 运行时自校验** | §4.2 |
| 3 | 唯一能绕开「dump 不出来」的技术路线是**模拟执行**（unidbg / Unicorn），不脱壳直接调用目标函数 | §4.4 |
| 4 | 若场景是「整体加密 / 段加密」→ 工具链开箱可用，半小时内出结果；若是「函数级/自定义 Linker」→ **必须自研脚本**，靠「逻辑特征锚点 + 抓写内存 + 早期 dump」 | §4.3 |
| 5 | **对本项目（囧次元）而言，这套工具链不适用** —— `libcore.so` 是结构完整的明文 ELF，没有壳可脱；难点在自研分组密码 `E` 的算法还原 | §5 |

---

## 1. 场景拆解：SO 加密一共有哪几档

这是全部后续讨论的坐标系。**先定位档位，再选工具**，否则会白做。

| 档 | 加密粒度 | 解密时机 / 方式 | 典型实现 | 内存 dump 是否有效 |
|---|---|---|---|---|
| **档 1** | 整个 SO 文件 | 加载前解密 → 写临时文件 `dlopen` / 自定义 loader 加载 | SO 加密后藏进 assets 或图片尾部（魔数 + 长度 + 密文），RC4/AES 整体加密 | **极易**。解密后内存里就是一份完整明文 SO |
| **档 2** | 段级（`.text` 或自定义 section） | `.init_array` 构造函数 或 `JNI_OnLoad` 内**一次性解密回原址** | XopProtector 式 `.text` RC4 等长加密；有源码/无源码加密 section | **容易**。在解密函数 `ret` 处断点，或在内存写钩子里抓 |
| **档 3** | 函数级 / 不固定位置 | 按需解密；解密结果**写到新分配内存**并改写 GOT / 函数指针；可能二次加密 | 随机偏移读密文、多层解密、指令膨胀 | **难**。整体 dump 得到的是密文或混合态；需特征定位 + 逐函数抓 |
| **档 4** | SO 级 VMP / 自定义 Linker | 自定义 linker 解密 + 映射 + 重定位；**抹 ELF 头、抹重定位表、移走 phdr/`.dynamic`/`.dynsym`/`.dynstr`** | 360 加固式「壳 SO 内嵌主 SO」、packed SO（替换 soinfo） | **整体 dump 基本失效**。必须「分段 dump + 在重定位修复前 dump」或放弃静态 |

> 来源：CrackSo README 的「SO 壳发展历程 / 常见加壳思路」（1~9 条）、《SO层不固定位置动态加密的逆向分析方法与实战》、kanxue 287254、博客园 revercc 17113730。

---

## 2. 技术资料文档（分类清单）

### 2.1 原理 / 入门

| 资料 | 关键内容 |
|---|---|
| [Android NDK（四）so 库的加解密实现](https://juejin.cn/post/6917496512201113607) | 两种加密方案：① 动态加载（SO 加密后放 assets/服务器，加载前解密，可瘦身但流程复杂）；② 就地加密（放 `lib/`，`System.loadLibrary` 后解密，工程目录不变、加载快） |
| [Android SO 文件保护加固——加密篇（一）](https://blog.csdn.net/feibabeibei_beibei/article/details/51498285) | 基于源码的 SO 保护：把关键函数放进自定义节并加密 |
| [SO 文件加固技术详解：ELF 加密、自定义 Linker 加载与 SO 级 VMP](https://dun.163.com/news/p/49b0789470eb45e983951aed431dbd20) | 网易易盾视角的三层拆解：整体加密 → 自定义 Linker → SO 级 VMP |
| [Android APK 加固原理（五）：SO `.text` 段加密、ELF 加载与运行时动态解密](https://juejin.cn/post/7680581898922082346) | `.text` 段 RC4 等长加密 + ELF 加载流程 + 运行时解密完整链路 |

### 2.2 脱壳 / 实战

| 资料 | 关键内容 |
|---|---|
| [一文搞懂 SO 脱壳全流程：识别加壳、Frida Dump、原理深入解析](https://cyrus-studio.github.io/blog/posts/一文搞懂-so-脱壳全流程识别加壳frida-dump原理深入解析/) | **本主题最完整的一篇**。判断依据、`frida_dump` 用法、`SoFixer` 修复、**`solist`/`soinfo` 定位原理**（含 frida-gum 调用链 `gum_android_enumerate_modules → gum_enumerate_soinfo → gum_linker_api_get`） |
| [SO 层不固定位置动态加密的逆向分析方法与实战](https://blog.csdn.net/weixin_28715953/article/details/166977851) | **档 3 的权威方法论**。「位置不固定」的本质、三条定位路径（静态 init_array/JNI_OnLoad → GDB 硬件写断点 → Frida hook `memcpy` 抓写内存）、特征定位法、自动化脚本、避坑清单 |
| [APP 加固分析之内存 dump 修复 so、JNI_OnLoad、动态注册](https://zhuanlan.zhihu.com/p/599065643) | dump 修复固定流程 + 断点 linker 执行 init 的时机拿真实函数地址 |
| [初试 so 文件解密](https://zhuanlan.zhihu.com/p/165097792) | 看雪 2W 班习题：单个 native 函数加密的还原 |
| [Android so 层解密分析](https://bygeee.github.io/2025/03/23/android%20so%E5%B1%82%E7%AE%80%E5%8D%95%E5%88%86%E6%9E%90/) | `JNI_OnLoad` 内指向的变量加密态 → 动态还原 |

### 2.3 加固实现 / 对抗（加固方视角，用于反推）

| 资料 | 关键内容 |
|---|---|
| [自定义 Linker 与 SO 加固技术（kanxue 287254）](https://bbs.kanxue.com/thread-287254.htm) | 完整 Linker 源码剖析：`do_dlopen → find_library → CallConstructors`；**`DT_INIT`/`DT_INIT_ARRAY` 是标准脱壳点**；只读 Program Header 不读 Section Header（这就是「抹头」能骗过 IDA 的根因）；只取**第一个** `PT_DYNAMIC`（可加多个迷惑 IDA）；作者给出自定义 Linker 组件划分（ElfReader/MemoryManager/SoinfoManager/Relocator）+ 把主 SO 用 RC4 藏在 `ic_launcher.webp` 后面 |
| [自实现 linker 加固 so 防 dump](https://www.cnblogs.com/revercc/p/17113730.html) | **反 dump 的具体手段**：抹 ELF 头（加载后无用）、抹 `.rel.plt/.rela.plt/.rel.dyn/.rela.dyn`（重定位后无用）、移走 phdr/`.dynamic`/`.dynsym`/`.dynstr`（并修复 soinfo 内对应虚址）。作者明言：仍可**分段 dump 组合**，或在**重定位修复之前 dump** → 所以需加反调试 |
| [关于 SO 加密对抗的两种实现方式（kanxue 285650）](https://bbs.kanxue.com/thread-285650.htm) | 两种加密实现方式的对比 demo |
| [记录学到的三种 so 加固方式（kanxue 286878）](https://bbs.kanxue.com/thread-286878.htm) | 三种加固方案的动手实现 |
| [Android Linker 加固实战：自实现 RC4 加密与 ELF 内存修复](https://blog.csdn.net/weixin_29315569/article/details/162161537) | 加固 + 修复双向完整实现 |

### 2.4 关联主题

| 资料 | 关键内容 |
|---|---|
| [ELF 二进制字符串加密的逆向](https://brszzz.github.io/2026/06/23/ELF二进制字符串加密的逆向/) | 逆向自定义**双 pass 流密码**字符串加密（含完整性锚点）——与「自研密码算法还原」同类问题 |

---

## 3. GitHub 工具 / 项目 / 脚本清单

### 3.1 脱壳 / 修复（防守反制侧）

| 项目 | 语言 | 作用 | 覆盖档位 | 维护状态 | 备注 |
|---|---|---|---|---|---|
| [F8LEFT/SoFixer](https://github.com/F8LEFT/SoFixer) | C++ | 修复内存 dump 的 SO：重建 shdr / phdr / 重定位 | 1、2 | 2021-05 最后提交 | 事实标准；README **自承重定位表解析有已知 bug** |
| [SeeFlowerX/frida_dump](https://github.com/SeeFlowerX/frida_dump) | Python + Frida | 遍历 `solist`/`soinfo` dump so/dex；支持 **spawn / attach / 无注入（SIGSTOP + 读 maps + 算 solist 地址 + 遍历 soinfo 链表）** | 1、2、3（按模块） | 2024-04 仍在修 | 无注入模式仅 64 位、需 root、不需 Frida |
| [lasting-yang/frida_dump](https://github.com/lasting-yang/frida_dump) | Python + Frida | 前身项目，常与 SoFixer64 搭配 | 1、2 | 2019 | 大量教程以此为准 |
| [maiyao1988/elf-dump-fix](https://github.com/maiyao1988/elf-dump-fix) | C++ | dump + 修复 + 重建 Section Header | 1、2 | 2026-04 有更新 | 可作 SoFixer 的替代/补充 |
| [SCUBSRGroup/CrackSo](https://github.com/SCUBSRGroup/CrackSo) | C | 针对「第 2 代壳（so 本地加密型）」的通用脱壳：头部修复 → 段地址修复 → 重定位节修复 → 重建节头 → 清除壳入口 | 2 | 2018 停更 | README 的**加壳思路 9 条 + 脱壳思路 4 条**是很好的分类学参考 |

### 3.2 加固实现（攻击侧参考 / 教学 demo）

| 项目 | 语言 | 作用 | 档位 |
|---|---|---|---|
| [BiteFoo/SoProtect](https://github.com/BiteFoo/SoProtect) | Python + C | Python 加密 SO，C 侧动态解密调用 | 1 |
| [SoyBeanMilkx/soLoader](https://github.com/SoyBeanMilkx/soLoader) | C++ | 自定义动态链接器，加载并运行 SO | 1 |

### 3.3 模拟执行（不脱壳直接调）

| 项目 | 语言 | 作用 | 备注 |
|---|---|---|---|
| [unidbg](https://github.com/zhcom888/app-so-unidbg)（及上游） | Java | 基于 Unicorn 在纯 Java 环境加载运行 Android/iOS native 库 | **唯一能绕开「dump 不出来」的路线**；本项目实际用的就是 Unicorn 同源方案 |
| [frida-gum](https://github.com/frida/frida-gum) | C | `Process.enumerateModules()` 的底层：`gum_android_enumerate_modules → gum_enumerate_soinfo → solist` 遍历 | 理解 dump 定位的关键 |

### 3.4 工具索引 / 综合工具箱

| 项目 | 说明 |
|---|---|
| [h00klod0er/awesome-android-re](https://github.com/h00klod0er/awesome-android-re) | Android 逆向工具 / 脚本 / Frida gadget / MCP server 精选清单（2026-09 更新） |
| [lxyjyy/android-reverse-tools](https://github.com/lxyjyy/android-reverse-tools) | 安卓逆向工具汇总 |
| [fok777/artoolkit](https://github.com/fok777/artoolkit) | 安卓逆向工具箱（APK 分析等） |
| [wqzhellohhwy/so-rev-mcp](https://github.com/wqzhellohhwy/so-rev-mcp) | 通用 ARM64 SO 逆向 MCP 自动化服务框架 |

---

## 4. 对比分析

### 4.1 能力矩阵（工具 × 档位）

| 工具 | 档 1 整体加密 | 档 2 段加密 | 档 3 函数级/不固定位置 | 档 4 VMP / 自定义 Linker + 反 dump |
|---|---|---|---|---|
| `frida_dump`（两版） | ✅ 开箱 | ✅ 开箱 | ⚠️ 只能按模块 dump，需自行定位/逐函数抓 | ⚠️ 抹头移表后 dump 出来无法被 SoFixer 修复 |
| `SoFixer` / `elf-dump-fix` | ✅ | ✅ | ⚠️ 若 dump 的是混合态则产出不可用 | ❌ 依赖 phdr/`.dynamic`/`.dynsym`，被移走即失败 |
| `CrackSo` | ✅ | ✅ | ❌ | ❌ |
| 手工 Frida hook `memcpy` + 特征扫描 | ✅ | ✅ | ✅ **唯一有效** | ⚠️ 需配合早期 dump |
| GDB/IDA 硬件写断点 | ✅ | ✅ | ✅ | ⚠️ 需配合反调试绕过 |
| unidbg / Unicorn 模拟执行 | ✅ | ✅ | ✅ | ✅ **绕开脱壳**（但需补环境 + 遇 OLLVM/VMP 时指令量巨大） |

### 4.2 工具为什么会失效（三个硬原因）

1. **解密结果不写回原址。** 档 3 会把明文写到**新分配的内存**并改写 GOT / 函数指针。此时「dump 整个模块范围」拿到的是密文，而明文在模块外的一块匿名内存里 —— 你根本不知道 dump 哪。
2. **抹头移表。** 档 4 在加载后抹掉 ELF 头与重定位表、把 phdr / `.dynamic` / `.dynsym` / `.dynstr` 移到别处。而 `SoFixer` 这类修复工具**恰恰靠这些结构**重建链接视图 → 输入残缺，直接失败。（Android linker 只读 Program Header，所以抹掉 Section Header 完全不影响 App 运行，只影响 IDA。）
3. **二次加密 + 自校验。** 有的加固在解密函数返回后、正式执行前再对已解密代码加密/膨胀；另有对自身关键字节做哈希校验、发现被改即退出。导致「抓早了是密文、抓晚了已被改回」。

### 4.3 可行性判定

| 若链接场景属于 | 可行性 | 推荐动作 | 预计成本 |
|---|---|---|---|
| 档 1 / 档 2 | **高**，接近开箱即用 | `frida_dump` → `SoFixer -m <base>` → IDA 打开 | 半小时内 |
| 档 3 | **中**，需自研 | 静态找 `init_array`/`JNI_OnLoad` → Frida hook `memcpy`/解密循环，判断目标地址是否落在 SO 模块范围 → 在**解密函数 ret 处**dump 全段 → 特征扫描补漏 | 数小时～数天 |
| 档 4 | **低**（静态路线基本无解） | ① 在重定位修复**之前** dump；② 分段 dump 后自行重组；③ 绕过反调试；④ **转模拟执行**直接调函数 | 数天～数周 |

### 4.4 推荐的组合路线（按优先级）

1. **先判定档位**（见 §4.5），不要上来就 dump。
2. 档 1/2：`frida_dump --spawn` → `SoFixer` → IDA。
3. 档 3：`frida_dump` 只用来拿 base/size；核心用自写 Frida 脚本 —— hook `memcpy`/`mprotect`/解密循环，**筛出写入目标落在 SO 范围内的调用**，在解密函数返回处 dump 整段；再用**特征定位法**（预先拿到的明文指令特征，≥8 字节）在内存里 `Memory.scan` 补漏。
4. 档 4：放弃「dump 出完整 ELF」的执念，改用 **unidbg/Unicorn 模拟执行**目标函数；或按博客园 revercc 的思路在**重定位修复前**dump。
5. 所有档位都建议：dump 后立刻 `Memory.protect(..., 'r--')` 防止被二次加密覆盖。

### 4.5 分档判定法（原文 404，用它自行对号）

| 观察点 | 档 1/2 | 档 3 | 档 4 |
|---|---|---|---|
| IDA 打开 SO | 正常或仅 Section Header 异常 | 正常 | **报「无法识别 ELF」/ section 定义无效 / 大量红色汇编** |
| 是否有第二个「壳」SO | 可能 | 可能 | **大概率有**（主 SO 内嵌在壳 SO 或资源文件里） |
| `readelf -l` 看 PT_LOAD | 正常 | 正常 | **异常**（自定义 linker 才认的布局） |
| 加载后内存里搜明文指令特征 | 能搜到 | 只能按函数搜到 | 搜不到 |
| dump 后 IDA 能否打开 | 能（修复后） | 能但代码是混合态 | 不能 |

---

## 5. 落到本项目（囧次元）的映射 —— 一个重要的「不适用」结论

本项目 `research/artifacts/` 下两个 native 库的实际形态：

| 文件 | 实际状态 | 对应档位 |
|---|---|---|
| `libcore.so` | 6.8 MB，**结构完整、可被 `readelf` 正常解析的明文 ELF**（`.dynsym`/`.dynstr`/`.rela.dyn`/`.rela.plt`/`.text`/`.rodata` 齐全），11,334 个导出符号，OLLVM 混淆 | **无壳**。加密是**算法级**（自研分组密码 `E`），不是文件级 |
| `libloader.so` | 提供 `reload` 热更新入口 + `JNI_OnLoad` | 加载器，非加密壳 |

**结论：本次调研的整条工具链对本项目不适用。** 原因：

- 没有壳要脱 —— `libcore.so` 本身就是明文 ELF，`SoFixer`/`frida_dump` 解决的问题（dump 后重建 ELF）在这里不存在。
- 本项目真正的难点是**算法还原**：还原自研分组密码 `E`（`E(x) = T(SR(SB(AES9(T(x) ⊕ rk0)))) ⊕ C(K)`）及其分组模式中的 tweak 常量 `CONST_b`，使响应解密不再需要每次重新标定。
- 本项目实际走的是**模拟执行路线**（Unicorn，与 unidbg 同源）——这正是 §4.4 里对「档 4」推荐的兜底方案，且已在本轮取得突破：`libcore.so` 的 `call` 导出（`0x307a38`）已在模拟器内完整跑通，回调返回 `base64(AES-128-CBC-PKCS7(json))`，即**单次原生调用即可完成一次 API 加解密**。

> 即：本项目遇到的不是「SO 加壳」问题，而是「SO 内部自研密码算法」问题。调研得到的工具链（SoFixer 等）解决前者，对后者无帮助；真正可复用的是**模拟执行 + 特征锚点定位**的方法论。

---

## 6. 未完成项 / 证据缺口

| 项 | 状态 | 说明 |
|---|---|---|
| 读取掘金原文 `7638465686507601972` | **未执行成功** | 返回 404（页面已删或需登录）；搜索引擎按文章 ID 检索亦无命中 |
| 确认链接场景具体属于哪一档 | **未确认** | 原文不可读 → 改为提供 §4.5 分档判定法，供自行对号入座 |
| 未实际下载/运行任何 GitHub 工具 | **未执行** | 本轮为资料调研，未做工具实测；上表「覆盖档位」为基于 README 与源码结构的推断，非实测结论 |
| `awesome-android-re` 完整清单 | **部分** | 该页 WebFetch 未取到正文，工具清单来自搜索结果摘要 |
| `elf-dump-fix` / `so-rev-mcp` 的细节 | **未展开** | 仅取到项目描述，未读源码 |

**下一步可复现动作**（若需要把调研变成实测）：

```bash
# 1) 取 base/size 并 dump（需 root + frida 环境）
git clone https://github.com/SeeFlowerX/frida_dump && cd frida_dump
python -m frida_dump.dump_so --spawn -n <包名> <目标.so>
# 2) 修复（64 位）
git clone https://github.com/F8LEFT/SoFixer && cd SoFixer
mkdir build && cd build && cmake -DSO_64=ON .. && make
./sofixer -s <dump>.so -o <dump>.fix.so -m <base> -d
# 3) IDA 打开 <dump>.fix.so；若失败 → 说明落入档 3/4，转 §4.4 路线
```
