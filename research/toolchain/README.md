# research/toolchain/ — 分析工具

本目录是逆向分析的工具集：libcore.so 的 Unicorn 模拟器、运行时探针、
调用树追踪与反汇编工具。全部脚本通过 [`paths.py`](paths.py) 取路径。

## 模块一览

### 模拟器与驱动

| 文件 | 说明 |
|---|---|
| `paths.py` | **统一路径解析**（artifacts / toolchain / deliverables / captures / corpus / reports） |
| `emu_v11.py` | 基础模拟器：以真机基址 `0x400024a00000` 映射 libcore.so 并灌入数据段镜像；实现 libc 桩（`malloc`/`memcpy`/`__vsnprintf_chk` 等，含真实 va_list 展开） |
| `emu_v12.py` | 模拟器变体 |
| `emu_v14.py` | 在 `emu_v11` 基础上再加载全部 813 个设备 rw 区域（`authgen` 使用的引擎） |
| `v13.py` | 驱动：`collect` 收集缺页 / `dump` 拉取区域 / `run` 执行 / `auto` 迭代补区 |
| `dump_all.py` | 批量 dump 设备内存区域 → `artifacts/regions_all/` |
| `run_dump.py` | dump libcore 数据段 → `artifacts/libcore_dev_img.bin` |

### 探针与追踪

| 文件 | 说明 |
|---|---|
| `probe_D.py` | **受控实验主入口**，支持环境变量 `A1HEX` / `KEYHEX` / `IVHEX` / `TAG` |
| `probe_A/B/C/G/H/I.py` | 各阶段中间量 dump（A 编码器输入、E 的 key/iv、KSA 落地、入口实参） |
| `probe_ksa.py` | 抓取 `0x2cd8b0`（密钥相关 S 盒构造）的实参与产物 |
| `probe_xtime.py` | hook AES `xtime`（`0x2d2f0c`）并记录调用者 LR，用于定位轮函数 |
| `probe_regions.py` | **统计管线实际读取的设备内存区域** → 生成最小区域集 |
| `probe305.py` / `probe_stages.py` | 顶层生成器与管线各阶段取样 |
| `trace304.py` | 运行时逐指令追踪 `0x304eb0` 的调用树 |
| `trace_E.py` | 只追踪 E（`0x2d6f78`）内部调用树 |
| `trace_sbox.py` | 监视 S-box 内存读取，用于定位密码原语 |
| `dasm.py` | capstone 反汇编：`python dasm.py <so> <start_hex> <count>` |

### 密码学与爆破

| 文件 | 说明 |
|---|---|
| `sm4.py` | 纯 Python SM4（ECB/CBC），含 GB/T 32907-2016 标准向量自检 |
| `brute_E.py` | E 的算法爆破：AES 全模式 × 多组 key/iv × 多组明文，以及 SM4 |
| `try_custom_aes.py` | 参数化 AES（可换 S 盒），验证「AES 结构 + 自定义 S 盒」假设（140 组合，0 命中） |
| `hash_hypo.py` | 哈希假设验证（md5/sha1/sha256/sha512/sha3/blake2 组合） |

## 环境变量（`probe_D.py`）

| 变量 | 作用 |
|---|---|
| `A1HEX` | 强制指定送入 E 的 104 字节明文（十六进制） |
| `KEYHEX` | 覆盖 libcore 中的 AES key |
| `IVHEX` | 覆盖 libcore 中的 iv |
| `TAG` | 输出标签 |

## 常用命令

```bash
# 反汇编
./.venv/Scripts/python.exe research/toolchain/dasm.py research/artifacts/libcore.so 2dc524 130

# 受控实验：改一个字节看 E 的输出变化
TAG=flip A1HEX=$(python -c "print('41'*104)") \
  ./.venv/Scripts/python.exe research/toolchain/probe_D.py

# SM4 自检
./.venv/Scripts/python.exe research/toolchain/sm4.py
```

## 已确认无效的路径（勿重复）

- frida Interceptor 在 Houdini 翻译层下对 ARM64 代码无效（模块不可见）
- `emu_v14` 之外的**手工挑选**最小内存集不成立：只补字母表/密钥两块后管线立即 fault。
  正确做法是**统计实际读取**的区域（`probe_regions.py`），而不是猜
- 标准 AES / SM4 全参数空间对 E 均不成立（`brute_E.py`）
- 「AES 结构 + 自定义 S 盒」140 组合同样不成立（`try_custom_aes.py`）
- 哈希构造（md5/sha*/blake2 的各种组合）不成立（`hash_hypo.py`）
- `0x2d2f94` 等 PC 对 `0x701efc18` 区间的大量"读"是**栈访问噪声**，
  不是 S-box 读取（该区间与模拟器栈重叠）—— 监视 S-box 时要避开栈区
