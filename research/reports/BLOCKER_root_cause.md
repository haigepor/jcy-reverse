# C 转译引擎 差分 — 根因定位与通过记录

日期: 2026-10-06
执行: 接手 V18 交接，推进「最后一公里」

## 一、本轮已完成并验证的修复

### 1. 交接单里的 3 个待办补丁（全部落盘）
| 补丁 | 内容 | 状态 |
|---|---|---|
| a | `main.c`: `cur[8192]`→`cur[65536]`（P1 越界）+ `argv[8]` 可选明文文件装填 + 长度校验（P0 真明文静默出错） | ✅ |
| b | `gen_engine.py`: cover 并入 `pc_cover_multi.txt`（实测 25018 条闭包，multi ⊃ all，独有 408） | ✅ |
| c | DISPATCH 里 `curtrc.raw` 每 4096 条全量重写 = **O(n²)**，是 900s 超时真凶 | ✅ 已移除 |

重生成确认：`cover: 24984 + pc_cover_multi 独有 34 = 25018`，`生成 25018 / 25018, 未实现 0`。

### 2. 审计子代理 B 的 4 个 P0 + 2 个 P1（全部修复并验证落位）
| # | 位置 | 问题 | 验证 |
|---|---|---|---|
| B-001 P0 | `gen_engine.py` ubfiz | 实现成了 bfi（保留旧值）。UBFIZ 是 LSL 别名须清零 | `L_2d80cc` 现为 `((X[11]<<7)) & 0x80` ✅ |
| B-002 P0 | 逻辑立即 (and/orr/eor/bic/orn/eon) | 把 32 位掩码强行复制到高 32 位。`and x21,x25,#0xff` 用了 `0xff000000ff` | `L_2cdb18` 现为 `X[25] & 0xffULL` ✅ |
| B-003 P0 | NEON `.8b`/`.16b` | 只用 n1，n2 被丢弃；d==n1 时退化成恒等操作 | 两源都参与 ✅ |
| B-004 P0 | `op_shift` | **capstone 5.0.7 没有 `ARM64_SFT_SXTW/UXTW` 常量**（只有 INVALID/LSL/MSL/LSR/ASR/ROR），`sxtw` 被整个吞掉变零扩展。3 条 PC | 改为从 `ins.op_str` 文本检测，`L_2d9360` 现为 `(int64_t)(int32_t)` ✅ |
| B-005 P1 | `csneg` | 真分支也取了负。ARM64 是 `cond ? Rn : -Rm` | `L_2ce2b4` 已改 ✅ |
| B-006 P1 | `tst` | 未清 C/V（TST = ANDS Rd=31 别名，须 `::'00'`） | 已加 `FLG_C=0; FLG_V=0` ✅ |

**修复效果（实测）**：`heap exhausted` 消失。此前 malloc 收到 `size=0xf00000030` 这种垃圾 64 位值，正是 sxtw 符号扩展丢失 + 逻辑立即掩码错误共同导致。`HEAP-EXHAUST` / `BIGMALLOC` 计数器已加（全局 `g_nalloc/g_nbytes/g_nbig`），1 块执行全程 **0 次堆耗尽、0 次超大分配**。

## 二、诊断工具自身的两个 bug（交接单没提，是本轮新发现）

### 1. 对拍基准必须用 `reports/ref_trace_1blk.txt`，且它的 hook 范围必须是 `DB..DB+0x800000` ⚠️⚠️ 最易踩的坑

我第一版 `gen_ref_trace.py` 把 hook 范围写成 `DB..DB+0x400000`，产出 2,153,688 条的 `ref_trace_1blk.txt`（body 与 golden1 一致，看起来没问题）。用它对拍会报**「首个发散 idx 1085」** —— 假象。

用 `DB..DB+0x800000` 重生成后是 **2,180,018** 条（与 so 段映射 size=0x800000 一致），idx 1085 两侧**完全相同**（都是 `0x60c838`）。

**教训：body 逐字节一致 ≠ trace 一致。** 基准的可信度必须靠**在多个 idx 上交叉验证**（至少同时验证：长度、首 1000 条、已知分叉点两侧后继分布），不能只看 body 32 字节相等。已修正 `gen_ref_trace.py` 并在注释里写明原因。

### 2. `static` 计数器在宏展开处各是独立副本
`gen_engine.py` 的 DISPATCH 宏内 `static unsigned long long __mn;` 会展开 25018 份（每个 label 一份），`MALLOC#12` 这个计数**完全无效**。已改为 main.c 全局计数。

## 三、真正的首个发散点：idx 252879（用正确基准 2,180,018 条）

```
ref  [252878] 0x2d8870  br x8
ref  [252879] 0x2d8a64  ← Python 侧
c    [252879] 0x2d8874  ← C 侧（顺序走到下一条分支表项）
```
前 252,878 条两侧**完全一致**。

判定依据（`0x2d8870` 的后继分布）：
- Python 侧：5 个不同后继（`0x2d8a64` / `0x2d28a8` / …）
- C 侧：单一后继（恒定 `0x2d8874`）

### 根因 #1（已修）：`STUB_MALLOC` 尺寸公式与 Python 侧不一致

`main.c` 原写 `c_alloc((a0 ? a0 : 0x20) + 0x20) + 0x10`，Python 侧 `emu_v11.py` 是 `self.alloc(max(size, 0x20) + 0x20) + 0x10`。
`0 < a0 < 0x20` 时前者不补 `0x20` → **堆布局错位** → `std::vector` 类结构里存的堆指针差 **0x120**。

实测证据（`0x2d8820 ldr x9,[x21,#8]`，X21 两侧相同）：
```
ref  读出 0x50001140
c    读出 0x50001020     差 0x120
```

修法：
```c
uint64_t __sz = (a0 > 0x20ULL) ? a0 : 0x20ULL;
ret = c_alloc(__sz + 0x20) + 0x10;
```

**教训：桩函数必须与 Python 侧逐位对齐，不能凭直觉写「看起来等价」的形式。** `max(x,0x20)` 和 `x ? x : 0x20` 在 `0<x<0x20` 区间不等价。

### 根因 #2（已修）：`msub` 减法方向反了 ⚠️

ARM64 `MSUB Xd, Xn, Xm, Xa` → **`Xd = Xa - Xn*Xm`**，减数在**左边**。这是编译器求余的惯用法（`x/a` → `x - (x/a)*a`）。

`gen_engine.py` 原实现与 `madd` 同构（`Xn*Xm + Xa`），写成了 `Xn*Xm - Xa`：

```python
# 错
out.append(wr(rn(0), "(uint64_t)((uint64_t)(%s)*(uint64_t)(%s)-(uint64_t)(%s))"
                    % (rd(rn(1)), rd(rn(2)), rd(rn(3)))))
# 对
out.append(wr(rn(0), "(uint64_t)((uint64_t)(%s)-(uint64_t)(%s)*(uint64_t)(%s))"
                    % (rd(rn(3)), rd(rn(1)), rd(rn(2))))
```

实测证据（`0x2d8834 msub x8, x8, x25, x0`，输入 X0=0x20 / X8=0x3 / X25=0xa）：
```
ARM64  Xa - Xn*Xm = 0x20 - 0x3*0xa = 32 - 30 = 2   ← ref 实测 X8=0x2 ✓
原实现 Xn*Xm - Xa = 30 - 32 = -2 = 0xfffffffffffffffe  ✗
```

修后 `0x2d8838` 处的 X8 与 ref 一致。

**这个 bug 在整个引擎里只有一个实例（`0x2d8834`），但它恰好落在 AES 轮函数的除法取模上，一错就全盘发散。**

## 四、编译成本（重要，影响后续迭代速度）

```
gcc -O0 -w -o x.exe jcy_engine.c main.o   → 8m10s ~ 11m09s（4.3MB 单函数 / 25018 个 computed-goto label）
gcc -O0 -w -c -o main.o main.c            → 数秒（改驱动时务必只重编 main.o 再链接）
```
- 子代理 E 实测 13 组配置**只有 `-O0` 能编过**；`-O1/-Os/-O2/-O3` 及全部缓解参数 25min 超时，峰值 RSS 4.6–8.3 GiB，**不是被系统 OOM 杀，是单纯编译不完**。机器 15.74GB 物理内存 / 49GB 提交限制。无 clang/zig。
- exe 大小：24.1MB（无插桩）～27.6MB（带插桩）。**插桩会让日志涨到几十 MB 并拖垮执行，正式跑务必移除。**

## 五、性能：秒级目标的可达性（子代理 E 实测，详见 reports/audit_build_perf.md）

| 项 | 实测值 |
|---|---|
| 639 块总指令数 | 2,180,018 × 639 = **1,393,031,502** |
| 1 秒要求的 ns/dispatch | **0.718** |
| `-O0` 实测（不可预测跳转） | **41.42 ns**（N=1000）；N=10000 时 **77.33 ns** |
| 最好单档实测 | 5.35 ns（仍差 7.5×） |
| **单线程缺口** | **36.7×（乐观）～ 107.7×（贴近真实工作集）** |
| **12 核按块并行** | 41.42ns×12核 → **0.481 s**；26.33ns → **0.305 s** ✅ |

- 0.718 ns **低于一次间接跳转误预测（~5ns）**，单线程下达不到。
- **唯一实测支撑的达标路径：按块多核并行。** 639 块天然可切分，无依赖。
- `mem_ptr` 页表化实测 7.53→2.86 ns（-O0），但 mem_ptr 只占 30.7% 指令，折合总耗时仅省 **1.9%**，**不是瓶颈**。
- 瓶颈：平均每 label 仅 1.06 条语句却要付一次不可预测间接跳转，成本几乎全在间接跳转 + I-cache miss（占 30.7%）。
- 继续提速需架构级改动（按 basic block 建 label、mov/movk 常数折叠，占 43% 指令），**需改 `gen_engine.py`，待决策**。

## 六、产出文件

**新增工具（research/ 根目录）**
- `gen_ref_trace.py` — 生成与 golden 同源的 Unicorn 参考 trace（已验证 body 一致）
- `diff_body.py` — body 逐字节差分（含差异区间分段）
- `diff_trace.py` — C trace vs 参考 trace 逐条对拍（默认用 `ref_trace_*.txt`）
- `probe_reg.py` / `diff_reg.py` — 寄存器级逐字段对拍
- `probe_fork.py` — 分叉点现场取证

**新增报告**
- `reports/ref_trace_1blk.txt` — 2,153,688 条有效基准（**取代 `trace_py_1blk.txt`**）
- `reports/audit_templates.md` — 子代理 B 模板语义审计（4 P0 / 2 P1 / 6 P2）
- `reports/audit_build_perf.md` — 子代理 E 编译矩阵 + ns/dispatch + 639 块模型
- `reports/reg_ref.txt` / `reports/reg_c.txt` — 寄存器快照基准与 C 侧实测

**修改文件**
- `gen_engine.py` — 3 处待办补丁 + 6 个语义修复 + 移除 O(n²) 落盘
- `engine_c/main.c` — CUR 扩容 + argv[8] 明文装填 + 全局堆诊断
- `engine_c/jcy_engine.c` — 重新生成（勿手改）

## 七、下一步建议（按优先级）

1. **重做预运行镜像**：在 Unicorn 侧把 so 段 reloc + 初始化跑到稳定态后再 dump（`probe_c_state.py` 的 `cycle()` 里 dump 时机需移到 `e.call()` 之前**且**确保 so 段初始化已完成，或改为 dump 后用 Unicorn 再跑一次取 so 段 diff）。这是打通 idx 1085 的关键。
2. **提 TRACE_LIM** 到 3,000,000 以上（1 块实测 2.15M 条，5M 上限虽够但余量小；128 块会更多）。
3. **按块并行**：性能达标的唯一实测路径，12 核即可进 0.5s。`engine_run` 无全局状态（`X[]/Q[]/JT` 每次调用 memset 重置），可直接多线程；注意 `c_alloc` 的 `heap_ptr` 需改线程本地。
4. 镜像修好后跑 128 块全量差分，再外推 639 块。


---

# 【最终结果】差分已通过 ✅

修完 `STUB_MALLOC` + `msub` 两处后：

| 项 | 结果 |
|---|---|
| **1 块 trace** | **2,180,018 条逐条完全一致**（长度也相同）✓ |
| **1 块 body** | **32 字节逐字节完全一致**（golden1）✓ |
| **128 块 body** | **2064 字节逐字节完全一致**（golden128）✓ |
| 堆 | 1 块 410 次/32528 B；128 块 19451 次/2141440 B，0 次超大分配，0 次耗尽 |
| 异常 | 无 UNIMPL / BADPC / unmapped |

## 实测性能（无 trace，纯执行）

| 规模 | 耗时 | 备注 |
|---|---|---|
| 1 块 | **89 ms** | 2,180,018 指令 → **40.8 ns/dispatch**（24.5 M dispatch/s） |
| 128 块 | **4098 ms** | 32.0 ms/块 |

**与子代理 E 的性能模型交叉验证：实测 40.8 ns/dispatch vs E 模型 `-O0` 不可预测跳转 41.42 ns —— 吻合。模型可信。**

（开 trace 时 1 块 2086 ms / 128 块 9306 ms，即 trace 记录本身有约 20× 开销，正式使用务必关掉。）

## 639 块外推

| 并行度 | 预估耗时 | 结论 |
|---|---|---|
| 1 核 | 20458 ms | ✗ 超标 20.5× |
| 8 核 | 2557 ms | ✗ 超标 2.6× |
| 12 核 | 1705 ms | ✗ 超标 1.7× |
| 16 核 | 1279 ms | ✗ 超标 1.3× |

**注意：子代理 E 原估「12 核 0.481s 达标」是按 26.33 ns（可预测跳转）算的；真实负载是不可预测跳转（40.8 ns），因此 12 核不够，需 ~20 核，或配合 E 报告里列的架构级优化（按 basic block 建 label、mov/movk 常数折叠，占 43% 指令）。**

639 块天然可切分、无数据依赖，`engine_run` 每次调用都 memset 重置 `X[]/Q[]`，唯一共享状态是 `c_alloc` 的 `heap_ptr`（改线程本地即可）和 `JT`（首次 calloc 后只读，可共享）。

## 剩余待办
1. **提 TRACE_LIM** 到 3,000,000 以上（128 块撞了 5M 上限，说明 639 块需要约 1.1 亿条缓冲 = 880 MB —— 建议调试时才开 trace，且分块落盘）。
2. **按块多核并行**：`heap_ptr` 改线程本地；`JT` 只读可共享。
3. **DLL 化**：`gcc -shared` 导出 `engine_run`/`engine_write`/`engine_read`/`CUR`，用 ctypes 接 `deliverables/authgen_server.py` 的 `decrypt_e` 路径。
4. 架构级提速（需改 `gen_engine.py`）：按 basic block 合并 label、mov/movk 常数折叠。
