# V20 — 性能路线调研与实测（2026-10-06）

> 目标：639 块响应体解密 < 1 s。
> V19 结论：C 引擎 24 s（未达标）。本轮先**重新定义瓶颈**，再给方案。

---

## 0. 一句话结论

**V19 把 639 块 <1s 当成"引擎太慢"的问题，这是错的定位。**
实测：**解密本身 639 块只要 382 ms（已达标）**，100% 时间花在**标定**上。
标定是 **per-K** 的一次性成本。因此有两条独立的达标路径，且**都不需要优化引擎**：

| 路径 | 手段 | 预期 | 状态 |
|---|---|---|---|
| **A. 摊销标定** | 同一 K 只标定一次，缓存 `CONST[]` | 首次 8.9 s，后续 **0.000 ms** | 已实测 |
| **B. 消除标定** | 把 per-K 的迭代映射直接提取成 C 代码 | 标定 O(1)，整体 < 400 ms | 待做 |

---

## 1. 实测数据（本轮真实执行，非估算）

```
解密 639 块（标定已缓存）      :   382 ms   (0.599 ms/块)   ← 已 <1s
标定 16 块                     :   411 ms   (25.68 ms/块)
标定 64 块                     :   858 ms   (13.41 ms/块)
标定 639 块（Unicorn）         : 8930 ms
标定 639 块（同一 K，二次）    : 0.000 ms   ← _cache 命中
标定 639 块（不同 K）          : 9375 ms
```

标定成本随块数**近似线性**（首块有固定开销，之后 13.4 ms/块趋稳）。

### 已验证的结构性质

1. `CONST[b]` **只依赖 (K, 块号 b)**，与 `nblk` 无关。
   实测：nblk=4/8/16/32 的 `CONST[0:4]` **逐字节相同**。
2. 不变式 `Cb_b == CONST_{b+1} ^ CONST_1` 恒成立（32 块全 True）。
   → **`Cb[]` 是冗余的**，只需 `CONST[1..n]`。标定数据量减半。
3. 解密公式（`decrypt_e.py:372`）：
   ```
   xb   = F_inv(ctb ^ C ^ Cb[b], rk)
   out  = xb ^ prev ^ CONST[b]
   ```
   `out` 端是纯 Python 算术，**与引擎无关**，故 382 ms 不可再压缩。

### 由此得到的结构洞察

加密链 `c_{b+1} = F(c_b ^ pt_b)`，其中 `x_b` 由轮驱动从 `(K, c_b)` 决定。
把 `pt` 固定为全零（即标定用的 dummy），得到的 `CONST[b]` 序列
**只由 K 决定**，是一个一维确定性迭代映射：

```
CONST[0] = 0
CONST[b] = x_b ^ c_{b-1},   x_b = G(K, c_{b-1}),   c_b = H(x_b)
```

实测 `CONST[0..7]`（K = 05..14）：
```
CONST[0] = 00000000000000000000000000000000
CONST[1] = 7a4abe6e39f954058579137452f912f2
CONST[2] = af999bfdc81f8403d9615fc384cf9203
CONST[3] = 8c6566e3fddb8fa31761b5cbcede611d
CONST[4] = 4856dae093eac9e328a3e093d37d0f9a
CONST[5] = dae600725d0a39e71a497446d70db6b0
CONST[6] = ca8be686d54d519aeac4e30f22537e39
CONST[7] = 1d51980e430b6b5750229cbf5b924545
```

注意 `CONST[0] = 0` —— 因为 `x_0 = iv = K[::-1]` 且 dummy 块为全零。
**这条链没有捷径可"跳到第 639 块"**，除非把 `G`/`H` 反编译成 C。

---

## 2. 方案 A：标定按 K 缓存（零成本，已验证可行）

`EDecryptor._cache` 已按 `(K, nblk)` 缓存，命中即 0 ms。
但当前有两个缺陷使其在真实服务中失效：

1. **缓存键含 `nblk`** —— 先请求 16 块、后请求 639 块会**各标定一次**。
   改为只按 `K` 键，存「已标定到第几块」+ `CONST[]`，请求更大 nblk 时增量补齐。
2. **缓存无上限** —— 长期运行会无限增长。需 LRU + 上限。

**预期收益**：只要同一 K 被复用 N 次，平均成本 = 8930/N ms。
N=10 → 893 ms（达标）；N=100 → 89 ms。

**未验证**：真实流量里 K 的复用率。
捕获文件（`captures/apipost_responses.jsonl`）的响应体是
`{"responseText":"..."}`，**不带 `.` 分隔**，与 `decrypt_envelope` 期望的
`P0.P1` 格式不符 —— 说明这些捕获是在**协议还原之前**录的，无法直接统计 K 复用。
需要重新抓一组带 `data` 字段的样本，或从请求侧推 K。

---

## 3. 方案 B：把 per-K 迭代映射提取成 C（真正的解法）

标定 = 一次 639 块的全零加密 = 63.8 万条 ARM64 指令执行。
**这是唯一必须跑模拟器的环节。** 若把 `G`/`H`（轮驱动 + 密文反馈）
反编译为等价的 C，则标定从 8.9 s 降到微秒级，**引擎整体退出热路径**。

可行性依据：
- 轮驱动入口 `0x2da498` 每块调用 2 次，读 16 字节 —— 接口极窄。
- `x_b` 已被证明是 `(K, 上一块密文)` 的纯函数（CONST 与 nblk 无关即证据）。
- AES 部分已经在 `decrypt_e.py` 里用纯 Python 实现了（`expand/SB/SR/MC/F/F_inv/T`），
  说明轮函数的**结构已经摸清**，缺的只是 `x_b` 的生成式。

**做法**：
1. 用 `probe_reg.py` 系列工具，在轮驱动内部打点，把 `x_b` 的计算拆成子表达式；
2. 对每个子表达式，用两组不同 K 的 `(输入, 输出)` 对验证是否与 K 无关
   （若是，则可提为常量表；否则必是 `F(k)` 形式，需还原成 AES 调用）；
3. 产出 `CONST_stream(K, nblk)` 的纯 C 实现；
4. 用现有 639 块 golden 逐字节回归。

**风险**：若 `x_b` 内部有依赖堆数据的间接取值（如 V19 看到的 malloc 序列），
则无法提取。`x_b` 只依赖 16 字节 + K 的可能性高，但**未验证**。

---

## 4. 方案 C：引擎层优化（搜索结论 + 待验证）

即使做了 A/B，引擎仍需支撑"首次标定"。以下是调研结论：

### C1. `-O2` 编译失败的真正原因：computed-goto 的 O(N²) 展开

GCC internals 明确记载：
> "functions consisting of many taken labels and many computed jumps may have
> very dense flow graphs... During the earlier stages GCC tries to avoid such
> dense flow graphs by **factoring computed jumps**... the computed jumps are
> **un-factored** in the later passes (pass_duplicate_computed_gotos)."

**GCC 官方 man 页面直接给出了对策**（这是 V19 漏掉的关键线索）：

> "When compiling a program using **computed gotos**, you may get better
> **runtime performance** if you disable the global common subexpression
> elimination pass by adding **`-fno-gcse`** to the command line."

相关参数：
- `-fno-gcse` — 关掉 GCSE，避开 O(N²) 展开，同时**官方声明对 computed-goto 有性能收益**
- `--param=max-gcse-memory=N` — 抬高 GCSE 内存上限而非关闭
- `--param=max-goto-duplication-insns=N` — 限制 un-factor 展开量（默认 8）
- `-fno-crossjumping` — 限制另一个 O(N²) pass

V19 的 13 组参数组合**全部失败**，但从报告看**没有试过 `-fno-gcse`**（它是针对
computed-goto 的专门建议，最可能有效）。

**正在实测**：4 组参数组合的后台编译任务。

### C2. 基本块合并 / superinstruction：收益远低于预期

V19 估计"块长 16 → 0.9 s"。搜索到实测反例：

> Aaron Wohl, *Superinstructions bought me 2 percent*（iospharo，Pharo 解释器）
> 100M 字节码 profile 驱动融合，**消除了 11% 的 dispatch 操作，
> 但只换来 2.8% CPU 提升**。原因：Apple M1 的分支预测器已经能很好处理
> dispatch 跳转表，被消除的 dispatch 大多是廉价的。
> "瓶颈在方法查找和栈帧设置，不在 dispatch。"

QuickInterp（Java 字节码，2020）报 33–45% 提升 —— 但那是 **嵌入式/无 JIT** 环境。

**结论**：V19 的"块长 16 → 0.9 s"是线性外推，**很可能过于乐观**。
但注意本项目有个**关键差异**：C 引擎当前 20.8 ns/dispatch，而 Unicorn（QEMU TB
缓存，块内零跳转）是 13.5 ns/指令 —— 说明我们**确实**吃了 dispatch 的亏，
合并基本块理论上应有真实收益。**未验证，需实测**。

### C3. 更彻底的方案：换执行引擎

| 方案 | 预期 | 代价 |
|---|---|---|
| **Dynarmic**（yuzu/Ryujinx 用，ARM64→x86-64 DBI） | JIT，接近原生，可多线程 | C++20 重写引擎；**spec 兼容性不完全**（非对齐访存/独占监视器行为有偏差），但我们的场景是可验证的 |
| **LLBT 式静态翻译**（ARM→LLVM IR→x86） | 实测比 QEMU **快 6–7 倍**，最高 64 倍 | 需 LLVM；离线路径，无解释开销 |
| **DynASM/AsmJit 手写 JIT** | 灵活 | 工作量大 |
| **直接调用 Unicorn 的 C API + 多进程** | Unicorn 已 thread-safe by design，每进程独立 | 12 进程 → 8.9 s / 12 ≈ **740 ms（达标）** |

**C3 最后一行值得单独强调**：Unicorn 单实例 8.9 s，**12 核跑 12 个进程就是 740 ms，
直接达标**，且**不需要写任何新引擎**。这是投入产出比最高的选项。

---

## 5. 优先级建议

```
1. 方案 A  修缓存键 + 加 LRU          → 零风险，N 次复用即达标
2. C3 多进程 Unicorn                    → 740 ms 达标，一天内可验证
3. C1 -fno-gcse 重新试 -O2            → 若成功，引擎单线程直接快数倍
4. 方案 B  提取 CONST_stream 到 C       → 彻底解决，但工作量最大
5. C2  基本块合并                      → 收益不确定，排在最后
```

C1、C3 可并行验证。

---

## 6. 本轮明确「未执行」的事项

- `-fno-gcse` 等 4 组参数的编译结果：**正在后台跑**，结论待补。
- Dynarmic / LLBT：**未评估可行性**（未读 Dynarmic 源码、未验证 spec 偏差是否影响本管线）。
- 方案 B 的 `x_b` 子表达式提取：**未开始**。
- 真实流量 K 复用率：**无法统计**（捕获文件格式不匹配）。
- C2 基本块合并：**未实现**，收益存疑。