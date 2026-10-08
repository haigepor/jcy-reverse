# V23 性能对齐方案：把链路速度做到与 App 一致

> 2026-10-06 · 目标：消除解释器与 App（AOT 机器码）之间的指令吞吐差距

## 1. 差距的量化

从 128 块参考 trace 实测得到关键基数：

| 项| 值 | 来源 |
|---|---:|---|
| 128 块参考 trace 总条数 | 126,262,795 | `reports/ref_trace_128blk.txt`（`wc -l`） |
| **每块平均 ARM64 指令数** | **986,428** | 上者 ÷ 128 |
| 1 块完整 trace | 2,180,018 | 固定初始化 ~1,193,590 + 每块 986,428 |
| 我们引擎吞吐 | **3.47 ns/条** | 2188 ms ÷ 6.30亿条 |
| App AOT 机器码吞吐 | ~0.7 ns/条 | 经验值（**未在本机实测**，见 §6） |
| **差距** | **约 5×** | |

## 2.差距花在哪里 —— 实测拆解

`engine_c/mb2.exe`（微基准，6 条形态取自真实生成码）：

| 变体 | ns/块 | ns/指令 | 省|
|---|---:|---:|---:|
| A 现状（mem_ptr + TRACEPUT + PC 赋值） | 2.57 | 0.428 | — |
| B 去 TRACEPUT + PC | 2.26 | 0.376 | 12.1% |
| C 去 mem_ptr | 0.38 | 0.063 | **85.2%** |
| D 全去（局部变量 + 直接基址） | 0.53 | 0.088 | 79.5% |

**结论：`mem_ptr()` 占 83.2%，是唯一的靶心。**

## 3. mem_ptr 为什么慢

原实现：

```c
uint8_t *mem_ptr(uint64_t a) {          /* noinline */
    for (int i = 0; i < NREG; i++)      /* 9 次比较 */
        if (a >= RBASE[i] && a < RBASE[i] + RSZ[i]) return REGP[i] + (a - RBASE[i]);
    ...
}
```

慢的三个原因（缺一不可）：
1. **noinline** → call/ret，且阻断编译器的别名分析（返回指针可能别名任何全局）
2. **循环** → 编译器无法展开与预测，退出条件依赖前一次比较
3. **每次访存都调用** → 8,124 处调用点，遍布内层循环

## 4. 方案选型：三条路被实测否决

`engine_c/mb3.exe`（5 方案对比，全部在真实 8 区域布局上测）：

### 否决 1：4K 两级页表 —— 慢 0.72×
索引表 32 MB，随机访存全部 miss（超出 L2/L3）。

### 否决 2：低段 16 MB 查表 + 回退 —— 慢 0.87×
表项只有 512 B（必进 L1），但每次仍是一次 load + 边界判定，且打断分支预测。

### 否决 3：只把 noinline 去掉（保持 base顺序）—— 1.40×
有效但不够。

### 采纳：static inline + 热区优先比较链 —— **8.00×**

```c
static inline uint8_t *mem_ptr_hot(uint64_t a) {
    if (a - RBASE[4] < RSZ[4]) return REGP[4] + (a - RBASE[4]);  /* 代码区, 最热 */
    if (a - RBASE[0] < RSZ[0]) return REGP[0] + (a - RBASE[0]);  /* 主数据区 */
    if (a - RBASE[3] < RSZ[3]) return REGP[3] + (a - RBASE[3]);
    if (a - RBASE[1] < RSZ[1]) return REGP[1] + (a - RBASE[1]);
    if (a - RBASE[2] < RSZ[2]) return REGP[2] + (a - RBASE[2]);
    if (a - RBASE[5] < RSZ[5]) return REGP[5] + (a - RBASE[5]);
    if (a - RBASE[6] < RSZ[6]) return REGP[6] + (a - RBASE[6]);
    if (a - RBASE[7] < RSZ[7]) return REGP[7] + (a - RBASE[7]);
    fprintf(stderr, "ENG: unmapped ..."); exit(1);
}
#define mem_ptr(a) mem_ptr_hot((uint64_t)(a))
```

要点：
- **inline** 让编译器把判定折进访存点，无 call/ret，别名分析恢复
- **热区优先**：最热的代码区（PC 所在）放比较链首位，命中即第一个分支 → 预测器稳定命中
- **区域有序不重叠** → 每区只需一次 `(a - base) < size` 判定，无需两次比较，无需循环

区域顺序由镜像文件决定，**不可假定**。因此新增 `engine_sort_hot()`：每次 load 后按**内容**（而非槽号）把代码区与最大区交换到热位。

## 5. 第二项：TRACEPUT 编译期消掉 —— 12.1%

DLL 生产路径 `TRACE_BUF` 恒为 0，但源码 `if (TRACE_BUF && ...)` 仍是运行时分支，且每条指令执行一次。编译器无法自行删除（`TRACE_BUF` 是 TLS 全局，别处可能被赋值）。

新增 `--notrace` 生成开关：

```python
trace_macro = '#define TRACEPUT() do { } while (0)' if notrace else <原定义>
...
if k < len(chunk) - 1 and not notrace:
    body.append("  PC = %dULL; TRACEPUT();" % ...)   # notrace 下整行是死代码
```

块**尾**的 `PC = <常量>; DISPATCH();` 保留（`DISPATCH` 依赖它）。

## 6. 实测收益（进程隔离，median）

### 必须用进程隔离测量
同进程内反复 `load()` 101MB 镜像会让数据**完全失效**：`bench_ab.py` 实测 V22 在
**1851~5526 ms** 间波动（3 倍），而真实差异只有几百 ms。原因是每次 load 重新 mmap
镜像，进程内 malloc/页表状态不可控。

**规范**：`bench_iso.py` / `bench_e2e.py` 每个样本起独立子进程只跑一次。

### 引擎裸跑

| 规模 | V22 | V23 | 加速 | 稳定性 |
|---|---:|---:|---:|---|
| 639 块 | 2001 ms | 1056 ms | **1.89×** | stdev 76ms（V22）vs 70ms |
| 128 块 | 339 ms | 157 ms | **2.17×** | 极差 105 → 47 ms |

### 端到端全链路（冷标定 + 解密）

| 规模 | V22 | V23 | 加速 |
|---|---:|---:|---:|
| 639 块 | 2449 ms | 1487 ms | 1.65× |
| **verify_backends C 639** | **2668 ms** | **1501 ms** | **1.78×** |

### 真实接口（`bench_e2e.py`，明文全部 sha256 一致）

| 接口 | 块数 | V22 | V23 | 加速 |
|---|---:|---:|---:|---:|
| device-base | 3 | 57 ms | 49 ms | 1.15× |
| sign_rule | 30 | 130 ms | 150 ms | 0.86× |
| video_detail | 84 | 295 ms | 180 ms | 1.64× |
| app_config | 120 | 407 ms | 252 ms | 1.61× |
| update_list | 143 | 447 ms | 386 ms | 1.16× |
| app_channel | 166 | 609 ms | 384 ms | 1.59× |
| banners_0 | 259 | 882 ms | 644 ms | 1.37× |
| video_list | 539 | 2039 ms | 1310 ms | 1.56× |
| 合计 | — | 7315 ms | 4844 ms | **1.51×** |

小规模（3/30 块）加速不明显甚至倒退，因为固定开销（101MB 镜像加载 + 初始化）
占主导，与引擎吞吐无关。

**实际 1.51~2.17×，低于微基准预测的 8×** —— 微基准只测 6 条指令形态，
真实引擎的 dispatch、`X[32]` 数组访问、cache 行为都不在微基准覆盖范围内。

### DLL 体积
3,463,939 → **1,940,851 字节（小 44%）**

### 与 App 的差距
| 规模 | App（0.7ns/条） | V22 | V23 |
|---|---:|---:|---:|
| 168 块真实平均 | 116 ms | 609 ms（5.2×慢） | **384 ms（3.3×慢）** |
| 639 块压力 | 442 ms | 2449 ms | **1487 ms（3.4×慢）** |

> 注：App 侧 0.7 ns/条 是经验值，未在模拟器/真机实测。

### 正确性验收（全绿）

| 验证项 | 结果 |
|---|---|
| `verify_fuse.py` 1 块 body | PASS，32 字节逐字节一致 |
| `verify_fuse.py` 128 块 body | PASS，2,064 字节逐字节一致 |
| `verify_fuse.py` 639 块 body | PASS，10,240 字节逐字节一致 |
| `verify_fuse.py` 1 块 PC trace | **PASS，2,183,860 条逐条一致** |
| `verify_post.py` 轮密钥/C/CONST/Cb（1/8/128/639） | 全部逐位一致 |
| `verify_backends.py A` 639 块 C vs Unicorn | C / CONST[639] / Cb[639] 全一致 |
| `verify_backends.py B` 真实样本 | 一致 9 / 不一致 0 / 跳过 1 |
| 不变式自检 | C 侧 True，Unicorn 侧 True |

### V22 vs V23 直接 trace 对照（最强判据）
同参数（`image1.bin` + `pt1.bin`）分别跑两个 exe：

- **2,183,860 条 PC 逐条完全一致，无分叉**
- body 32 字节逐位一致

### 一个必须知道的验证陷阱
拿 V23 的 trace 去比 `reports/ref_trace_1blk.txt` 会在第 **711,283** 条「分叉」
（`0x2d303c` vs `0x2d2fac`，差 0x90）。**这是比错了对象，不是 bug**：

- `ref_trace_1blk.txt`（2,180,018 条）来自**「不传明文」**配置 ——
  已验证该配置产出的 body = `golden1`（`3665eb1c...`）
- V23 跑的是**「传明文 pt1.bin」**配置，body = `d085ec6c...`，trace 2,183,860 条

**判定 V23 是否正确，必须用 V22 exe 在完全相同参数下产生的 trace 作基线。**

## 7. 已知坑位

1. **`mem_ptr` 宏化会破坏外部 TU**。`dll_iface.c` 的 `uint8_t *mem_ptr(uint64_t);` 声明无法解析 → `undefined reference`。已在引擎侧导出 `mem_ptr_ext()` 包装，并在 `dll_iface.c` 用宏适配。
2. **`HEADER` 是 Python 格式化模板**，注释里的裸 `%` 会触发 `TypeError: not enough arguments for format string`。必须写 `%%`。
3. **`-O1` 编译耗时 8m41s**（融合源 3.5 MB）。任何引擎改动都要预留这个时间。
4. **`gen_engine.py` 输出到 `engine_c/jcy_fuse.c`**（不是 `jcy_engine_fuse.c`）。后者是历史遗留副本。

## 8. 未执行 / 待验证

- **App 端真实吞吐未实测**：0.7 ns/条是经验值。真实倍率需在雷电模拟器或真机上测。
- 剩余 3.3× 差距的归属未拆解。预计在 computed-goto dispatch（20,617 次已消除，
  剩余跨基本块的仍存在）与 `X[32]` 数组无法完全寄存器化。
- 小规模（<50 块）加速不明显（0.86~1.16×），固定开销主导。若真实业务以小响应为主，
  应优先优化**镜像加载**（101 MB malloc + 读盘）而非引擎吞吐。

## 9. 后续优化方向（按杠杆排序）

1. **镜像加载**：固定开销约 40~50 ms，占小规模请求的大部分。
   考虑 mmap 替代 malloc+read，或多进程预热常驻（`calib_pool.py` 已有雏形）。
2. **computed-goto dispatch**：剩余跨基本块的间接跳转。
3. **`X[32]` 寄存器化**：让热 PC 上的 X 读写落到真寄存器，需要 x86-64 codegen。
4. **热 PC 超块化**：6,399 个热 PC 占 73.3% 执行，做算子提取或超块融合。