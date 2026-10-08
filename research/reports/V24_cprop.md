# V24 — --cprop 常量传播代码生成（引擎提速 1.43×，639 块 <1s 达标）

日期: 2026-10-07
前置: V23_perf_align.md（--fuse 基本块合并 + mem_ptr_hot，639 块 e2e 1487ms）

## 一、动机与结论

用户目标：离线解密跑出 App 级速度。App 侧 libcore.so 原生执行 639 块约 440ms；
V23 引擎 1487ms，差距 3.3×。本轮对 `gen_engine.py` 新增 `--cprop` 编译期常量传播，
**639 块端到端 889ms（3 轮隔离中位）/ 874ms（15 轮 DLL 级中位），<1000ms 目标达成**。

## 二、--cprop 三项变换（全部在 gen_engine.py，不改运行时）

| # | 变换 | 形式 | 依据（trace 混合比） |
|---|---|---|---|
| A | 常量控制流直化 | `PC = 0xT; DISPATCH();` → `PC = 0xT; [TRACEPUT();] goto L_T`（T-BASE ∈ cover 时） | term/branch 10.24%，223k 次/块 dispatch 中绝大多数目标静态 |
| B | movz/movk 立数折叠 | `X[n]=c1; X[n]=(X[n]&m)\|c2` → 单条 `X[n]=c` | movz/movk 23.26% + mov-imm 12.54%，常量装配合计 35.8% |
| C | 常量寄存器读替换 | kval 已知时 `X[n]` 读替换为 `(0x..ULL)`（cbz/tbz 条件变常量） | alu 26.83% 中相当部分操作数是装配出来的常量 |

trace 混合比（1 块 2,180,018 条）：alu 26.83% / movz+movk 23.26% / mem 21.04% /
mov-imm 12.54% / term+branch 10.24% / mov-reg 6.09%。

### 正确性边界（kval 失效点，缺一即错）

kval（编译期已知寄存器值表）在以下位置**必须清空或失效**：
1. 每个 chunk（基本块）起点 —— 控制流汇合；
2. 内部 label 且 `o2 ∈ JUMP_TARGETS`（静态分支目标 ∪ trace jump-in，2,128 个）——
   1,948 个 trace jump-in 目标可从任意处跳入，块中 label 不清会传染脏值；
3. 任何外部调用语句（`stub_run/hook_after_*/hook_x/memcpy/fprintf/abort`）——
   AAPLS 调用破坏 X19-X28 callee-saved 的编译期假设；
4. 任何赋值目标（`_RE_ANYDEF`，含 csel 的 `if(c) X[d]=..; else X[d]=..;`）——
   LHS 由 `_RE_XREF` 负向前瞻 `\bX\[(\d+)\](?!\s*=(?!=))` 保护，替换绝不碰左值；
5. 裸 `DISPATCH/goto/return` 语句。

保留语义：`PC = 0x900000` 返回哨兵与 `0x6000xxxx` 桩区间**不**直化（不在 cover）；
`--notrace` 下直化省掉 TRACEPUT，trace 版直化保留 TRACEPUT 后再 goto，PC 序列不变。

## 三、验证（全绿）

| 项 | 结果 |
|---|---|
| body 1 / 128 / 639 块 | 32 / 2064 / 10240 字节逐字节一致 golden ✓ |
| PC trace（jcy_fuse24_trace.exe vs Unicorn 基线） | **2,183,860 条逐条一致**（长度相同）✓ |
| C-vs-Unicorn 标定（verify_backends） | C/CONST[128]/Cb[128] 全一致，两侧不变式自检 True；128 块标定 269ms |
| 真实捕获样本 | 9/9 全对 ✓ |
| 15 轮进程隔离 bench_iso（V23 vs V24） | body sha256 相同 `52cb6706e6a241e1` ✓ |

## 四、性能

### DLL 级（bench_iso.py 639 块 15 组独立进程）

| | min | median | mean | stdev |
|---|---|---|---|---|
| V23 jcy_fuse_fast.dll | 1090 | **1247** | 1371 | 260 |
| V24 jcy_fuse24.dll | 771 | **874** | 931 | 141 |
| 加速 | 1.41× | **1.43×** | 1.47× | — |

⚠️ 基准方法坑：7 轮时 V24 中位数曾"翻车"为 0.93×——进程噪声（stdev≈280ms）淹没差异，
15 轮后分布彻底分离。**结论必须 ≥15 轮或看 min**；bench_iso 逐组跑所有 DLL，
组间漂移会同时污染所有组，靠 min/median 双指标判读。

### 真实链路（bench_e2e.py 冷标定+解密，3 组独立进程取中位）

| 接口 | 块数 | V23ms | V24ms | 加速 |
|---|---|---|---|---|
| device-base | 3 | 83 | 116 | 0.71×（固定开销主导）|
| sign_rule | 30 | 156 | 120 | 1.30× |
| video_detail | 84 | 289 | 163 | 1.78× |
| app_config | 120 | 330 | 224 | 1.47× |
| update_list | 143 | 435 | 261 | 1.66× |
| app_channel | 166 | 442 | 281 | 1.57× |
| banners_0 | 259 | 618 | 317 | 1.95× |
| video_list | 539 | 1382 | 758 | 1.82× |
| 【639压力】 | 639 | 1576 | 889 | 1.77× |
| **合计** | | **5311** | **3130** | **1.70×** |

9 组明文 sha256 两侧全部一致。小响应（≤3 块）受镜像加载固定开销（~40-50ms）主导，
引擎吞吐优化不受益（V23 已知坑位，维持结论）。

## 五、产物与复现

```bash
cd research
python gen_engine.py --fuse --notrace --cprop      # → engine_c/jcy_engine_fuse.c (3268.9 KB, V23 4298.1 KB)
bash build_fuse.sh "-O1 -fno-gcse" fuse24          # → jcy_fuse24.dll 1,474,330 B / jcy_fuse24.exe
python gen_engine.py --fuse --cprop                # → jcy_engine_trace24.c (trace 版, 带 TRACEPUT)
# trace exe: gcc -O1 -fno-gcse -w -c jcy_engine_trace24.c + 链 jcy_fuse24_post.o main.c
python verify_cprop.py          # body 1/128/639
python verify_cprop.py trace    # body + PC trace 2,183,860 条逐条
python bench_iso.py 639 15      # DLL 级 15 轮隔离
python bench_e2e.py 3           # 真实链路 9 端点
```

管线接入：`c_engine.py._DLL_CANDIDATES` 首选已切 `jcy_fuse24.dll`（JCY_DLL 可回退
jcy_fuse.dll/jcy_engine.dll）。文件备份：`gen_engine_v23.py.bak`、`jcy_engine_fuse_v23.c.bak`。

## 六、遗留边界

- **CONST_b 闭式仍未还原**：本轮决定性对拍证实 (u=P5(K)) 模型只命中 b=0/1，
  b≥2 全盘发散（rk1..rk8 逐块演化）。churn 已证是 (K)-only 状态机但 schedule 流
  非任何 AES key-schedule 变体；angr 反编译为 MBA soup。**解密不需要闭式**
  （引擎逐位复刻 0x2d9ed0 即可），闭式只影响把标定从"每 K 一次"降到"零次"。
- hub 模式（`ldr w8,[x21,#8]` → br x8）动态分发未直化，属 cprop 下一步空间（<10.24%）。
- 3 块以下小响应瓶颈在镜像加载固定开销，与引擎无关。

## 七、堆窗口扩容（2026-10-07 晚，桥层实测时发现并修复）

**现象**：桥层 `video/list?limit=24`（28KB 响应 ≈ 1,750 块）请求 ~5.7s 后连接死亡、
无响应，node 监督器反复重生 worker；`limit=6`（6.7KB ≈ 420 块）正常。
隔离复现（JCY_DLL=jcy_fuse24.dll 直接调 jcy_api）得
`ENG: unmapped 0x54000010 PC=0x400024cdeb20`（PC 在 churn 窗口内）。

**根因**：镜像堆区固定 0x50000000-0x54000000（64MB，image639 预跑地图），
真实堆消耗 ≈ 41KB/块，~1,600 块即打穿；c_alloc 耗尽分支仍返回越界地址，
应用写入时 mem_ptr 落 unmapped → exit(1)。**前端可触达**：search(limit=25 ≈ 1,700 块)、
updateList(limit=50 时间表页，可达 3,100 块) 都会踩中，video_list(limit=6) 侥幸不踩。

**修复**（三处）：
1. `gen_engine.py` postlude：`engine_grow_heap()` —— 装载镜像后把堆区背衬
   realloc 到 256MB（0x50000000-0x60000000，上面紧邻 0x60000000 TLS 区，
   中间无其他映射），尾部零填充（malloc 语义 = 新分配内存写后读，零页正确）；
2. `dll_iface.c` / `main.c`：`HEAP_HI` 0x54000000 → 0x60000000（两侧同步）；
3. 重编 jcy_fuse24.dll/exe，body 1/128/639 逐字节复验 PASS。

**结果**：容量 64MB→256MB ≈ 1,630→6,500 块（≈104KB JSON 响应）。
隔离复现 limit=24 转绿（code 20000, 24 项）；桥层 limit=24 冷 3.8s / 热(缓存) 16ms；
播放闭环 resolve 3.3s、stream 首字节 415ms 全通。代价：进程首次装载 +192MB RAM。

**经验**：引擎容量边界（639 块）此前从未被负载探到——verify 金料最大就 639 块。
**金料上限=被测上限**，接入真实负载前必须用超金料规模做一次冒烟。
