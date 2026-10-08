# V19 收官报告：639 块全量差分 + DLL 化 + 双后端

日期：2026-10-06
机器：x86_64-w64-mingw32 (gcc 16.1.0)，12 核，15.74 GB

---

## 1. 差分结果（全部实测）

| 项 | 结果 |
|---|---|
| 1 块 PC trace | **2,180,018 条逐条完全一致**（上一轮） |
| 1 块 body | 32 字节逐字节一致（golden1） |
| 128 块 PC trace | 参考 126,262,795 条已生成；**前 5,000,000 条逐条一致**（C 侧受 `TRACE_LIM` 截断） |
| 128 块 body（exe） | 2064 字节逐字节一致（golden128） |
| 128 块 body（DLL） | 2064 字节逐字节一致 ✓ |
| **639 块 body（exe）** | **10240 字节逐字节一致 ✓**（真实非零明文，10224 + PKCS#7 整块填充） |
| **639 块 body（DLL）** | **10240 字节逐字节一致 ✓** |
| 标定量双后端对拍（639 块） | `C` / `CONST[639]` / `Cb[639]` **全部逐位一致**；两侧不变式自检均 True |
| 真实样本解密（`tmp_pairs.json`） | C 后端 vs Unicorn 后端：**一致 9 / 不一致 0 / 跳过 1** |

堆统计：128 块 19,456 次 / 2,143,136 字节；639 块 95,952 次 / 15,559,936 字节；0 耗尽、0 超大分配。

---

## 2. 性能实测（未达标，如实记录）

| 负载 | Unicorn | C 引擎 | 目标 |
|---|---|---|---|
| 标定 128 块 | 2,059 ms | ~2,800 ms | — |
| 标定 639 块 | 8,460 ms | 22,959 ms | — |
| 639 块全链路（标定+解密） | — | **24,076 ms** | **< 1,000 ms** |

**C 引擎比 Unicorn 慢 2.7 倍**，与"转译后应更快"的直觉相反。原因已定位：

```
Unicorn (QEMU TB 缓存)  : 13.5 ns/指令  ← 整个基本块编译成机器码，块内零跳转
C 引擎 (computed-goto)  : 20.8 ns/指令  ← 每条指令一次间接跳转，48.1 M dispatch/s
```

`-O1` 及以上档位**全部编译失败**（4.3 MB 单函数 / 25,018 个 computed-goto label，
`cc1 out of memory`，13 组参数组合无一成功，见 `audit_build_perf.md` §2），
所以 20.8 ns/dispatch 是当前架构下限。

**达标的唯一路径是基本块合并（superinstruction fusion）**：把一串无分支指令直译成
顺序 C 语句，只在块尾做一次间接跳转。若平均块长 8 条，dispatch 开销降至 ~2.6 ns/指令，
639 块约 1.8 s；块长 16 条则约 0.9 s —— **达标**。该改动不影响正确性（差分基线已在），
属纯性能工程，未执行。

---

## 3. 交付物

### 3.1 DLL（`engine_c/jcy_engine.dll`，14.7 MB）

```
gcc -O0 -fPIC -w -c -o jcy_pic.o jcy_engine.c        # 8m42s
gcc -shared -o jcy_engine.dll jcy_pic.o dll_iface.c
```

ABI：
| 导出 | 说明 |
|---|---|
| `jcy_init(const char* image)` | 加载镜像（走 `_wfopen`，支持非 ASCII 路径） |
| `jcy_encrypt(k16, pt, ptlen, out, outcap)` | 一次加密，返回 body 长度 |
| `jcy_encrypt_ex(..., want_x)` | 同上 + 逐块 `x_b` 捕获（标定用） |
| `jcy_capture_enable/count/get` | 捕获缓冲管理（`get(2*i)` 取偶数位） |
| `jcy_last_error() / jcy_heap_stat() / jcy_version()` | 诊断 |

运行时依赖 `libgcc_s_seh-1.dll` + `libwinpthread-1.dll`（已复制到 `engine_c/`）。
Python 侧需 `os.add_dll_directory()` 并**持有句柄**（否则被 GC 后 dlopen 失败）。

### 3.2 Python 侧

- `c_engine.py` — ctypes 绑定（含 `encrypt_with_x`）
- `deliverables/decrypt_e.py` — `EDecryptor(backend="c"|"unicorn"|"auto")`，
  默认 auto（C 优先），C 失败自动回退 Unicorn 并记忆 `_c_ready=False`；
  环境变量 `JCY_BACKEND=unicorn` 强制回退，`JCY_IMAGE` 指定镜像
- `deliverables/authgen_server.py` — `_decrypt_auto` 在 C 后端可用时**进程内直接解**
  （C 引擎是纯本地计算、不占 GIL，不再需要子进程隔离 Unicorn 的 `emu_start`）

### 3.3 工具

- `diff_trace_stream.py` — 大 trace 流式对拍（常驻内存 < 32 MB；
  旧的 `diff_trace.py` 用 `read().split()` 会吃 4.5 GB 必 OOM）
- `dump_image639.py` — 按 nblk 生成专用镜像 + golden
- `verify_dll.py` / `verify_backends.py` / `bench639.py`

---

## 4. 并发：部分修复，明确未完成

引擎侧 `X[]/PC/Q[]/SP/FLG_*/CUR/BODY*/TRACE_*/CAP_*` 已全部改为 `JTLS`
（`__declspec(thread)`），`JT` 首调改为原子状态机
（`InterlockedCompareExchange` → 填 → `Exchange(2)`；**不能用 `InitOnceExecuteOnce`**，
因为 `&&label` 只能在 `engine_run` 函数体内取址）。

**但仿真的地址空间仍未隔离**：堆 `0x50000000`、栈 `0x6fc6a000..`、TLS 区 `0x61000000`、
K/iv 落点 `0x688130` —— 这四样在宿主上就是一块普通内存。逐项按线程槽位切分的实测结果：

| 尝试 | 结果 |
|---|---|
| 堆/栈按槽位切 | `unmapped 0x5eed5eedcafef035`（canary 被覆盖） |
| + K/iv 按槽位偏移 | `PC=0x935b0f258cf82b2f`（PC 本身被踩） |
| + `engine_set_tls_base()` / TPIDR 换基址 | **639 块单线程**即 `unmapped 0x0 / X8=0` |

根因：这些地址不是"随便换块基址都行"——`emu_v11` 里 `mem_map(TLS, 0x4000)` 的 16 KB
承载了 libcore 的线程局部量布局，`0x688130` 附近也有相邻静态数据。
**切片方案已全部回退**，当前 DLL 只保证**单线程**正确。

正确解法是**每线程独立镜像**（各自 `engine_load_image` 一份），
12 份 × 101 MB ≈ 1.2 GB，机器内存够，但未执行。

> ⚠ **对 `authgen_server.py` 的影响**：`ThreadingHTTPServer` 下两个并发请求会踩坏
> 仿真内存。当前 `decrypt_e` 用 `_cache` 按 K 缓存标定结果，同一 K 的重复请求会命中缓存；
> 不同 K 的并发请求仍不安全。**未执行**进程内串行化保护。

---

## 5. 未执行清单

1. 基本块合并 / superinstruction 优化（`<1s` 达标的唯一路径）
2. 每线程独立镜像的 DLL 并发支持
3. `authgen_server.py` 的进程内并发串行化
4. 128 块 PC trace 全量 1.26 亿条差分（C 侧需放开 `TRACE_LIM` 重跑，
   预计单次 trace 文件 1 GB+、耗时 ~20 min）
5. `CONST_b` 生成器（`0x2d9ed0`）的闭式还原 —— 有了它标定可完全跳过引擎

---

## 6. 本轮踩到的坑（详见 `.workbuddy/memory/2026-10-06.md`）

1. `main.c` trace 开关只看 `argc>7` → 传 `"0"` 仍开 trace，639 块计时被 20× 插桩污染
2. `#ifdef` **不能放在多行宏定义内部** —— 预处理指令会截断宏，`DISPATCH()` 后半截掉出宏外，
   连带 `uint8_t *CUR;` 声明被注释掉。插桩开关必须在生成器层面
3. `__declspec(thread)` 在 MinGW/GCC 下被**静默忽略**（只 warning）→ 必须 `__thread`
4. `mkstr` 必须严格复刻：`≤22` 字节走 SSO 内联（首字节 `size<<1`），`>22` 才用 `{cap,len,data}`；
   且返回 **string 对象地址**而非数据缓冲地址
5. DLL 加载缺 `libgcc_s_seh-1.dll` / `libwinpthread-1.dll`，且 Python 3.8+ 不搜索 DLL 目录
6. MinGW `fopen` 按 ANSI 代码页解释字节，工程路径含中文（`囧次元`）时 ctypes 传 UTF-8 打不开
7. `hook_x`（`0x2da498`）**每块触发 2 次**，必须采全部再取偶数位；
   只留奇数次会得到 `CAP_N = nblk/2 + 1`
8. 不能复用 `image128.bin` 跑 639 块：① 输入串长度 L 与块数绑定（128→1534，639→7666）
   ② 该镜像是在一次运行**之后** dump 的，堆上 2.1 MB 是那次运行的垃圾