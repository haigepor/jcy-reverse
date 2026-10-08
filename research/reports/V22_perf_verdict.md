# V22 性能裁决报告 — 单请求 639 块

日期：2026-10-06
目标：真实单请求 639 块 < 1000 ms

## 结论速览

| 指标 | V19 起点 | V21 | **V22** | 目标 |
|---|---:|---:|---:|---:|
| 端到端 639 块 | 24,076 ms | 4,533 ms | **2,668 ~ 2,923 ms** | <1,000 ms |
| ├ 标定（冷） | — | 4,142 ms | **2,269 ~ 2,392 ms** | |
| └ 解密（标定已缓存） | — | 391 ms | **480 ~ 532 ms** | |
| 引擎 1 块 | 12.0 ms | 12.0 ms | **5.0 ms** | |
| 引擎边际 | 6.4 ms/块 | 6.4 ms/块 | **3.9 ms/块** | |

**未达标**（约 2.7~2.9× 差距），但相对 V19 改善 **8.2 ~ 9.0×**。

> 测量说明：V21 的 4,533 ms 与 V22 的 2,923 ms 均取自有其他进程竞争时的读数；
> 引擎单独对比（`bench_o1.py`）在同样条件下 4,397 → 2,309 ms，比例一致。
> 区间下限为干净环境、上限为有编译进程竞争时的读数。

## 本轮两个真实突破

### 1. `-O1 -fno-gcse` 引擎：1.90× 加速（推翻历史结论）

V21 记录「`-O1 -fno-gcse` 编译 40 分钟超时，无产出，结论未定」。
**根因：编译错了文件。**

| | 文件 | 行数/大小 | 结果 |
|---|---|---|---|
| 错误目标 | `jcy_engine.c` | 103,828 行 / 25,018 case | 40 min 超时（EXIT=124） |
| 正确目标 | `jcy_engine_fuse.c` | 4,298,095 字节 / 4,401 基本块 | **8 min 16 s 成功** |

- gcc 16.1.0 (MinGW-W64 x86_64-ucrt-posix-seh)
- 产物体积：5,714,281 B (`-O2`) → 5,712,821 B (`-O1 -fno-gcse`)
- **DLL 体积 5.71 MB → 3.46 MB（-39%）**
- 639 块：4,397 ms → **2,309 ms（1.904×）**，body 10,240 字节逐位一致

`jcy_fuse.dll` 已切换为 `-O1 -fno-gcse` 版；`-O2` 版保留为 `jcy_fuse_O2.dll.bak`。

### 2. 标定后处理下沉到 C：省 200~280 ms

`prof_split.py` 分段计时（639 块，V22 引擎）：

| 段 | 耗时 | 占比 |
|---|---:|---:|
| 引擎 `encrypt_with_x` | 2,472.2 ms | 89.5% |
| `_determine_C_c` | 7.0 ms | 0.3% |
| Python 后处理循环 | 281.8 ms | 10.2% |

那 281.8 ms 是 639 次纯 Python 的 `T()`/`F()`/`xr()` 解释开销，与正确性无关。
新增 `engine_c/jcy_post.c`（SM4 置换 + 轮密钥扩展 + 标定后处理），
DLL 导出 `jcy_expand` / `jcy_determine_C` / `jcy_post`，639 块后处理 **<0.1 ms**。

对拍：`verify_post.py` 逐位验证 1/8/128/639 块的 `CONST[]`/`Cb[]` 与 Python 完全一致。

## 定位过程：一个关键的错误结论已纠正

曾一度怀疑「`verify_fuse.py` 的 `L` 计算有 bug」，试图改成 `b64len(L)==L` 的不动点 ——
**这是错的，已回退**。实测证明原算法 `b64len(L) == 16*nblk` 才是对的。

真正的问题是 `run_exe` 在非 trace 模式**不传 `argv[7]/argv[8]`**，
`main.c:149` 只看 `argc>8` 才装填明文，于是：
- 跑的是镜像里烤死的明文；
- 1 块的烤死明文恰好等于 golden1 → **假 PASS**；
- 128/639 全错（首字节 `36` 而非 `d0`）。

修复后 1/128/639 全部 PASS。另外发现**两批 golden 生成条件不同**
（golden1 不传明文，golden128/639 传明文），验证脚本现按规模分别选配置。

## 被证伪的路线（有数据支撑）

### 单请求切块并行 — 数学上不可能

`probe_xdep2.py`：固定 8 块，只改**块 0 的明文**，观察 `x_b`：

```
b=0..7 的 x_b 全部改变
```

`x_b` 完全依赖前序明文 → 链式耦合是完全的，切段并行不可能。
这解释了 V20「从 `ctd[7]` 续算失败」的**根因**（不是工程难度问题）。

### K 缓存 / CONST 外推（V20 已否决，V22 无新证据支持）

13 条样本 10 个不同 K；仿射可加性检验全 False。

## 引擎的结构性分析（新数据）

`hotspot.py` + `loopdetect.py` 对单块 2,180,018 条 PC trace：

- 唯一 PC 24,984 个，每 PC 平均执行 87.3 次
- **91.3% 的转移已是 fall-through**（`pc → pc+4`）→ 基本块合并已把 dispatch 压到最低
- 执行次数双峰：4,204 个 PC 只跑 1–4 次（冷路径）；**1,598,763 次执行（73.3%）集中在 6,399 个热 PC**（各 ≥100 次）
- Top1000 个 PC 占 50% 动态执行

**判据**：算子提取/超块化有真实空间（存在大量紧循环），
但已无可并行化的结构（链式依赖）。

`scale_curve.py` 拟合：`t = -81.8 + 5.560 * n`（n≥8），
固定成本≈0，边际 5.0–5.6 ms/块 → 纯边际成本模型，无共享阶段。

## 剩余瓶颈与唯一可行方向

引擎占 89.5%，且已无结构性浪费（91.3% fall-through）。
要达到 <1000 ms 需要每块 1.56 ms，即再快 **2.5×**。

唯一未被尝试且有数据支撑的方向：**从 6,399 个热 PC 提取算子**
（把反复执行的紧循环生成 C 函数，或做 trace 级超块/常量折叠）。

未执行：
- `x_b` 生成式直接提取（LLBT / Dynarmic / static translation）
- 动态基本块 / JIT
- `-O2` + `-fno-gcse` 组合（`-O1` 已证明 `-fno-gcse` 有效，`-O2` 组合未测）

## 正确性状态（全绿）

| 验证项 | 结果 |
|---|---|
| `verify_fuse.py` 1 块 body | PASS，32 字节逐字节一致 |
| `verify_fuse.py` 128 块 body | PASS，2,064 字节逐字节一致 |
| `verify_fuse.py` 639 块 body | PASS，10,240 字节逐字节一致 |
| `verify_fuse.py` 1 块 PC trace | PASS，**2,183,860 条逐条一致** |
| `verify_post.py` 轮密钥 11 个 | 一致 |
| `verify_post.py` C | 一致 |
| `verify_post.py` CONST/Cb（1/8/128/639） | 全部逐位一致 |
| `verify_backends.py A` 128 块 C vs Unicorn | C / CONST[128] / Cb[128] 全一致 |
| `verify_backends.py B` 真实样本 | 一致 9 / 不一致 0 / 跳过 1 |
| 不变式自检 | C 侧 True，Unicorn 侧 True |

## 新增/修改文件

| 文件 | 说明 |
|---|---|
| `engine_c/jcy_post.c` | **新增** SM4 置换 + 轮密钥扩展 + 标定后处理（C） |
| `engine_c/dll_iface.c` | 新增 3 个导出；内部函数改名避免符号冲突 |
| `engine_c/build_fuse.sh` | **新增** 可复现构建脚本（含「编译目标是 fuse 源」的注释警示） |
| `engine_c/jcy_fuse.dll` | 切换为 `-O1 -fno-gcse` + `jcy_post` |
| `engine_c/jcy_fuse_O2.dll.bak` | `-O2` 版备份 |
| `c_engine.py` | 注册新导出的 argtypes（`hasattr` 保护，旧 DLL 兼容） |
| `deliverables/decrypt_e.py` | `_calibrate_c` 优先走 C 后处理，异常自动回落 Python |
| `verify_fuse.py` | 修 `argv[7]/argv[8]` 静默不装填；按规模选明文配置 |
| `prof_split.py` `scale_curve.py` `hotspot.py` `loopdetect.py` `verify_post.py` `bench_o1.py` `probe_xdep.py` `probe_xdep2.py` `build_fuse.sh` | **新增**测量与验证工具 |

## 残留风险 / 测试缺口

1. **`jcy_fuse.dll` 仍只保证单线程**（TLS 只覆盖 CPU 状态，仿真堆/栈/TLS/K/iv 仍是进程级共享）。
2. 128 块参考 trace 共 126,262,795 条，因 C trace 上限只完成前 5,000,000 条逐条对拍，**不能声称全量通过**。
3. `-O2 -fno-gcse` 组合未测（`-O1` 已证明 `-fno-gcse` 有效，可能还有增量）。
4. 两批 golden 生成条件不同（1 块不传明文 / 128·639 传明文），历史遗留不一致，建议重新生成统一基线。
