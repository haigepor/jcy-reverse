# -*- coding: utf-8 -*-
"""gap_analysis.py — 量化「解释器 vs App AOT」差距的真实构成。

目的: 回答「要跟 app 一致的解密手段, 怎么实现」——先算清楚
  (1) 引擎真实 ns/ARM64 指令
  (2) 每请求固定开销(mmap 镜像 + 初始化) vs 边际成本(每块)
  (3) 固定开销占比, 决定下一步该抠哪一头

方法: 用拟合而不是单点测。
  t(N) = fixed + N * per_block
两个规模(128 / 639)各取独立进程 median, 线性拟合求 fixed 与 per_block。
slope 可靠, 单点绝对值不可靠(同进程反复 load 会让数据失效)。
"""
import os, subprocess, sys, statistics, json

HERE = os.path.dirname(os.path.abspath(__file__))
ENG = os.path.join(HERE, "engine_c")
DLL = os.environ.get("GAP_DLL", os.path.join(ENG, "jcy_fuse.dll"))

# 每块的 ARM64 指令数: 来自 128 块参考 trace 1,262,627,948 条
# 减去固定初始化 1,193,590条, 再除以 128
TRACE_128_TOTAL = 1262627948
FIXED_INSN = 1193590
INSN_PER_BLOCK = (TRACE_128_TOTAL - FIXED_INSN) // 128

CHILD = r'''
import ctypes, os, sys, time
sys.path.insert(0, %r)
from c_engine import load
ENG = %r
NB = int(sys.argv[1])
load(%r)
lib = load()
t0 = time.time()
img = os.path.abspath(os.path.join(ENG, "image%%d.bin" %% NB))
assert lib.jcy_init(img.encode()) == 0, lib.jcy_last_error().decode()
t_init = (time.time() - t0) * 1000
K = bytes(range(0x05, 0x15))
pt = open(os.path.join(ENG, "pt%%d.bin" %% NB), "rb").read()
cap = len(pt) + 80
buf = ctypes.create_string_buffer(cap)
assert lib.jcy_encrypt_ex(K, pt, len(pt), buf, cap, 1) > 0
t0 = time.time()
n = lib.jcy_encrypt_ex(K, pt, len(pt), buf, cap, 1)
t_run = (time.time() - t0) * 1000
import hashlib
print("%%.3f %%.3f %%s" %% (t_init, t_run,
      hashlib.sha256(bytes(buf.raw[:n])).hexdigest()[:16]))
''' % (HERE, ENG, DLL)

CHILD_PY = os.path.join(ENG, "_gap_child.py")
open(CHILD_PY, "w", encoding="utf-8").write(CHILD)

ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 5
SIZES = [1, 32, 128, 320, 639]


def measure(nb):
    inits, runs, hs = [], [], set()
    for _ in range(ROUNDS):
        p = subprocess.run([sys.executable, CHILD_PY, str(nb)],
                           capture_output=True, text=True)
        if p.returncode != 0:
            return None, None, p.stderr.strip()[-200:]
        a = p.stdout.strip().split()
        inits.append(float(a[0]))
        runs.append(float(a[1]))
        hs.add(a[2])
    return statistics.median(inits), statistics.median(runs), hs


print("DLL = %s" % os.path.basename(DLL))
print("每块 ARM64 指令数 = %d (来自 128 块参考 trace)" % INSN_PER_BLOCK)
print("每组 %d 个独立进程\n" % ROUNDS)
print("%6s %10s %10s %10s %10s" % ("块数", "init ms", "run ms", "ns/指令", "ms/块"))
data = {}
for nb in SIZES:
    i, r, hs = measure(nb)
    if i is None:
        print("%6d   失败: %s" % (nb, r))
        continue
    data[nb] = (i, r)
    tot_insn = INSN_PER_BLOCK * nb
    ns = r * 1e6 / tot_insn if tot_insn else 0
    print("%6d %10.1f %10.1f %10.3f %10.3f" % (nb, i, r, ns, r / nb))

if 128 in data and 639 in data:
    (i1, r1), (i2, r2) = data[128], data[639]
    slope = (r2 - r1) / (639 - 128)          # ms per block
    fixed = r1 - slope * 128# 拟合截距
    print()
    print("=== 线性拟合 t(N) = fixed + N * slope ===")
    print("  边际 slope      = %.4f ms/块= %.3f ns/ARM64 指令" % (slope, slope * 1e6 / INSN_PER_BLOCK))
    print("  引擎内固定开销= %.1f ms" % fixed)
    print("  jcy_init 实测   = %.1f ms(镜像加载 + 区域映射 + 初始化)" % data[639][0])
    print()
    print("=== 固定开销占比(端到端口径) ===")
    for nb in (3, 30, 84, 168, 539, 639):
        tot = fixed + slope * nb
        print("  %4d 块: 固定 %5.1f ms / 合计 %7.1f ms = %5.1f%%"
              % (nb, fixed, tot, 100.0 * fixed / tot))
    print()
    print("=== 与 App AOT 的差距(按 0.7 ns/指令经验值) ===")
    for nb in (84, 168, 639):
        ours = fixed + slope * nb
        app = 0.7 * INSN_PER_BLOCK * nb / 1e6
        print("  %4d 块: 我们 %7.1f ms  App %6.1f ms  -> %.2f 倍慢"
              % (nb, ours, app, ours / app))
    print()
    print("  若抹掉全部固定开销(常驻/mmap), %d 块降为 %.1f ms"
          % (639, slope * 639))
    print("  App 侧 639 块约 %.1f ms, 抹掉固定开销后仍慢 %.2f 倍 -> 剩余差距是范式差距"
          % (0.7 * INSN_PER_BLOCK * 639 / 1e6,
             (slope * 639) / (0.7 * INSN_PER_BLOCK * 639 / 1e6)))

os.remove(CHILD_PY)
