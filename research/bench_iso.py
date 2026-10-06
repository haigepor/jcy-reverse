# -*- coding: utf-8 -*-
"""bench_iso.py — 进程隔离的单次计时, 消除同进程内 DLL 反复 load/unload 的偏差。

背景: bench_ab.py 交替测量出现 V22 在 1851~5526 ms 间波动(3 倍),
而两个 DLL 的差异只有几百 ms。这说明**同进程内反复 load 101MB 镜像**
让 malloc/页表状态不可控, 测量本身失效。

方案: 每个 (DLL, 轮次) 起一个独立子进程, 进程内只做
一次 init + 一次加密 -> 打印耗时 -> 退出。进程退出后所有
内存状态归零, 组间完全可比。
"""
import os, subprocess, sys, statistics

HERE = os.path.dirname(os.path.abspath(__file__))
ENG = os.path.join(HERE, "engine_c")

CHILD = r'''
import ctypes, os, sys, time
sys.path.insert(0, %r)
from c_engine import load
ENG = %r
K = bytes(range(0x05, 0x15))
NB = int(sys.argv[2])
dll = os.path.join(ENG, sys.argv[1])
load(dll)
lib = load()
got = os.path.abspath(getattr(lib, "_name", ""))
assert got == os.path.abspath(dll), "DLL mismatch: %%s" %% got
img = os.path.abspath(os.path.join(ENG, "image%%d.bin" %% NB))
assert lib.jcy_init(img.encode()) == 0, lib.jcy_last_error().decode()
pt = open(os.path.join(ENG, "pt%%d.bin" %% NB), "rb").read()
rc = lib.jcy_capture_enable(NB)
assert rc == 0, lib.jcy_last_error().decode()
cap = len(pt) + 80
buf = ctypes.create_string_buffer(cap)
t0 = time.time()
n = lib.jcy_encrypt_ex(K, pt, len(pt), buf, cap, 1)
dt = (time.time() - t0) * 1000
assert n > 0, lib.jcy_last_error().decode()
import hashlib
print("%%.2f %%s" %% (dt, hashlib.sha256(bytes(buf.raw[:n])).hexdigest()[:16]))
''' % (HERE, ENG)

CHILD_PY = os.path.join(ENG, "_bench_child.py")
open(CHILD_PY, "w", encoding="utf-8").write(CHILD)

NB = int(sys.argv[1]) if len(sys.argv) > 1 else 639
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 7
DLLS = [("V22", "jcy_fuse.dll"), ("V23", "jcy_fuse_fast.dll")]

data = {}
hashes = {}
print("进程隔离测量, %d 块, 每组 %d 个独立进程\n" % (NB, ROUNDS))
for tag, dll in DLLS:
    vals = []
    for r in range(ROUNDS):
        p = subprocess.run([sys.executable, CHILD_PY, dll, str(NB)],
                           capture_output=True, text=True)
        if p.returncode != 0:
            print("  %s 第%d轮失败: %s" % (tag, r+1, p.stderr.strip()[-200:]))
            break
        parts = p.stdout.strip().split()
        vals.append(float(parts[0]))
        hashes.setdefault(tag, set()).add(parts[1])
    data[tag] = vals
    print("  %s: %s" % (tag, "  ".join("%.0f" % v for v in vals)))

os.remove(CHILD_PY)
print()
for tag, _ in DLLS:
    v = data.get(tag) or []
    if not v:
        continue
    print("%-4s min=%7.1f  median=%7.1f  mean=%7.1f  stdev=%6.1f  极差=%6.1f"
          % (tag, min(v), statistics.median(v), statistics.mean(v),
             statistics.stdev(v) if len(v) > 1 else 0, max(v) - min(v)))

if all(data.get(t) for t, _ in DLLS):
    a, b = statistics.median(data["V22"]), statistics.median(data["V23"])
    print()
    print("median: V22=%.0f  V23=%.0f  ->  %.2fx  %s"
          % (a, b, a / b, "加速" if b < a else "变慢"))
    print("body sha256 一致: %s" % (len(hashes["V22"]) == 1 and hashes["V22"] == hashes["V23"]))
    for t, _ in DLLS:
        print("  %s sha=%s" % (t, list(hashes[t])[0]))