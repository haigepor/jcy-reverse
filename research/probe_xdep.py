# -*- coding: utf-8 -*-
"""probe_xdep.py —判定 x_b 是否依赖前序块（决定单请求能否切块并行）。

逻辑:
  若 x_b 只依赖 (K, b) 而与前序链状态无关, 则 639 块可以切成 4 段并行,
  每段独立跑, 理论 4x -> 5.6ms/块 降到 1.4ms/块, 总耗时约 900ms, 达标。
  若 x_b 依赖前序, 则必须串行, 多进程路线彻底否决。

测法: 用 C 引擎 capture 拿 x_b。跑 (a) 一次 8 块, (b) 单独跑第 b 块。
  比较两次的 x_b。x_b 一致 => 独立。
注意: 引擎的 iv 可控 (encrypt_with_iv), 用全零 iv 排除链状态影响。
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from c_engine import load

img = os.path.abspath(os.path.join(HERE, "engine_c", "image639.bin"))
K = bytes(range(0x05, 0x15))
Z = bytes(16)

lib = load()
rc = lib.jcy_init(img.encode())
print("jcy_init ->", rc)

def cap(nblk, pt):
    import ctypes
    rc = lib.jcy_capture_enable(nblk)
    if rc != 0:
        raise RuntimeError("cap_enable: %s" % lib.jcy_last_error().decode())
    outcap = len(pt) + 16 + 64
    buf = ctypes.create_string_buffer(outcap)
    n = lib.jcy_encrypt_ex(K, pt, len(pt), buf, outcap, 1)
    if n < 0:
        raise RuntimeError("enc: %s" % lib.jcy_last_error().decode())
    got = lib.jcy_capture_count()
    out = []
    for i in range(min(nblk, got)):
        b = ctypes.create_string_buffer(16)
        lib.jcy_capture_get(i, b)
        out.append(bytes(b.raw))
    return bytes(buf.raw), out

N = 8
# (a) 一次跑 8 块
_, xa = cap(N, bytes(16 * N))
print("(a) 8 块一次跑:捕获 %d 条" % len(xa))
for i, x in enumerate(xa):
    print("    x[%d] = %s" % (i, x.hex()))

# (b) 每块单独跑 (改 pt 只有 1 块, 但用不同偏移的"填充"模拟)
# 关键: 单块跑时 x_0 就是 x_0, 与 a 的 x_0 比
_, xb = cap(1, bytes(16))
print("(b) 单独跑 1 块: x[0] = %s" % xb[0].hex())
print()
print("=== 结论 ===")
if xa and xb and xa[0] == xb[0]:
    print("x_0 在两种方式下一致 -> x_b 不依赖链状态(至少首块)")
else:
    print("x_0 不一致 -> x_b 依赖链状态, 单请求切块不可行")
