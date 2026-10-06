# -*- coding: utf-8 -*-
"""probe_xdep2.py — 判定 x_b 对前序明文的依赖（比 probe_xdep 更严格）。

方法: 固定 nblk=8, 只改**第 0 块**的明文, 其余全零。
  - 若 x[1..7] 完全不变 -> x_b 与前序明文无关, 但仍可能依赖前序**密文**。
  - 再测: 固定所有明文, 改 iv -> 若 x[1..7] 变, 则依赖链密文, 不可切分。
这一步直接决定"单请求 639 块能否切成 4 段并行"。
"""
import ctypes, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from c_engine import load

img = os.path.abspath(os.path.join(HERE, "engine_c", "image639.bin"))
K = bytes(range(0x05, 0x15))
lib = load()
print("jcy_init ->", lib.jcy_init(img.encode()))

def cap(nblk, pt, use_iv=True, iv=None):
    rc = lib.jcy_capture_enable(nblk)
    if rc != 0:
        raise RuntimeError(lib.jcy_last_error().decode())
    outcap = len(pt) + 16 + 64
    buf = ctypes.create_string_buffer(outcap)
    if use_iv:
        n = lib.jcy_encrypt_iv(K, iv or bytes(16), pt, len(pt), buf, outcap)
        # 注意: encrypt_iv 不做 capture, 需用 encrypt_ex
        n = lib.jcy_encrypt_ex(K, pt, len(pt), buf, outcap, 1)
    else:
        n = lib.jcy_encrypt_ex(K, pt, len(pt), buf, outcap, 1)
    if n < 0:
        raise RuntimeError(lib.jcy_last_error().decode())
    got = lib.jcy_capture_count()
    out = []
    for i in range(min(nblk, got)):
        b = ctypes.create_string_buffer(16)
        lib.jcy_capture_get(i, b)
        out.append(bytes(b.raw))
    return bytes(buf.raw), out

N = 8
Z = bytes(16)

# 基线
ct0, xa = cap(N, bytes(16 * N))
print("基线 (全零 8 块): ct0[:16]=%s" % ct0[:16].hex())

# 变体A: 第 0 块明文改 0xaa
ptA = bytearray(16 * N)
ptA[0:16] = b'\xaa' * 16
ctA, xA = cap(N, bytes(ptA))
print("变体A (块0 明文=0xaa): ct0[:16]=%s" % ctA[:16].hex())

# 变体B: 第 0..3 块明文改 0xbb
ptB = bytearray(16 * N)
for b in range(4):
    ptB[b*16:(b+1)*16] = b'\xbb' * 16
ctB, xB = cap(N, bytes(ptB))
print("变体B (块0-3 明文=0xbb): ct0[:16]=%s" % ctB[:16].hex())

print("\n=== x_b 依赖分析 ===")
print("%-4s %-34s %-34s %-34s" % ("b", "基线x_b", "变体A x_b(改块0明文)", "变体B x_b(改块0-3明文)"))
for b in range(min(N, len(xa))):
    a = xA[b].hex() if b < len(xA) else "-"
    bb = xB[b].hex() if b < len(xB) else "-"
    print("%-4d %-34s %-34s %-34s" % (b, xa[b].hex(), a, bb))

print("\n=== 结论 ===")
sameA = all(xa[b] == xA[b] for b in range(1, min(N, len(xa), len(xA))))
sameB = all(xa[b] == xB[b] for b in range(4, min(N, len(xa), len(xB))))
print("改块0 明文后, x[1..7] 不变: %s" % sameA)
print("改块0-3 明文后, x[4..7] 不变: %s" % sameB)
if sameA and sameB:
    print("=> x_b 与前序**明文**无关。仍需确认是否依赖前序**密文**(链状态)。")
else:
    print("=> x_b 依赖前序明文, 不能简单切段。")
