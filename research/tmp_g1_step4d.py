# -*- coding: utf-8 -*-
"""tmp_g1_step4d.py — 闭式假设扫描。
假设：tweak_b = AES9 型函数 F(x_b, rk)（±C 输出常数），x_b 由块号 b 构造。
金料：const_golden.json（8 密钥 × 128 块）。
附加：把 churn 热读的 .bss 16B 单元作为候选轮密钥尝试。
"""
import os
import sys
import json
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import expand, F, xr, _b64len  # noqa: E402

gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
K0 = bytes.fromhex(list(gold)[0])
print("金料 keys=%d, blocks/key=%d, K0=%s" % (
    len(gold), len(gold[K0.hex()]), K0.hex()))


def counter_xs(b):
    """块号 → 候选 16B 输入。"""
    xs = []
    xs.append(struct.pack("<Q", b) + bytes(8))
    xs.append(bytes(8) + struct.pack("<Q", b))
    xs.append(struct.pack(">Q", b) + bytes(8))
    xs.append(bytes(8) + struct.pack(">Q", b))
    xs.append(struct.pack("<I", b) + bytes(12))
    xs.append(bytes(12) + struct.pack("<I", b))
    xs.append(struct.pack(">I", b) + bytes(12))
    xs.append(bytes(12) + struct.pack(">I", b))
    xs.append(struct.pack("<I", b) * 4)
    xs.append(struct.pack(">I", b) * 4)
    xs.append(struct.pack("<QQ", b, b))
    xs.append(bytes([b]) * 16)
    xs.append(struct.pack("<Q", b + 1) + bytes(8))
    xs.append(bytes(8) + struct.pack("<Q", b + 1))
    return xs


def F_variants(x, rk):
    """F 及常见变体输出。"""
    outs = [("F", F(x, rk))]
    # F 后再过一次 T（捕获即 T 后值）
    from decrypt_e import T
    outs.append(("F^T", bytes(T(list(F(x, rk))))))
    return outs


# --- 主扫描：K 自身的 rk
hits = []
for kh, consts_hex in gold.items():
    K = bytes.fromhex(kh)
    consts = [bytes.fromhex(c) for c in consts_hex]
    rk = expand(K)
    iv = K[::-1]
    n = len(consts)
    found = False
    for xi in range(len(counter_xs(0))):
        for mode in ("per_b", "chain"):
            if mode == "per_b":
                ok = True
                for b in range(n):
                    x = counter_xs(b)[xi]
                    got = dict(F_variants(x, rk)).values()
                    if consts[b] not in got and xr(consts[b], iv) not in got:
                        ok = False
                        break
                if ok:
                    hits.append((kh, xi, mode))
                    found = True
            else:  # chain: x_b = prev_const ^ counter
                ok = True
                prev = bytes(16)
                for b in range(n):
                    x = xr(prev, counter_xs(b)[xi])
                    got = dict(F_variants(x, rk)).values()
                    if consts[b] not in got and xr(consts[b], iv) not in got:
                        ok = False
                        break
                    prev = consts[b]
                if ok:
                    hits.append((kh, xi, mode))
                    found = True
        if found:
            break
    if not found:
        print("  K#%s: 无命中" % kh[:16])
    else:
        print("  K#%s ✅ xi=%d %s" % (kh[:16], hits[-1][1], hits[-1][2]))

print("\n命中: %s" % (hits if hits else "无"))

# --- 附加：bss 单元作轮密钥（仅 K0，快速试）
# （bss dump 需在线取，这里先做纯离线部分）
