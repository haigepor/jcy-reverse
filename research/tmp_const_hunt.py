# -*- coding: utf-8 -*-
"""tmp_const_hunt.py — 判定 CONST_b 序列是否为「低维线性递推」（LFSR 型）。

若 {CONST_b ^ CONST_1} 张成的 GF(2) 空间维数很小（比如 ≤16），
说明 CONST_b 由一个低阶 LFSR 生成 → 只要还原那几项就能纯 Python 算全部，
解密即可摆脱 Unicorn（0.53s/块 → 0.0017s/块）。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import EDecryptor  # noqa: E402

N = 64


def rank_gf2(vectors):
    basis = []
    for v in vectors:
        x = int.from_bytes(v, "big")
        for b in basis:
            x = min(x, x ^ b)
        if x:
            basis.append(x)
            basis.sort(reverse=True)
    return len(basis)


def span_contains(vectors, target):
    basis = []
    for v in vectors:
        x = int.from_bytes(v, "big")
        for b in basis:
            x = min(x, x ^ b)
        if x:
            basis.append(x)
            basis.sort(reverse=True)
    x = int.from_bytes(target, "big")
    for b in basis:
        x = min(x, x ^ b)
    return x == 0


def main():
    d = EDecryptor()
    K = bytes(range(16))
    C, rk, CONST, Cb = d.calibrate(K, N)
    CONST = [bytes(x) for x in CONST]
    Cb = [bytes(x) for x in Cb]

    print("b : CONST_b                                    Cb_b")
    for b in range(0, 12):
        print("%2d: %s  %s" % (b, CONST[b].hex(), Cb[b].hex()))

    # 1) 差分关系
    for start in (0, 1, 2):
        ok = all(bytes(a ^ b2 for a, b2 in zip(CONST[b], Cb[b])) == CONST[b + 1]
                 for b in range(start, N - 1))
        print("关系 CONST_b ^ Cb_b == CONST_{b+1} (b>=%d): %s" % (start, ok))

    # 2) Cb 是否也落在低维空间
    print("\n-- 线性维数（GF(2) rank）--")
    for name, seq in (("CONST_b^CONST_1", [bytes(a ^ b2 for a, b2 in zip(CONST[b], CONST[1]))
                                           for b in range(1, N)]),
                      ("Cb_b", Cb[1:]),
                      ("CONST_b", CONST[1:])):
        r = rank_gf2(seq)
        print("  %-18s rank = %3d / 128   (样本 %d)" % (name, r, len(seq)))

    # 3) 关键判定：CONST_b 能否由前几项线性组合出来（= 低阶 LFSR）
    for order in (1, 2, 3, 4, 6, 8):
        preds = [bytes(a ^ b2 for a, b2 in zip(CONST[i], CONST[i + order]))
                 for i in range(1, N - order)]
        r = rank_gf2(preds)
        # 若 rank 很小，说明是 order 阶递推
        print("  递推假设 CONST_{b+%d} 与 CONST_b 之差 的 rank = %d" % (order, r))

    # 4) 直接检验：CONST_b 是否 = A·CONST_{b-1} ^ B（仿射、线性映射）
    #    用 1..N-1 求 A（若存在且唯一），再验证
    pairs = [(CONST[b], CONST[b + 1]) for b in range(1, N - 1)]
    rk = rank_gf2([p[0] for p in pairs])
    print("\n-- 仿射假设 CONST_{b+1} = A·CONST_b ^ B --")
    print("  输入集 rank = %d（<128 则 A 不唯一，无法判定）" % rk)

    # 5) 是否与 ctd（全零 dummy 的密文）有关
    print("\n-- 相邻项 XOR 观察 --")
    for b in range(1, 8):
        print("  CONST_%d ^ CONST_%d = %s" % (b, b + 1,
              bytes(a ^ c for a, c in zip(CONST[b], CONST[b + 1])).hex()))


if __name__ == "__main__":
    main()
