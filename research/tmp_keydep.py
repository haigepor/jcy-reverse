# -*- coding: utf-8 -*-
"""tmp_keydep.py — CONST_b 对密钥 K 的依赖关系。

若 CONST_b 与 K 无关 → 预计算一次即可，解密纯 Python 秒出。
若为简单依赖（如 CONST_b(K) = f(b) ^ g(K)）→ 也能大幅简化。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import EDecryptor, expand, F, F_inv, xr  # noqa: E402

NB = 12


def main():
    d = EDecryptor()
    K1 = bytes(range(16))
    K2 = bytes(range(16, 32))
    K3 = bytes(16)
    _, rk1, C1, Cb1 = d.calibrate(K1, NB)
    _, rk2, C2, Cb2 = d.calibrate(K2, NB)
    _, rk3, C3, Cb3 = d.calibrate(K3, NB)
    C1 = [bytes(x) for x in C1]
    C2 = [bytes(x) for x in C2]
    C3 = [bytes(x) for x in C3]

    print("K1 =", K1.hex())
    print("K2 =", K2.hex())
    print("\n b  CONST_b(K1)                        CONST_b(K2)                        XOR")
    for b in range(1, NB):
        print("%2d  %s  %s  %s"
              % (b, C1[b].hex(), C2[b].hex(), xr(C1[b], C2[b]).hex()))

    print("\n-- CONST_b(K1)^CONST_b(K2) 是否恒定 --")
    xs = [xr(C1[b], C2[b]) for b in range(1, NB)]
    print("  唯一值数:", len(set(xs)), " 首个:", xs[0].hex())

    print("\n-- CONST_b(K1)^CONST_b(K3) --")
    for b in range(1, 6):
        print("  b=%d %s" % (b, xr(C1[b], C3[b]).hex()))

    print("\n-- 是否 CONST_b(K) = E_K(固定值) 型：检查 CONST_b(K1)^CONST_b(K2) 是否等于 K1^K2 派生 --")
    print("  K1^K2 =", xr(K1, K2).hex())
    print("  K1^K3 =", xr(K1, K3).hex())
    for b in range(1, 5):
        print("  b=%d CONSTxor=%s  ==K1^K2? %s" % (b, xr(C1[b], C2[b]).hex(), xr(C1[b], C2[b]) == xr(K1, K2)))

    # 保存
    import json
    json.dump({"K1": K1.hex(), "K2": K2.hex(),
               "C1": [x.hex() for x in C1], "C2": [x.hex() for x in C2],
               "C3": [x.hex() for x in C3]},
              open(os.path.join(HERE, "tmp_keydep.json"), "w"), indent=1)
    print("\n已存 research/tmp_keydep.json")


if __name__ == "__main__":
    main()
