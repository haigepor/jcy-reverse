# -*- coding: utf-8 -*-
"""tmp_g1_step5r.py — 双表对比 + 阈值谓词检验."""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
import decrypt_e as de  # noqa: E402

SO = de._SO
T1 = SO[0x1DFC00:0x1DFC00 + 256]
T2 = SO[0x1DFD10:0x1DFD10 + 256]
# 前缀一致长度
n = 0
while n < 256 and T1[n] == T2[n]:
    n += 1
print("两表前缀一致长度:", n)
diff = [i for i in range(256) if T1[i] != T2[i]]
print("不同的项数:", len(diff), "范围:", (min(diff), max(diff)) if diff else None)
print("T2 尾部 16 字节:", T2[240:].hex())

br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
Aset = set(br["grpA"])
data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))
items = [(bytes.fromhex(kh), 0 if kh in Aset else 1) for kh in data]
X = [K for K, _ in items]
Y = [y for _, y in items]


def sep(fn, name):
    va = {fn(K) for K, y in zip(X, Y) if y == 0}
    vb = {fn(K) for K, y in zip(X, Y) if y == 1}
    ok = not (va & vb) and va and vb
    if ok:
        print("命中:", name, "A→", sorted(va)[:6], "B→", sorted(vb)[:6])
    return ok


print("\n=== 阈值谓词 ===")
found = False
for p in range(16):
    for L in (n, n - 1, n + 1, 0x80, 0x40):
        if sep(lambda K, p=p, L=L: K[p] >= L, "K[%d]>=%d" % (p, L)):
            found = True
        if sep(lambda K, p=p, L=L: de.SBOX[K[p]] >= L, "SB(K[%d])>=%d" % (p, L)):
            found = True
        if sep(lambda K, p=p, L=L: de.ISBOX[K[p]] >= L, "iSB(K[%d])>=%d" % (p, L)):
            found = True
if not found:
    print("单字节阈值无命中")

# 谓词 = SB(v) 表切换: 检验 T2 作为替代盒时, 残差字头 σ 与 SB 差的关系
# delta_wordhead = T1[b] ^ T2[b] (若 mux 发生在该字节)
print("\n=== 残差字头 vs 表差检验 ===")
def mk_M(rec):
    emap = {int(k): int(v, 16) for k, v in rec["emap"].items()}

    def M(v_int):
        out, vv, j = 0, v_int, 0
        while vv:
            if vv & 1:
                out ^= emap.get(j, 0)
            vv >>= 1
            j += 1
        return out
    return M


M1 = mk_M(br["A"]["1"])
c1 = int(br["A"]["1"]["c"], 16)
heads = {}
for kh in br["grpB"]:
    K = int.from_bytes(bytes.fromhex(kh), "big")
    actual = int.from_bytes(bytes.fromhex(data[kh]["rks"]["1"]), "big")
    delta = actual ^ (M1(K) ^ c1)
    b0 = delta & 0xFF  # little-end? int big-end: 字头 = 最高字节
    hh = (delta >> 120) & 0xFF
    heads.setdefault(hh, []).append(kh[:8])
print("残差字头值分布:", {format(k, "02x"): len(v) for k, v in heads.items()})
# 表差值集合
tvals = sorted({T1[i] ^ T2[i] for i in range(256)})
print("T1^T2 差值集合:", [format(v, "02x") for v in tvals][:20])
