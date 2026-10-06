# -*- coding: utf-8 -*-
"""tmp_g1_step4v.py — 提取 9 把 K 的生成器轮密钥存档 + 调度结构离线破解。"""
import sys
import os
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import xr  # noqa: E402
from tmp_g1_step4t import harvest, extract_rks  # noqa: E402

out_path = os.path.join(HERE, "reports", "gen_rks.json")
data = {}
keys = [bytes(range(0x30, 0x40))]
gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
keys += [bytes.fromhex(k) for k in gold]

for K in keys:
    tr = harvest(K, 1)
    rks = extract_rks(tr, 0)
    data[K.hex()] = {str(r): rks[r].hex() for r in sorted(rks)}
    print("K=%s rk1=%s" % (K.hex()[:8], rks[1].hex()))

json.dump(data, open(out_path, "w"), indent=1)
print("已存", out_path)

# ---- 离线结构分析 ----
print("\n=== 词链结构检验（标准 AES 递推） ===")
okall = True
for K, rks in data.items():
    for r in range(1, 7):
        a = bytes.fromhex(rks[str(r)])
        b = bytes.fromhex(rks[str(r + 1)])
        aw = [a[i:i + 4] for i in range(0, 16, 4)]
        bw = [b[i:i + 4] for i in range(0, 16, 4)]
        c1 = xr(bw[1], aw[1]) == xr(bw[0], aw[0])
        c2 = xr(bw[2], aw[2]) == bw[1]
        c3 = xr(bw[3], aw[3]) == bw[2]
        if not (c1 and c2 and c3):
            okall = False
            print("  K=%s r=%d 链失效 c1=%s c2=%s c3=%s"
                  % (K[:8], r, c1, c2, c3))
print("词链（标准递推）全部成立?" , okall)

# 列链变体: bw[i] ^ aw[i] == bw[i-1] 用列取词 bw_col[i] = b[4i..]？已试词。
# 变体: T 转置布局下的链
print("\n=== T 转置布局词链检验 ===")
def Tt(v):
    return bytes(v[4 * j + i] for i in range(4) for j in range(4))

okT = True
for K, rks in data.items():
    for r in range(1, 7):
        a = Tt(bytes.fromhex(rks[str(r)]))
        b = Tt(bytes.fromhex(rks[str(r + 1)]))
        aw = [a[i:i + 4] for i in range(0, 16, 4)]
        bw = [b[i:i + 4] for i in range(0, 16, 4)]
        if not (xr(bw[1], aw[1]) == xr(bw[0], aw[0])
                and xr(bw[2], aw[2]) == bw[1] and xr(bw[3], aw[3]) == bw[2]):
            okT = False
            break
    if not okT:
        break
print("T 转置词链成立?", okT)

# g 表采样：t_r[0] = g(rk_r[word])
print("\n=== g 样本 ===")
samples = []
for K, rks in data.items():
    for r in range(1, 8):
        if str(r + 1) not in rks:
            continue
        a = bytes.fromhex(rks[str(r)])
        b = bytes.fromhex(rks[str(r + 1)])
        t0 = xr(b[:4], a[:4])
        samples.append((K, r, a[12:16], t0))
print("样本数", len(samples))
for K, r, w, t in samples[:6]:
    print("  K=%s r=%d in=%s out=%s" % (K[:8], r, w.hex(), t.hex()))
json.dump([{"K": K.hex(), "r": r, "in": w.hex(), "out": t.hex()}
           for K, r, w, t in samples],
          open(os.path.join(HERE, "reports", "g_samples.json"), "w"), indent=1)
