# -*- coding: utf-8 -*-
"""tmp_g1_step4x.py — 全 16B 转移仿射求解: rk_{r+1} = M·rk_r ^ c (GF(2)^128)."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr  # noqa: E402

data = json.load(open(os.path.join(HERE, "reports", "gen_rks.json")))

# 样本: (输入16B, 输出16B) 同 r 跨 K 差分
pairs = []
by_r = {}
for Kh, rks in data.items():
    for r in range(1, 8):
        if str(r + 1) not in rks:
            continue
        a = bytes.fromhex(rks[str(r)])
        b = bytes.fromhex(rks[str(r + 1)])
        by_r.setdefault(r, []).append((a, b))

# --- 全转移差分一致性: d_out 只依赖 d_in? ---
consistent = True
chk = {}
for r, lst in by_r.items():
    for i in range(len(lst)):
        for j in range(i + 1, len(lst)):
            di = xr(lst[i][0], lst[j][0])
            do = xr(lst[i][1], lst[j][1])
            if di in chk and chk[di] != do:
                consistent = False
                print("差分矛盾 r=%d di=%s do1=%s do2=%s"
                      % (r, di.hex(), chk[di].hex(), do.hex()))
                break
            chk[di] = do
        if not consistent:
            break
    if not consistent:
        break
print("全转移差分一致性:", consistent, "(唯一差分 %d 个)" % len(chk))

if consistent:
    # 解 M: 128x128 GF(2). 用高斯消元: 每个输出字节位 = 线性组合输入位 + 常数
    # 构造: 找 128 个线性独立差分向量作为基
    basis = []   # (d_in_int, d_out_int)
    seen = set()
    for di, do in chk.items():
        v = int.from_bytes(di, "big")
        if v == 0:
            continue
        basis.append((v, int.from_bytes(do, "big")))
    # 高斯: 选独立集
    ind = []
    pivots = {}
    for v, o in basis:
        x = v
        for pv, (pvv, _) in list(pivots.items()):
            pass
        # 简化: 逐位消元
        cur = x
        row_out = o
        for pbit, (prow_in, prow_out) in sorted(pivots.items(), reverse=True):
            if cur >> pbit & 1:
                cur ^= prow_in
                row_out ^= prow_out
        if cur:
            hb = cur.bit_length() - 1
            pivots[hb] = (cur, row_out)
            ind.append((cur, row_out))
        # 线性相关 → 一致性已验证, 跳过
    print("独立差分基:", len(ind))
    if len(ind) < 128:
        print("!! 基不足 128, 仿射解不唯一")
        sys.exit(0)

    # 求每个输出位 about M 列: g(w) = M·w ^ c; 用 w=0 无样本 → c 由差分结构:
    # 对差分 d: out 差 = M·d (与 c 无关) ✓ 已有. c 需要绝对样本: rk_{r+1} = M·rk_r ^ c
    # 用任一样本 (a,b): c = b ^ M·a
    # 解 M: 对每个输出位 i (0..127), M 行 i 满足: <M_i, d> = do_bit_i 对所有基
    # 高斯消元解 128 元方程组 per 输出位 → 太重; 改为: M 的列 j 满足 M·e_j
    # 由基解出 M·d 对所有 d → 用基表达 e_j = Σ α_k d_k → M·e_j = Σ α_k do_k
    # 基构成上三角消元结构 → 直接回代
    # 排序为上三角: pivots[hb] = (d, do) 其中 d 最高位 = hb
    rows = sorted(pivots.values(), key=lambda t: t[0].bit_length() - 1)
    # 完整消元成 reduced 形式
    for i in range(len(rows)):
        hb_i = rows[i][0].bit_length() - 1
        for j in range(len(rows)):
            if j == i:
                continue
            if rows[j][0] >> hb_i & 1:
                rows[j] = (rows[j][0] ^ rows[i][0], rows[j][1] ^ rows[i][1])
    # 现在 rows 每行 d 是 2 的幂 (e_j)?? 不一定 — 再验证
    emap = {}
    for d, o in rows:
        if d.bit_count() == 1:
            emap[d.bit_length() - 1] = o
    if len(emap) != 128:
        print("!! reduced 后单位向量仅 %d 个" % len(emap))
        sys.exit(0)

    def matmul(v_int):
        # M·v = Σ_j v_j · M·e_j  (v 位 j)
        out = 0
        j = 0
        vv = v_int
        while vv:
            if vv & 1:
                out ^= emap.get(j, 0)
            vv >>= 1
            j += 1
        return out

    # 常数 c: 用第一个样本
    a0, b0 = next(iter(by_r[1]))
    c = int.from_bytes(b0, "big") ^ matmul(int.from_bytes(a0, "big"))

    # 验证全部转移
    bad = 0
    for r, lst in by_r.items():
        for a, b in lst:
            pred = matmul(int.from_bytes(a, "big")) ^ c
            if pred != int.from_bytes(b, "big"):
                bad += 1
    print("转移验证: %d/%d 失败" % (bad, sum(len(v) for v in by_r.values())))
    if bad == 0:
        json.dump({"M_rows_emap": {str(j): format(o, "x") for j, o in emap.items()},
                   "c": format(c, "x")},
                  open(os.path.join(HERE, "reports", "gen_schedule.json"), "w"))
        print("已存 reports/gen_schedule.json")
