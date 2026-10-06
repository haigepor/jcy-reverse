# -*- coding: utf-8 -*-
"""tmp_g1_step5c.py — 链自洽验证 + 末轮 H2 仿射 + 汇总."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, SBOX, ISBOX, _gmul  # noqa: E402

data = json.load(open(os.path.join(HERE, "reports", "gen_rks2.json")))
items = []
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    items.append({"K": K, "iv": K[::-1],
                  "preSB0": bytes.fromhex(rec["preSB0"]),
                  "rks": {int(r): bytes.fromhex(v) for r, v in rec["rks"].items()},
                  "g1": bytes.fromhex(rec["golden1"]) if rec.get("golden1") else None})


def SB(b):
    return bytes(SBOX[x] for x in b)


def iSB(b):
    return bytes(ISBOX[x] for x in b)


def MC(x):
    out = []
    for c4 in range(4):
        a, b, cc, dd = x[4 * c4:4 * c4 + 4]
        out.extend((_gmul(a, 2) ^ _gmul(b, 3) ^ cc ^ dd,
                    a ^ _gmul(b, 2) ^ _gmul(cc, 3) ^ dd,
                    a ^ b ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                    _gmul(a, 3) ^ b ^ cc ^ _gmul(dd, 2)))
    return bytes(out)


# ---------- 链自洽: preSB0 + rk1 → 重算 rk2..rk8 对比 ----------
print("=== 链自洽验证 ===")
mismatch = 0
for it in items:
    st = it["preSB0"]
    for r in range(1, 9):
        st = xr(MC(SB(st)), it["rks"][r])   # state_r = MC(postSB_{r-1}) ^ rk_r
        post = SB(st)
        # 下轮 rk 由 post 反推: rk_{r+1} = MC(post) ^ state_{r+1}; 无独立核
        # 直接核: MC(post) 应为下一 state 的 preSB 部分 — 记录供对比
        it.setdefault("postSB", []).append(post)
print("链推进完成 (每键 8 个 postSB)")

# postSB_8 → MC → W = iSB(g1) ^ MC(postSB_8)?
print("\n=== 末轮 H2: g1 = SB(MC(postSB_8) ^ W(K)) ===")
pairsW = []
for it in items:
    if it["g1"] is None:
        continue
    W = xr(iSB(it["g1"]), MC(it["postSB"][7]))
    pairsW.append((it["K"], W))
    if len(pairsW) <= 3:
        print("  K=%s W=%s" % (it["K"].hex()[:8], W.hex()))
print("W 样本:", len(pairsW))

chk = {}
lin = True
for i in range(len(pairsW)):
    for j in range(i + 1, len(pairsW)):
        di = xr(pairsW[i][0], pairsW[j][0])
        do = xr(pairsW[i][1], pairsW[j][1])
        v = int.from_bytes(di, "big")
        if v == 0:
            continue
        if v in chk and chk[v] != int.from_bytes(do, "big"):
            lin = False
            print("  W 差分矛盾: di=%s" % di.hex())
            break
        chk[v] = int.from_bytes(do, "big")
    if not lin:
        break
print("W 差分一致性(仿射必要):", lin, "(独立差分 %d)" % len(chk))
if lin and len(chk) >= 127:
    piv = {}
    for v, o in chk.items():
        cur, ro = v, o
        for pbit, (pin, pout) in sorted(piv.items(), reverse=True):
            if cur >> pbit & 1:
                cur ^= pin
                ro ^= pout
        if cur:
            piv[cur.bit_length() - 1] = (cur, ro)
    rows = sorted(piv.values(), key=lambda t: t[0].bit_length() - 1)
    for i in range(len(rows)):
        hb = rows[i][0].bit_length() - 1
        for j in range(len(rows)):
            if j != i and rows[j][0] >> hb & 1:
                rows[j] = (rows[j][0] ^ rows[i][0], rows[j][1] ^ rows[i][1])
    emap = {d.bit_length() - 1: o for d, o in rows}

    def M(v):
        out, vv, j = 0, v, 0
        while vv:
            if vv & 1:
                out ^= emap.get(j, 0)
            vv >>= 1
            j += 1
        return out

    x0, y0 = pairsW[0]
    c = int.from_bytes(y0, "big") ^ M(int.from_bytes(x0, "big"))
    bad = sum(1 for x, y in pairsW
              if M(int.from_bytes(x, "big")) ^ c != int.from_bytes(y, "big"))
    print("W 仿射解: 验证失败 %d/%d" % (bad, len(pairsW)))
    if bad == 0:
        json.dump({"emap": {str(k): format(v, "x") for k, v in emap.items()},
                   "c": format(c, "x")},
                  open(os.path.join(HERE, "reports", "gen_final_W.json"), "w"))
        print("已存 gen_final_W.json")
