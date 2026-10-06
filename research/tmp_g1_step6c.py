# -*- coding: utf-8 -*-
"""tmp_g1_step6c.py — 纯 Python 闭式生成器 + 8 键 × 128 块金料全量验证.

模型:
  u     = P5(K)                                (rk0, 字节置换)
  rks   = 精简收割 (0.06s/键) rk1..rk8
  W     = iSB(golden1) ^ MC(postSB_8)          (链推导)
  preSB_b = M(x_b) ^ u                         (M 通用已解)
  CONST_{b+1} = SB(MC(postSB_8^{(b)}) ^ W)
  x_b   = pt_b ^ ct_{b-1} ^ CONST_b  (加密侧; 解密侧用 ct_b)
"""
import os
import sys
import json
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import SBOX, ISBOX, _gmul, xr, T  # noqa: E402

MJ = json.load(open(os.path.join(HERE, "reports", "gen_M.json")))
EMAP_M = {int(k): int(v, 16) for k, v in MJ["emap"].items()}


def Mmap(vb):
    v = int.from_bytes(vb, "big")
    out, j = 0, 0
    while v:
        if v & 1:
            out ^= EMAP_M.get(j, 0)
        v >>= 1
        j += 1
    return out.to_bytes(16, "big")


def SB(b):
    return bytes(SBOX[x] for x in b)


def iSB(b):
    return bytes(ISBOX[x] for x in b)


def MC(b):
    out = []
    for c in range(4):
        a, b2, cc, dd = b[4 * c:4 * c + 4]
        out.extend((_gmul(a, 2) ^ _gmul(b2, 3) ^ cc ^ dd,
                    a ^ _gmul(b2, 2) ^ _gmul(cc, 3) ^ dd,
                    a ^ b2 ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                    _gmul(a, 3) ^ b2 ^ cc ^ _gmul(dd, 2)))
    return bytes(out)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def gen_consts(ct, K, rks, W, nblk):
    """x_b = pt_b(=0) ^ ct_{b-1} ^ CONST_b  (dummy-pt 加密侧链, 与金料同构)."""
    iv = K[::-1]
    u = bytes(K[(5 * j) % 16] for j in range(16))
    consts = [bytes(16)]
    prev_ct = iv
    for b in range(nblk - 1):
        cb = ct[b * 16:(b + 1) * 16]
        x_b = xor(prev_ct, cb)          # pt_b = 0
        pre = xor(Mmap(x_b), u)
        st = pre
        for r in range(1, 9):
            st = xor(MC(SB(st)), rks[r])
        consts.append(xor(MC(SB(st)), W))
        prev_ct = cb
    return consts


def main():
    gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
    data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))
    total_bad = 0
    total = 0
    t0 = time.time()
    for kh, golds in gold.items():
        rec = data[kh]
        K = bytes.fromhex(kh)
        rks = {int(r): bytes.fromhex(v) for r, v in rec["rks"].items()}
        u = bytes(K[(5 * j) % 16] for j in range(16))
        # W 由 golden1 推导
        pre0 = bytes.fromhex(rec["preSB0"])
        st = pre0
        for r in range(1, 9):
            st = xor(MC(SB(st)), rks[r])
        W = xor(iSB(bytes.fromhex(rec["consts"][1])), MC(SB(st)))
        # 重建 ct 流 (加密侧): ct_b = F(pt_b ^ ct_{b-1} ^ CONST_b)?? 不需要 —
        # 验证直接用模型生成 consts 并与金料比对. 但 x_b 需 ct_b —
        # 金料的 ct 流 = 引擎加密 dummy 的输出, 未知!
        # ⇒ 用解密侧等价: 由金料 CONST 反推 x_b = ct_{b-1} ^ CONST_b (pt=0)
        #   而 ct_b = E-side output = F_e(x_b)... 引擎 ct 未知 ⇒ 跳过 ct,
        #   改用链式: x_b 已含 CONST_b — 直接迭代模型: 由 CONST_b 求 x_b 需 ct_b.
        #   ⇒ 换验证法: 用 emu 收割 128 块的 x 流 (一次性, 慢) — 不做.
        #   ⇒ 简化验证: 对 8 键各验 b=1 (已知 golden1 = 模型输出 ✓ 已含)
        pass
    print("见 step6d: 需 x 流金料, 本脚本仅组件自检")
    # 组件自检: 模型重现 preSB0 (b=0)
    for kh, rec in list(data.items())[:20]:
        K = bytes.fromhex(kh)
        iv = K[::-1]
        u = bytes(K[(5 * j) % 16] for j in range(16))
        pre_pred = xor(Mmap(iv), u)
        if pre_pred.hex() != rec["preSB0"]:
            print("preSB0 模型不符:", kh[:8])
            total_bad += 1
        total += 1
    print("preSB0 = M(iv) ^ P5(K) 验证: %d/%d 失败" % (total_bad, total))
    print("耗时 %.2fs" % (time.time() - t0))


if __name__ == "__main__":
    main()
