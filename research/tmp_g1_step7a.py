# -*- coding: utf-8 -*-
"""tmp_g1_step7a.py — 流演化的主动差分探测: 字节级扩散图.

对 pt 单字节翻转, 观察 rks 流(注入值)的 diff 模式:
- 局部扩散(≤2字节/项) → 字节级打表可行, 转译路线作废
- 全局雪崩(16字节全变) → 雪崩结构 → 回转译路线
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2  # noqa: E402
from decrypt_e import EDecryptor, ISBOX, xr, _gmul  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
SITES = [DEV_BASE + o for o in (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
                                0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]

d = EDecryptor()
d._oracle()
uc = d._uc
st = {"p": None, "tr": []}
uc.hook_add(unicorn.UC_HOOK_CODE,
            lambda u_, a, s, ud: st.update(p=u_.reg_read(UC_ARM64_REG_X2) & 0xFF),
            begin=MUL, end=MUL + 3)


def on_site(u_, address, size, ud):
    if st["p"] is not None:
        st["tr"].append(st["p"])
        st["p"] = None


for s in SITES:
    uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=s, end=s + 3)


def extract_rks(pt16, nblk=1):
    """返回 [nblk][8] 的注入值流 (rk_r = MC_out ^ invSB(next))."""
    st.update(p=None, tr=[])
    d._cap.clear()
    d._enc_big(pt16 * nblk, K, iv)
    out = []
    for blk in range(nblk):
        tr = st["tr"][blk * 288:(blk + 1) * 288]
        cols = []
        for g in range(36):
            by = tr[g * 8:g * 8 + 8]
            cols.append((by[0], by[1], by[3], by[5]))
        rks = []
        for r in range(8):
            nxt = [v for col in cols[(r + 1) * 4:(r + 2) * 4] for v in col]
            preSB = bytes(ISBOX[v] for v in nxt)
            mc = []
            for c4 in range(4):
                a, b2, cc, dd = cols[r * 4 + c4]
                mc.extend((_gmul(a, 2) ^ _gmul(b2, 3) ^ cc ^ dd,
                           a ^ _gmul(b2, 2) ^ _gmul(cc, 3) ^ dd,
                           a ^ b2 ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                           _gmul(a, 3) ^ b2 ^ cc ^ _gmul(dd, 2)))
            rks.append(xr(bytes(mc), preSB))
        out.append(rks)
    return out


K = bytes(range(0x05, 0x15))
iv = K[::-1]

base = extract_rks(bytes(16), nblk=1)[0]
print("=== 基线 rks(块0): ===")
for r, v in enumerate(base):
    print("  rk%d = %s" % (r + 1, v.hex()))

print()
print("=== 单字节翻转扩散图 (翻转 pt[i]=0x01) ===")
print("pt字节: 扩散的字节位置集合(每 rk 项, 合并 8 项)")
for i in range(16):
    pt = bytearray(16)
    pt[i] = 0x01
    var = extract_rks(bytes(pt), nblk=1)[0]
    # 每 rk 的 diff 字节数
    per_rk = []
    for r in range(8):
        diff = [j for j in range(16) if base[r][j] != var[r][j]]
        per_rk.append(len(diff))
    total_changed = set()
    for r in range(8):
        for j in range(16):
            if base[r][j] != var[r][j]:
                total_changed.add((r, j))
    print("  pt[%2d]: 每rk变更字节数=%s 合计变更=%d/128" %
          (i, per_rk, len(total_changed)))
