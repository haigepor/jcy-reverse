# -*- coding: utf-8 -*-
"""tmp_g1_step4r.py — 用标准 AES S 盒重建生成器：轮密钥/输入 + 端到端模型验证。"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import EDecryptor, xr, T, _gmul  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

# 标准 AES S 盒（镜像 0x1DFD10）
so = open(os.path.join(HERE, "artifacts", "libcore.so"), "rb").read()
S2 = so[0x1DFD10:0x1DFD10 + 256]
assert S2[0] == 0x63 and S2[1] == 0x7c
IS2 = bytes(S2.index(i) for i in range(256))


def expand_std(key):
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    rc = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [S2[x] for x in t]
            t[0] ^= rc
            rc = _xt(rc)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(11)]


def _xt(rc):
    rc <<= 1
    return (rc ^ 0x1B) & 0xFF if rc & 0x100 else rc


# AES9 标准加密（状态=16B 列主序，9 轮 = AES-128 但只 9 轮 + 无最终轮 MC 的处理按需）
def aes9(pt, rk, final_mc=True):
    s = list(xr(pt, rk[0]))
    for r in range(1, 10):
        s = [S2[x] for x in s]
        s = shift_rows(s)
        s = mix_cols(s)
        s = list(xr(bytes(s), rk[r]))
    if final_mc:
        s = [S2[x] for x in s]
        s = shift_rows(s)
        s = mix_cols(s)
    return bytes(s)


def shift_rows(s):
    # 标准 AES: 行 r 左移 r（列主序 s[4c+r]）
    o = [0] * 16
    for c in range(4):
        for r in range(4):
            o[4 * c + r] = s[4 * ((c + r) % 4) + r]
    return o


def mix_cols(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        o[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        o[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[2] if False else a[3], 2)
    return o


gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
K = bytes(range(0x30, 0x40))
tw1 = bytes.fromhex(gold[K.hex()][1])
print("K=%s" % K.hex())
print("golden[1]=%s" % tw1.hex())
rk = expand_std(K)
print("expand_std rk[1]=%s" % rk[1].hex())

# 用 harvested 列（从 step4q 重算太重 → 内联 harvest 一次，NBLK=1，只取列字节）
import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_PC,
)
from decrypt_e import EDecryptor  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
PREP = DEV_BASE + 0x2D9AD4
SITES = [DEV_BASE + o for o in
         (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
          0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]

d = EDecryptor()
d.calibrate(K, 1)
d._o = None
d._uc = None
d._oracle()
uc = d._uc
ctx = [None]
mem0 = []


def on_snap(uc_, address, size, ud):
    if ctx[0] is not None:
        return
    ctx[0] = uc_.context_save()
    for rbase, rend, _perms in uc_.mem_regions():
        sz = rend - rbase
        if sz > 64 * 1024 * 1024:
            continue
        try:
            mem0.append((rbase, sz, bytes(uc_.mem_read(rbase, sz))))
        except Exception:
            pass


h = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 3)
d._cap.clear()
d._enc_big(bytes(16), K, K[::-1])
uc.hook_del(h)
uc.context_restore(ctx[0])
for base, size, data in mem0:
    try:
        uc.mem_write(base, data)
    except Exception:
        pass
uc.ctl_flush_tb()

st = {"pending": None, "trace": [], "n": 0}


def on_mul(uc_, address, size, ud):
    st["pending"] = uc_.reg_read(UC_ARM64_REG_X2) & 0xFF


def on_site(uc_, address, size, ud):
    if st["pending"] is None:
        return
    st["trace"].append(st["pending"])
    st["pending"] = None
    st["n"] += 1
    if st["n"] >= 288:
        uc_.emu_stop()


uc.hook_add(unicorn.UC_HOOK_CODE, on_mul, begin=MUL, end=MUL + 3)
for s in SITES:
    uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=s, end=s + 3)
d._cap.clear()
try:
    uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=180 * 1000000,
                 count=6_000_000)
except Exception:
    pass

TR = st["trace"]
print("乘法字节轨迹 %d 条" % len(TR))
# 36 列
cols = []
for g in range(36):
    by = TR[g * 8:(g + 1) * 8]
    cols.append((by[0], by[1], by[3], by[5]))

# 状态布局：试 列主序(g=列) 与 转置(g=行)
def build_state(cols, transposed):
    s = [0] * 16
    for gi, (a, b, c, dd) in enumerate(cols):
        r = gi % 4
        cc = gi // 4
        if transposed:
            s[4 * r + cc] = a
            s[4 * ((r + 1) % 4) + cc] = b
            s[4 * ((r + 2) % 4) + cc] = c
            s[4 * ((r + 3) % 4) + cc] = dd
        else:
            s[4 * cc + 0] = a
            s[4 * cc + 1] = b
            s[4 * cc + 2] = c
            s[4 * cc + 3] = dd
    return s


for tp in (False, True):
    postSB_r1 = build_state(cols[0:4], tp)
    preSB = bytes(IS2[x] for x in postSB_r1)
    print("\n转置=%s: invSB2(r1 postSB)=%s" % (tp, preSB.hex()))
    print("  ^rk0 = %s" % xr(preSB, rk[0]).hex())

# 端到端：输入 = preSB ^ rk0，跑 aes9 标准模型，对照 golden[1]（含 T 变体）
for tp in (False, True):
    postSB_r1 = build_state(cols[0:4], tp)
    preSB = bytes(IS2[x] for x in postSB_r1)
    inp = xr(preSB, rk[0])
    for fmc in (True, False):
        out = aes9(inp, rk, final_mc=fmc)
        hits = []
        if out == tw1:
            hits.append("直接=")
        if bytes(T(list(out))) == tw1:
            hits.append("T(out)=")
        if out == bytes(T(list(tw1))):
            hits.append("=T(golden)")
        print("转置=%s finalMC=%s out=%s %s" % (
            tp, fmc, out.hex()[:16] + "..", ",".join(hits) or "不匹配"))
