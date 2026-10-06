# -*- coding: utf-8 -*-
"""tmp_g1_step7d.py — 定位注入值(rk)在引擎内存中的诞生地.

1) 跑块0, 记录全部内存读事件 (addr, 8B data, pc)
2) 用已提取的 rk1..8 值在事件流里匹配 → 找到 rk 被读的缓冲区地址
3) mem write hook → 找写这些地址的 PC → schedule 计算位置
"""
import os
import sys
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2, UC_ARM64_REG_PC  # noqa: E402
from decrypt_e import EDecryptor, ISBOX, xr, _gmul, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
SITES = [DEV_BASE + o for o in (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
                                0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]

d = EDecryptor()
d._oracle()
uc = d._uc
K = bytes(range(0x05, 0x15))
iv = K[::-1]

# 先正常提取块0 rks (golden)
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

d._cap.clear()
d._enc_big(bytes(16), K, iv)
tr = st["tr"][:288]
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
print("golden rks:")
for r, v in enumerate(rks):
    print("  rk%d = %s" % (r + 1, v.hex()))

# ---- 内存读写 trace (只记录 DEV_BASE 映射区域) ----
reads = collections.deque(maxlen=1200000)
writes = collections.deque(maxlen=1200000)


def on_read(uc_, access, address, size, value, ud):
    if size == 8 or size == 4:
        try:
            data = uc_.mem_read(address, size)
            reads.append((address, bytes(data), uc_.reg_read(UC_ARM64_REG_PC)))
        except Exception:  # noqa: BLE001
            pass


def on_write(uc_, access, address, size, value, ud):
    if DEV_BASE <= address < DEV_BASE + 0x800000:
        writes.append((address, size, value, uc_.reg_read(UC_ARM64_REG_PC)))


h_r = uc.hook_add(unicorn.UC_HOOK_MEM_READ, on_read, begin=DEV_BASE, end=DEV_BASE + 0x800000)
h_w = uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write, begin=DEV_BASE, end=DEV_BASE + 0x800000)

d._cap.clear()
d._enc_big(bytes(16), K, iv)
uc.hook_del(h_r)
uc.hook_del(h_w)
print("读事件 %d, 写事件 %d" % (len(reads), len(writes)))

# ---- 匹配 rk 值的读地址 ----
for r in (0, 1):
    rk = rks[r]
    pat = rk[:8]
    pat2 = rk[8:]
    hits = [(a, pc) for (a, data, pc) in reads if data == pat]
    hits2 = [(a, pc) for (a, data, pc) in reads if data == pat2]
    addrs = collections.Counter(a for a, _ in hits)
    print("rk%d[:8] 读命中: %d 次, 地址: %s" % (r + 1, len(hits), [hex(a - DEV_BASE) for a, _ in sorted(addrs.items())[:6]]))
    addrs2 = collections.Counter(a for a, _ in hits2)
    print("rk%d[8:] 读命中: %d 次, 地址: %s" % (r + 1, len(hits2), [hex(a - DEV_BASE) for a, _ in sorted(addrs2.items())[:6]]))
    # 写这些地址的 PC
    waddrs = set(addrs) | set(addrs2)
    wpc = collections.Counter(pc for (a, sz, v, pc) in writes if any(abs(a - w) <= 8 for w in waddrs))
    print("rk%d 缓冲区写入者 PC top6: %s" % (r + 1, [hex(p - DEV_BASE) for p, _ in wpc.most_common(6)]))
