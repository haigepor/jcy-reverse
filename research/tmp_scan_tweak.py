# -*- coding: utf-8 -*-
"""tmp_scan_tweak.py — 在块1的轮驱动调用时刻全内存搜索 CONST_1 / C_1 及其转置。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

A_DRV = DEV_BASE + 0x2da498
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
T = lambda b: bytes(V.T(list(b)))

K = b'X8TEUA3DEXZNW2TN'
CONST1 = bytes.fromhex('52f4c36b5f665eaafdb1cb79065d7df5')
C1 = bytes.fromhex('8d694ae0b3634986aeab189a21479ff2')
pats = {
    'CONST1': CONST1, 'C1': C1,
    'T(CONST1)': T(CONST1), 'T(C1)': T(C1),
    'C1^C': bytes.fromhex('1f4411604ab7308b1e9bc36e6a5e9e62'),
}
C = V.determine_C(o, K)
pats['CONST1^C'] = V.xr(CONST1, C)
pats['C1^CONST1'] = V.xr(C1, CONST1)

cnt = {'n': 0}
hits = []


def scan():
    regions = list(uc.mem_regions())
    for (b, e, perms) in regions:
        if not (perms & unicorn.UC_PROT_READ):
            continue
        sz = e - b + 1
        if sz > 0x2000000:
            continue
        try:
            data = uc.mem_read(b, sz)
        except Exception:
            continue
        for nm, p in pats.items():
            idx = data.find(p)
            while idx != -1:
                hits.append((nm, b + idx, sz))
                idx = data.find(p, idx + 1)


def cb(uc_, address, size, ud):
    cnt['n'] += 1
    if cnt['n'] == 3:      # 块1的轮驱动调用 (每次调用触发2次)
        scan()


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=A_DRV, end=A_DRV + 4)

o.enc(bytes([0x11] * 16) + bytes([0x22] * 16), K, Z)
print('n drv calls', cnt['n'])
for nm, a, sz in hits:
    print('  HIT %-12s @ %#x (region size %#x)' % (nm, a, sz))
if not hits:
    print('  无命中')
