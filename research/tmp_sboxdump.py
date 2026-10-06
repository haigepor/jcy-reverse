# -*- coding: utf-8 -*-
"""tmp_sboxdump.py — dump 堆上的 S 盒副本, 与 raw AES / KSA 变体比对。"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')
SO = open('research/artifacts/libcore.so', 'rb').read()
AES = SO[0x1dfc00:0x1dfc00 + 256]
AINV = SO[0x1e03b0:0x1e03b0 + 256]
AUTH_KEY = b'ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv'


def ksa(base, key):
    S = list(base)
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    return bytes(S)


o = EOracle()
uc = o.s.e.uc
out = o.enc(PT, K, IV)
print('out', out.hex())

addrs = [0x6ff99394, 0x737e41c38960]
# 也从 0x6ff99394 向前找 256 对齐起点
for a in addrs:
    base = a & ~0xff
    for cand in (base, base - 0x100, base + 0x100, a):
        try:
            d = bytes(uc.mem_read(cand, 256))
        except Exception:
            continue
        if len(set(d)) != 256:
            continue
        print('PERM @%#x' % cand)
        print('   == raw AES?  %s' % (d == AES))
        print('   == AES inv?  %s' % (d == AINV))
        for kn, kk in (('K16', K), ('rev', IV), ('AUTH', AUTH_KEY)):
            print('   == KSA(%s)? %s' % (kn, d == ksa(AES, kk)))
        if d != AES:
            print('   head', d[:32].hex())
            print('   tail', d[-32:].hex())
