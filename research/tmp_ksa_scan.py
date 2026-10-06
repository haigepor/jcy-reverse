# -*- coding: utf-8 -*-
"""tmp_ksa_scan.py — 在模拟器内存中搜索 KSA(AES S-box, key) 生成的 256B 表。

若命中 ⇒ S 盒确实由 KSA 生成 ⇒ 任意 key 的 S 盒可离线复现(关键!)。
"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')
SO = open('research/artifacts/libcore.so', 'rb').read()
AES = SO[0x1dfc00:0x1dfc00 + 256]
AINV = SO[0x1e03b0:0x1e03b0 + 256]


def ksa(base, key):
    S = list(base)
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    return bytes(S)


cands = {
    'AES_raw': AES,
    'AES_inv': AINV,
    'KSA(K16)': ksa(AES, K),
    'KSA(rev)': ksa(AES, IV),
    'KSAinv(K16)': ksa(AINV, K),
}

o = EOracle()
uc = o.s.e.uc
out = o.enc(PT, K, IV)
print('out', out.hex())

regions = [(lo, hi) for (lo, hi, _) in uc.mem_regions()]
print('regions', len(regions))
for name, tab in cands.items():
    hits = []
    for lo, hi in regions:
        size = hi - lo + 1
        if size > 0x8000000:
            continue
        try:
            data = bytes(uc.mem_read(lo, size))
        except Exception:
            continue
        p = 0
        while True:
            i = data.find(tab[:64], p)
            if i < 0:
                break
            hits.append(lo + i)
            p = i + 1
            if len(hits) > 6:
                break
    print('%-12s hits=%d %s' % (name, len(hits), ['%#x' % a for a in hits[:6]]))
