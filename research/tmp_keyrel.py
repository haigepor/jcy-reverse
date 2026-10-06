# -*- coding: utf-8 -*-
"""tmp_keyrel.py - 测 E_b 是否为 Feistel(可经密钥变换实现解密).

判据: 若存在 K' 使 E_{K'}(y_i) == x_i 对 8 组全成立, 则 D_K = E_{K'}.
"""
import sys

sys.path.insert(0, 'research/captures/rsa_scan')
from e_oracle import EOracle  # noqa

d = open('research/tmp_bfpairs.bin', 'rb').read()
pairs = [(d[i * 16:i * 16 + 8], d[i * 16 + 8:i * 16 + 16]) for i in range(8)]
K = b'X8TEUA3DEXZNW2TN'
IV0 = b'\x00' * 16


def rot(b, n):
    return b[n:] + b[:n]


cands = {}
cands['K'] = K
cands['rev(K)'] = K[::-1]
for n in range(1, 16):
    cands['rot%d(K)' % n] = rot(K, n)
    cands['rot%d(revK)' % n] = rot(K[::-1], n)
for name, v in (('AES_KEY16', b'ziISjqkXPsGUMRNG'), ('AES_KEY16b', b'yWigxDGtJbfTdcGv'),
                ('AES_IV16', b'WonrnVkxeIxDcFbv'), ('chan_key', b'qPwClBj7j7ZQraSm'),
                ('chan_iv', b'p3JdVQl3q7WQJIgG')):
    cands[name] = v
cands['zeros'] = b'\x00' * 16

o = EOracle()
print('pairs: %d' % len(pairs))
x0, y0 = pairs[0]
hits = []
for name, Kp in cands.items():
    if len(Kp) != 16:
        continue
    try:
        out = o.enc(y0, Kp, IV0)
        ex = bytes(a ^ b for a, b in zip(out[:8], IV0[:8]))
        m = (ex == x0)
    except Exception as ex:
        print('%-14s ERR %s' % (name, ex))
        continue
    print('%-14s pair0 %s' % (name, 'HIT' if m else '-'))
    if m:
        hits.append((name, Kp))

for name, Kp in hits:
    ok = 0
    for x, y in pairs:
        out = o.enc(y, Kp, IV0)
        ex = bytes(a ^ b for a, b in zip(out[:8], IV0[:8]))
        if ex == x:
            ok += 1
    print('>>> %s 全量 %d/8' % (name, ok))
print('done')

