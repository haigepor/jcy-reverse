# -*- coding: utf-8 -*-
"""tmp_statedump.py — dump 状态缓冲, 看结构与密文。"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')

o = EOracle()
uc = o.s.e.uc
out = o.enc(PT, K, IV)
print('out', out.hex())
print('expected E-out block0 =', out[:16].hex())

for base in (0x50002fc0, 0x50003000, 0x50003040, 0x50003080,
             0x50004600, 0x50004640, 0x50004680, 0x500046c0):
    try:
        d = bytes(uc.mem_read(base, 0x10))
        print('%#x: %s' % (base, d.hex()))
    except Exception as ex:
        print('%#x: ERR %s' % (base, ex))
# 0x50002fc0 周围 0x100
print('--- 0x50002f80..0x50003100 (0x10/row) ---')
for a in range(0x50002f80, 0x50003100, 0x10):
    d = bytes(uc.mem_read(a, 0x10))
    print('%#x: %s' % (a, d.hex()))
