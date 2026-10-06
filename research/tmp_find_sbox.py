# -*- coding: utf-8 -*-
"""tmp_find_sbox.py — 钩 1 字节读, 找出被连续 256 字节读满的表(=候选 S-box)。"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')

AES = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3e5d645d197360814fdc222a908846eeb814de5e0bd'
    'be0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee'
    '1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16')

o = EOracle()
uc = o.s.e.uc
reads = set()


def mem_cb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ and size == 1:
        reads.add(address)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('distinct byte-read addrs:', len(reads))

# 找连续 256 字节全被读过的区间
srt = sorted(reads)
runs = []
start = prev = srt[0]
for a in srt[1:]:
    if a == prev + 1:
        prev = a
    else:
        if prev - start + 1 >= 256:
            runs.append((start, prev))
        start = prev = a
if prev - start + 1 >= 256:
    runs.append((start, prev))
print('contiguous runs >=256:', len(runs))
for lo, hi in runs[:12]:
    print('  run @%#x .. %#x  (%d bytes)' % (lo, hi, hi - lo + 1))
    # dump first 256 from the run
    for base in range(lo, min(hi - 255, lo + 3)):
        d = bytes(uc.mem_read(base, 256))
        tag = 'AES-SBOX' if d == AES else ('PERM' if len(set(d)) == 256 else 'nonperm')
        print('    base=%#x %s %s' % (base, tag, d[:32].hex()))
