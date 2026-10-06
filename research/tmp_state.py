# -*- coding: utf-8 -*-
"""tmp_state.py — 钩内存写, 找出被反复写入的 16B 状态缓冲(密码轮状态)。"""
import sys
from collections import Counter
sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_PC
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')

o = EOracle()
uc = o.s.e.uc
wr = Counter()
seq = {}


def mem_cb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_WRITE:
        wr[address] += 1
        if len(seq) < 200000:
            pc = uc_.reg_read(UC_ARM64_REG_PC) - DEV_BASE
            seq.setdefault(address, []).append((pc, size, value))


uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, mem_cb)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('distinct write addrs:', len(wr))
print('--- top 30 written addresses ---')
for a, n in wr.most_common(30):
    print('  %#x  n=%d' % (a, n))
# 找被写 >=8 次且地址连续 16 的缓冲
hot = [a for a, n in wr.items() if n >= 8]
hot.sort()
runs = []
s = p = hot[0] if hot else 0
for a in hot[1:]:
    if a - p <= 2:
        p = a
    else:
        runs.append((s, p)); s = p = a
if hot:
    runs.append((s, p))
print('--- hot runs (>=8 writes) ---')
for s, p in runs[:15]:
    print('  %#x .. %#x (len %d)' % (s, p, p - s + 1))
