# -*- coding: utf-8 -*-
"""tmp_xref.py - 扫描 BL 交叉引用, 统计密码区(0x2c0000-0x300000)入口."""
import struct
import sys

sys.path.insert(0, 'research/toolchain')
from paths import SO  # noqa

D = open(SO, 'rb').read()
e_phoff = struct.unpack_from('<Q', D, 0x20)[0]
e_phentsize = struct.unpack_from('<H', D, 0x36)[0]
e_phnum = struct.unpack_from('<H', D, 0x38)[0]
SEGS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz = struct.unpack_from('<IIQQQQQ', D, o)
    if p_type == 1:
        SEGS.append((p_offset, p_vaddr, p_filesz, p_flags))


def off2va(off):
    for po, va, fs, fl in SEGS:
        if po <= off < po + fs:
            return va + (off - po)
    return None


def va2off(va):
    for po, va0, fs, fl in SEGS:
        if va0 <= va < va0 + fs:
            return po + (va - va0)
    return None


# 扫描可执行段
exec_segs = [(po, va, fs) for po, va, fs, fl in SEGS if fl & 1]
from collections import Counter, defaultdict
tgt = Counter()
callers = defaultdict(list)
for po, va, fs in exec_segs:
    for i in range(0, fs - 4, 4):
        w = struct.unpack_from('<I', D, po + i)[0]
        if (w >> 26) != 0b100101:
            continue
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        t = va + i + imm * 4
        if 0x2c0000 <= t < 0x300000:
            tgt[t] += 1
            if len(callers[t]) < 12:
                callers[t].append(va + i)

print('crypto-region BL targets:', len(tgt))
print('--- top 40 被调用目标 ---')
for t, n in tgt.most_common(40):
    print('  0x%06x  n=%d  callers=%s' % (t, n, ' '.join('0x%x' % c for c in callers[t][:8])))
