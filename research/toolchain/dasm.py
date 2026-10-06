# -*- coding: utf-8 -*-
# dis.py <so> <start_hex> <count>  -- 反汇编 libcore/libapp 指定 vaddr 区间
import sys, struct
from capstone import *

import paths as _P
SO = sys.argv[1] if len(sys.argv) > 1 else _P.SO
D = open(SO, 'rb').read()
e_phoff = struct.unpack_from('<Q', D, 0x20)[0]
e_phentsize = struct.unpack_from('<H', D, 0x36)[0]
e_phnum = struct.unpack_from('<H', D, 0x38)[0]
SEGS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from('<II', D, o)
    p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from('<QQQQQQ', D, o + 8)
    SEGS.append((p_type, p_offset, p_vaddr, p_filesz, p_flags))


def va2off(va):
    for t, po, v, fs, fl in SEGS:
        if t == 1 and v <= va < v + fs:
            return po + (va - v)
    return None


def sym_at(va):
    """粗略: 返回包含 va 的函数名(通过 .dynsym STT_FUNC)"""
    return None


def dis(va, n):
    o = va2off(va)
    if o is None:
        print('!! unmapped %#x' % va)
        return
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    code = D[o:o + n * 4]
    for i in md.disasm(code, va):
        print('%08x  %-8s %s' % (i.address, i.mnemonic, i.op_str))


if __name__ == '__main__':
    va = int(sys.argv[2], 16)
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 64
    dis(va, n)
