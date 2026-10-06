# -*- coding: utf-8 -*-
"""tmp_find_rk.py — 在第一次 ARK 调用时遍历指针, 定位含 K 的轮密钥缓冲。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_LR
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

A_ARK = DEV_BASE + 0x2d52e0
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]

state = {'done': False, 'out': []}


def try_rd(a, n):
    try:
        return rd(a, n)
    except Exception:
        return None


def scan_ptrs(base, depth, seen, out):
    if depth > 2 or base in seen:
        return
    seen.add(base)
    for i in range(4):
        try:
            q = u64(base + i * 8)
        except Exception:
            return
        out.append(('  ' * depth + 'q%d' % i, q))
        b = try_rd(q, 64)
        if b:
            out.append(('  ' * depth + 'mem', b))
            if b[:16] == b'\x58\x38\x54\x45\x55\x41\x33\x44\x45\x58\x5a\x4e\x57\x32\x54\x4e':
                out.append(('  ' * depth + '** FOUND K at %#x' % q, b))
        scan_ptrs(q, depth + 1, seen, out)


def cb(uc_, address, size, ud):
    if state['done']:
        return
    state['done'] = True
    x0 = uc_.reg_read(UC_ARM64_REG_X0)
    x1 = uc_.reg_read(UC_ARM64_REG_X1)
    x2 = uc_.reg_read(UC_ARM64_REG_X2)
    lr = uc_.reg_read(UC_ARM64_REG_LR) - DEV_BASE
    out = [('lr', lr), ('x0', x0), ('x1', x1), ('x2', x2)]
    for nm, v in (('x0', x0), ('x1', x1), ('x2', x2)):
        b = try_rd(v, 64)
        out.append((nm + '.mem', b.hex() if b else None))
        scan_ptrs(v, 0, set(), out)
    state['out'] = out


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=A_ARK, end=A_ARK + 4)

K = b'X8TEUA3DEXZNW2TN'
o.enc(bytes([0x11] * 16) + bytes([0x22] * 16), K, Z)
for nm, v in state['out']:
    print('%-24s %s' % (nm, v if isinstance(v, str) else hex(v) if isinstance(v, int) else v))
