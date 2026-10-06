# -*- coding: utf-8 -*-
"""tmp_sbox_trace.py - 追踪栈上 S 盒查找序列, 还原轮结构."""
import sys

sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('0000000000000000')

o = EOracle()
uc = o.s.e.uc

TBL_LO, TBL_HI = 0x701efa00, 0x701efe00
acc = []


def mem_cb(uc_, access, address, size, value, ud):
    if access in (unicorn.UC_MEM_READ, unicorn.UC_MEM_READ_UNMAPPED):
        if TBL_LO <= address < TBL_HI and len(acc) < 60000:
            try:
                pc = uc_.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC) - DEV_BASE
            except Exception:
                pc = -1
            acc.append((pc, address, value))


uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('acc count', len(acc))

mem = bytes(uc.mem_read(TBL_LO, TBL_HI - TBL_LO))
open('research/tmp_stack_tables.bin', 'wb').write(mem)
print('stack dump saved, len', len(mem))

print('--- 表访问前 260 条 (pc, addr_off, idx, val) ---')
for i, (pc, a, v) in enumerate(acc[:260]):
    print('%3d pc=0x%06x addr=0x%x idx=%3d val=%s' % (i, pc, a, a - TBL_LO, v))
