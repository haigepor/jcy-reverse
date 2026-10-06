# -*- coding: utf-8 -*-
"""tmp_trace_mem.py - 单块加密的内存访问热力图: 找 S 盒(256B 表)与状态缓冲."""
import sys
from collections import Counter

sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('0000000000000000')

o = EOracle()
uc = o.s.e.uc

rcnt = Counter()   # 精确地址读计数
rpc = Counter()    # 读指令 PC
wr = Counter()


def rd_cb(uc_, access, address, size, value, ud):
    rcnt[address] += 1
    if access == 1 or True:
        pass


def code_cb(uc_, address, size, ud):
    pass


def mem_cb(uc_, access, address, size, value, ud):
    if access in (unicorn.UC_MEM_READ, unicorn.UC_MEM_READ_UNMAPPED):
        rcnt[address] += 1
        try:
            rpc[uc_.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC) - DEV_BASE] += 1
        except Exception:
            pass
    elif access in (unicorn.UC_MEM_WRITE, unicorn.UC_MEM_WRITE_UNMAPPED):
        wr[address] += 1


uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, mem_cb)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('distinct read addrs:', len(rcnt), 'total reads:', sum(rcnt.values()))

# 找 256 字节密集区
addrs = sorted(rcnt)
print('--- top 30 read addrs ---')
for a, n in rcnt.most_common(30):
    tag = ' off 0x%x' % (a - DEV_BASE) if DEV_BASE <= a < DEV_BASE + 0x800000 else ''
    print('  0x%x%s  %d' % (a, tag, n))

# 聚合到 256B 页
page = Counter()
for a, n in rcnt.items():
    page[a & ~0xFF] += n
print('--- top 20 256B 页 ---')
for p, n in page.most_common(20):
    tag = ' off 0x%x' % (p - DEV_BASE) if DEV_BASE <= p < DEV_BASE + 0x800000 else ''
    print('  0x%x%s  %d  (distinct %d)' % (p, tag, n, sum(1 for a in rcnt if (a & ~0xFF) == p)))

print('--- top 20 写地址 ---')
for a, n in wr.most_common(20):
    tag = ' off 0x%x' % (a - DEV_BASE) if DEV_BASE <= a < DEV_BASE + 0x800000 else ''
    print('  0x%x%s  %d' % (a, tag, n))
print('--- top 15 读 PC ---')
for p, n in rpc.most_common(15):
    print('  0x%06x  %d' % (p, n))
