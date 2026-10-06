# -*- coding: utf-8 -*-
"""ttype_scan.py — 用扫描法反推 gcc_except_table 中 type 表的真实布局。

原理：类型条目 (enc=0x9c: indirect|pcrel|sdata8) 是 8 字节值 V，位于 P，
     目标 Q = P + V，*Q = type_info 指针。
     先从 thrown 的 ti 链拿到 parse_error/exception/std::exception 的 ti 运行时地址，
     在 img 里找"存放这些 ti 指针"的位置 Q（.data.rel.ro，重定位已应用），
     再扫 gcc_except_table 找 pcrel 指向这些 Q 的 8B 条目 P —— P 即真实 type 表条目。
     由 P 反推所属 LSDA 与 tbase = P + filter*8。
"""
import struct
from elftools.elf.elffile import ELFFile

SO = 'research/artifacts/device_libs/libcore.so'
IMG = 'research/artifacts/libcore_dev_img.bin'
DEV_BASE = 0x400024a00000

elf = ELFFile(open(SO, 'rb'))
g = elf.get_section_by_name('.gcc_except_table')
GA, GSIZE = g['sh_addr'], g['sh_size']
imgd = open(IMG, 'rb').read()


def rd(addr, n):
    off = addr - DEV_BASE
    if off < 0 or off + n > len(imgd):
        return None
    return imgd[off:off + n]


def u64(a):
    b = rd(a, 8)
    return struct.unpack('<Q', b)[0] if b else 0


def cstr(a, n=160):
    b = rd(a, n)
    if b is None:
        return None
    i = b.find(0)
    return b[:i if i >= 0 else n].decode('latin1', 'replace')


# thrown header 里的 tinfo (parse_error ti) —— 上轮 emu 日志 header hdr[0x20:0x28]
TI_PARSE = 0x40002508ada0
print('parse_error ti=0x%x name=%r' % (TI_PARSE, cstr(u64(TI_PARSE + 8))))
# 继承链
chain = []
cur = TI_PARSE
while cur:
    nm = cstr(u64(cur + 8))
    chain.append((cur, nm))
    print('  ti=0x%x %r base=0x%x' % (cur, nm, u64(cur + 16)))
    cur = u64(cur + 16)
    if cur < DEV_BASE or cur > DEV_BASE + 0x800000:
        break

tis = set(t for t, _ in chain)
# 1) 找存放 ti 指针的 Q
qs = {}
needle_vals = tis
for off in range(0, len(imgd) - 8, 8):
    v = struct.unpack_from('<Q', imgd, off)[0]
    if v in needle_vals:
        qs[DEV_BASE + off] = v
print('指向 ti 的槽 Q: %d 个' % len(qs))
for q, v in sorted(qs.items()):
    print('  Q=0x%x → ti=0x%x (%s)' % (q, v, cstr(u64(v + 8))))

# 2) 在 gcc_except_table 里扫 pcrel 指向这些 Q 的 8B 条目
print('\ngcc_except_table 内的 type 条目:')
imgd_gcc = imgd  # gcc_except_table 非重定位区, img 与文件一致
for off in range(0, GSIZE - 8, 8):
    p_rt = DEV_BASE + GA + off
    raw = imgd_gcc[GA + off:GA + off + 8]
    v = struct.unpack('<q', raw)[0]
    q = p_rt + v
    if q in qs:
        print('  条目 P=0x%x (GDATA off 0x%x) v=%d → Q=0x%x ti=%r'
              % (p_rt, GA + off, v, q, cstr(u64(qs[q] + 8))))

# 3) LSDA 边界参考
print('\n参考: LSDA fn0x30267c @GDATA 0x%x, act_off=0x1d90; LSDA native_call @0x%x, act_off=0x2997'
      % (0x1a3c50 - GA + GA, 0x1a40b8))
