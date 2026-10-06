# -*- coding: utf-8 -*-
"""lsda_diag.py — 离线全量解析 LSDA：cs 表 + action 表 + 类型名（用 dev img 的已重定位指针）。

目的：裁决 fn 0x30267c(act=5) 与 native_call(act=1) 的 catch 类型，
     以及全 LSDA 内所有非 cleanup pad 的类型清单。
"""
import struct
import sys
from elftools.elf.elffile import ELFFile

SO = 'research/artifacts/device_libs/libcore.so'
IMG = 'research/artifacts/libcore_dev_img.bin'
DEV_BASE = 0x400024a00000

elf = ELFFile(open(SO, 'rb'))
g = elf.get_section_by_name('.gcc_except_table')
GA, GD = g['sh_addr'], g.data()
IMGD = open(IMG, 'rb').read()
print('gcc_except_table: addr=0x%x size=0x%x' % (GA, len(GD)))


def uleb(b, o):
    r = s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, o
        s += 7


def sleb(b, o):
    r = s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7f) << s
        s += 7
        if not x & 0x80:
            if x & 0x40:
                r -= 1 << s
            return r, o


def img_read(addr, n):
    off = addr - DEV_BASE
    if off < 0 or off + n > len(IMGD):
        return None
    return IMGD[off:off + n]


def img_u64(addr):
    b = img_read(addr, 8)
    return struct.unpack('<Q', b)[0] if b else 0


def img_cstr(addr, n=160):
    b = img_read(addr, n)
    if b is None:
        return None
    i = b.find(0)
    if i < 0:
        i = n
    return b[:i].decode('latin1', 'replace')


def resolve_type(entry_rt, tenc=0x9c):
    """ttype 表条目 → 类型名 (0x9c=indirect|pcrel|sdata8)"""
    v = struct.unpack('<q', img_read(entry_rt, 8))[0]
    target = (entry_rt + v) & ((1 << 64) - 1)          # pcrel
    if tenc & 0x80:                                     # indirect
        target = img_u64(target)
        if not target:
            return None
    nmp = img_u64(target + 8)
    return img_cstr(nmp) if nmp else None


def parse_lsda(lsda_va, label, fn_start, probe=None):
    o = lsda_va - GA
    lp_enc = GD[o]
    t_enc = GD[o + 1]
    o += 2
    tbase_rt = None
    if t_enc != 0:
        fpos = o
        co, o = uleb(GD, o)
        tbase_rt = DEV_BASE + GA + fpos + (co if t_enc & 0x10 else 0)
    cs_enc = GD[o]
    o += 1
    cs_len, o = uleb(GD, o)
    cs_end = o + cs_len
    act_off = cs_end
    print('\n=== LSDA %s 0x%x: lp_enc=%#x ttype_enc=%#x cs_enc=%#x cs_len=%d '
          'ttype_base_rt=0x%x act_off(GDATA)=0x%x fn_start=0x%x' %
          (label, lsda_va, lp_enc, t_enc, cs_enc, cs_len,
           tbase_rt or 0, act_off, fn_start))
    ents = []
    while o < cs_end:
        cs_start, o = uleb(GD, o)
        cs_len2, o = uleb(GD, o)
        lp_off, o = uleb(GD, o)
        act, o = uleb(GD, o)
        ents.append((fn_start + cs_start, cs_len2, fn_start + lp_off, act))

    def chain(act):
        recs = []
        pos = act
        seen = set()
        while True:
            if pos in seen:
                recs.append('LOOP')
                break
            seen.add(pos)
            pp = act_off + pos
            f, pp = sleb(GD, pp)
            nx, pp = sleb(GD, pp)
            recs.append((f, nx))
            if nx == 0:
                break
            pos = pos + nx            # next = 相对当前记录的位移
        return recs

    def tname(f):
        if f == 0:
            return '<cleanup>'
        if tbase_rt is None:
            return None
        return resolve_type(tbase_rt - f * 8, t_enc)

    print('act!=0 的 pad (去重):')
    seen = set()
    for cs, cl, lp, act in ents:
        if not act or not lp or (lp, act) in seen:
            continue
        seen.add((lp, act))
        recs = chain(act)
        names = [tname(f) for f, _ in recs]
        print('  pad=0x%x act=%d 链=%s 类型=%s' % (lp, act, recs, names))
    if probe is not None:
        print('cs 表逐条 (与 probe=0x%x 相关 ±3 条):' % probe)
        idx = [i for i, (cs, cl, lp, act) in enumerate(ents)
               if cs - 0x40 <= probe < cs + cl + 0x40]
        for i in idx:
            cs, cl, lp, act = ents[i]
            mark = ' <<<' if cs <= probe < cs + cl else ''
            print('  [%d] cs=0x%x+0x%x lp=0x%x act=%d%s' % (i, cs, cl, lp, act, mark))
            if act:
                recs = chain(act)
                print('       链=%s 类型=%s' % (recs, [tname(f) for f, _ in recs]))
    print('action 表前 64B (act_off=0x%x): %s' % (act_off, GD[act_off:act_off + 64].hex()))
    return ents


ents1 = parse_lsda(0x1a3c50, 'fn 0x30267c', 0x30267c, probe=0x302700)
ents2 = parse_lsda(0x1a40b8, 'native_call', 0x307a38, probe=0x309560)
