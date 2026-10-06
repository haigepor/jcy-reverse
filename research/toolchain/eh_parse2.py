#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eh_parse2.py - 线性遍历 .eh_frame: FDE → 函数范围 + LSDA → call-site/landing pad"""
import struct
import sys

from elftools.elf.elffile import ELFFile

SO = 'research/artifacts/device_libs/libcore.so'
raw = open(SO, 'rb').read()
elf = ELFFile(open(SO, 'rb'))
ehf = elf.get_section_by_name('.eh_frame')
EADDR, EDATA = ehf['sh_addr'], ehf.data()
gcc = elf.get_section_by_name('.gcc_except_table')
GADDR, GDATA = gcc['sh_addr'], gcc.data()


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def s32(b, o):
    return struct.unpack_from('<i', b, o)[0]


def uleb(b, o):
    r = 0
    s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, o
        s += 7


def sleb(b, o):
    r = 0
    s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7f) << s
        s += 7
        if not x & 0x80:
            if x & 0x40:
                r -= 1 << s
            return r, o


cies = {}
fdes = []
o = 0
N = len(EDATA)
while o < N - 4:
    length = u32(EDATA, o)
    if length == 0:
        break
    if length == 0xffffffff:
        break
    start = o
    cie_ptr = s32(EDATA, o + 4)
    if cie_ptr == 0:  # CIE
        cies[start] = True
        o += 4 + length
    else:  # FDE
        cie_off = o + 4 - cie_ptr
        pco = o + 8
        try:
            pc_begin = EADDR + pco + s32(EDATA, pco)
            pc_range = u32(EDATA, pco + 4)
        except Exception:
            o += 4 + length
            continue
        fdes.append((pc_begin, pc_range, start, cie_off, pco))
        o += 4 + length
print('FDE 数:', len(fdes))

# CIE 解析 (一次): aug 串 → fde_enc/lsda_enc


ENC_SIZE = {0x00: 8, 0x02: 2, 0x03: 4, 0x04: 8, 0x0a: 2, 0x0b: 4, 0x0c: 8}


def parse_cie(cie_off):
    length = u32(EDATA, cie_off)
    p = cie_off + 8
    end0 = EDATA.find(b'\x00', p)
    aug = EDATA[p:end0].decode('latin1')
    p = end0 + 1
    _, p = uleb(EDATA, p)
    _, p = sleb(EDATA, p)
    _, p = uleb(EDATA, p)
    fde_enc = 0x1b
    lsda_enc = 0x1c
    if 'z' in aug:
        alen, p = uleb(EDATA, p)
        for ch in aug[1:]:
            if ch == 'R':
                fde_enc = EDATA[p]
                p += 1
            elif ch == 'P':
                enc = EDATA[p]
                p += 1
                if (enc & 0x0f) in (0x01, 0x09):
                    _, p = uleb(EDATA, p)
                else:
                    p += ENC_SIZE[enc & 0x0f]
            elif ch == 'L':
                lsda_enc = EDATA[p]
                p += 1
    return aug, fde_enc, lsda_enc


cie_cache = {}


def fde_info(pc_begin, pc_range, fde_off, cie_off, pco):
    if cie_off not in cie_cache:
        cie_cache[cie_off] = parse_cie(cie_off)
    aug, fde_enc, lsda_enc = cie_cache[cie_off]
    p = pco + 8
    # augmentation length (uleb) — CIE 含 'z' 才有
    lsda_va = None
    if 'z' in aug:
        alen, p2 = uleb(EDATA, p)
        q = p2
        for ch in aug[1:]:
            if ch == 'L':
                enc = lsda_enc
                if (enc & 0x0f) == 0x0b:  # sdata4 pcrel
                    lsda_va = EADDR + q + s32(EDATA, q)
                    q += 4
                elif (enc & 0x0f) == 0x0c:  # sdata8 pcrel
                    lsda_va = EADDR + q + struct.unpack_from('<q', EDATA, q)[0]
                    q += 8
                elif (enc & 0x0f) == 0x03:  # udata4
                    lsda_va = u32(EDATA, q)
                    q += 4
                else:
                    q += 8
            elif ch == 'R':
                q += 1
    return lsda_va


def parse_lsda(lsda_va, func_start):
    o = lsda_va - GADDR
    lp_enc = GDATA[o]
    o += 1
    lp_start = func_start
    if lp_enc not in (0x00, 0xff):
        if (lp_enc & 0x0f) == 0x0b:
            lp_start = GADDR + o + s32(GDATA, o)
        elif (lp_enc & 0x0f) == 0x03:
            lp_start = u32(GDATA, o)
        o += 4
    ttype_enc = GDATA[o]
    o += 1
    if ttype_enc != 0x00:
        _, o = uleb(GDATA, o)
    cs_enc = GDATA[o]
    o += 1
    cs_len, o = uleb(GDATA, o)
    end = o + cs_len
    table = []
    while o < end:
        cs_start, o = uleb(GDATA, o)
        cs_len2, o = uleb(GDATA, o)
        lp_off, o = uleb(GDATA, o)
        act, o = uleb(GDATA, o)
        table.append((func_start + cs_start, cs_len2,
                      (lp_start + lp_off) if lp_off else None, act))
    return table


TARGETS = [int(x, 16) for x in sys.argv[1:]] or [0x328b84, 0x30cce0, 0x307a38, 0x2fdc24]
for t in TARGETS:
    for pc_begin, pc_range, fde_off, cie_off, pco in fdes:
        if pc_begin <= t < pc_begin + pc_range:
            lsda = fde_info(pc_begin, pc_range, fde_off, cie_off, pco)
            print(f'=== {t:#x} → func {pc_begin:#x}..{pc_begin + pc_range:#x} lsda={lsda and hex(lsda)}')
            if lsda:
                try:
                    for cs, cl, lp, act in parse_lsda(lsda, pc_begin):
                        mark = '  <<<' if cs <= t < cs + cl else ''
                        print(f'   callsite {cs:#x}+{cl:#x} → lp {lp and hex(lp)} act={act}{mark}')
                except Exception as e:
                    print('   LSDA 解析失败:', e)
            break
    else:
        print(f'=== {t:#x} 无 FDE')
