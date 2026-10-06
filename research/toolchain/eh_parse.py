#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eh_parse.py - 解析 libcore.so 的 .eh_frame_hdr/.eh_frame/.gcc_except_table
输出: 函数范围 → {call_site(返回地址) → landing_pad} 映射, 聚焦 parse 区域 0x328xxx"""
import struct
import sys

from elftools.elf.elffile import ELFFile

SO = 'research/artifacts/device_libs/libcore.so'
raw = open(SO, 'rb').read()
elf = ELFFile(open(SO, 'rb'))


def sec(name):
    s = elf.get_section_by_name(name)
    return s['sh_addr'], s.data()


hdr_addr, hdr = sec('.eh_frame_hdr')
ehf_addr, ehf = sec('.eh_frame')
gcc_addr, gcc = sec('.gcc_except_table')


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


# ---- eh_frame_hdr 表 ----
ver, ptre, cne, tbe = hdr[0], hdr[1], hdr[2], hdr[3]
ehf_ptr = hdr_addr + 8 + s32(hdr, 8)
fde_count = u32(hdr, 12)
print(f'hdr@{hdr_addr:#x} ehf_ptr={ehf_ptr:#x} fde_count={fde_count}')

fdes = []  # (func_start, func_end, fde_off_in_ehf)
tb = 16
for i in range(fde_count):
    loc = hdr_addr + tb + s32(hdr, tb)
    fde = hdr_addr + tb + 4 + s32(hdr, tb + 4)
    fdes.append((loc, fde))
    tb += 8
print('FDE 表项:', len(fdes))

# ---- FDE 解析: pc_begin/pc_range + LSDA ----
DW_EH_PE_pcrel_sdata4 = 0x1b


def parse_fde(fde_va):
    o = va2off = fde_va - ehf_addr
    length = u32(ehf, o)
    if length == 0:
        return None
    cie_ptr = o + 4 + s32(ehf, o + 4)  # back offset to CIE (pcrel from field)
    # 解 CIE 拿 FDE 编码 (简化: 假设标准 0x1b pcrel sdata4 + LSDA)
    pco = o + 8
    pc_begin = fde_va + 8 + s32(ehf, pco)  # pcrel from field位置(fde_va+8)
    pc_range = u32(ehf, pco + 4)
    # augmentation data: 需按 CIE 的 aug 串解析; GCC ARM64 常见 "zR" 或 "zPLR"
    auge = pco + 8
    # 找 CIE 的 aug 字符串
    cie_off = cie_ptr
    clen = u32(ehf, cie_off)
    cie_id = s32(ehf, cie_off + 4)
    aug_pos = cie_off + 8
    aug_end = ehf.find(b'\x00', aug_pos)
    aug = ehf[aug_pos:aug_end].decode()
    p = aug_end + 1
    # code_align(uleb) data_align(sleb) ret_reg(uleb)
    _, p = uleb(ehf, p)
    _, p = sleb(ehf, p)
    _, p = uleb(ehf, p)
    lsda_enc = None
    fde_enc = 0x1b
    if 'z' in aug:
        alen, p = uleb(ehf, p)
        zend = p + alen
        for ch in aug[1:]:
            if ch == 'R':
                fde_enc = ehf[p]
                p += 1
            elif ch == 'P':
                penc = ehf[p]
                p += 1
                # personality 例程编码大小
                sz = {0x1b: 4, 0x03: 4, 0x0b: 8, 0x1d: 4}.get(penc & 0x0f, 4)
                if penc & 0x70 == 0x10:  # pcrel
                    p += sz
                else:
                    p += sz
            elif ch == 'L':
                lsda_enc = ehf[p]
                p += 1
        p = zend if p > zend else p
    # FDE augmentation length
    alen, p = uleb(ehf, p)
    aug_data_start = p
    lsda_va = None
    if 'L' in aug and lsda_enc is not None:
        lsda_va = fde_va + (p - o) + s32(ehf, p) if (lsda_enc & 0x0f) == 0x0b else None
        if (lsda_enc & 0x0f) == 0x0b:
            pass
        elif (lsda_enc & 0x0f) == 0x03:  # sdata4 absptr? 实际 sdata4=0x0a? 0x03=udata4
            lsda_va = u32(ehf, p)
        p += 4 if (lsda_enc & 0x0f) in (0x03, 0x0a, 0x1a, 0x0b) else 8
    return pc_begin, pc_range, lsda_va


def off2va(off):
    return ehf_addr + off


# ---- 目标函数: 覆盖 0x328b84 的 FDE ----
TARGETS = [0x328b84, 0x30cce0, 0x307a38, 0x2fdc24]
for t in TARGETS:
    found = None
    for loc, fde_va in fdes:
        r = parse_fde(fde_va)
        if r is None:
            continue
        pc_begin, pc_range, lsda = r
        if pc_begin <= t < pc_begin + pc_range:
            found = (pc_begin, pc_range, lsda)
            break
    if found:
        fs, fr, ls = found
        print(f'FDE 覆盖 {t:#x}: func={fs:#x}..{fs + fr:#x} lsda={ls and hex(ls)}')
    else:
        print(f'FDE 未覆盖 {t:#x}')

# ---- LSDA 解析 (call-site 表) ----


def parse_lsda(lsda_va, func_start):
    o = lsda_va - gcc_addr
    lp_enc = gcc[o]
    o += 1
    lp_start = func_start
    if lp_enc != 0x00:
        lp_start = gcc_addr + o + s32(gcc, o) if (lp_enc & 0x0f) == 0x0b else u32(gcc, o)
        o += 4
    ttype_enc = gcc[o]
    o += 1
    if ttype_enc != 0x00:
        _, o = uleb(gcc, o)  # class table offset
    cs_enc = gcc[o]
    o += 1
    cs_len, o = uleb(gcc, o)
    end = o + cs_len
    table = []
    while o < end:
        cs_start, o = uleb(gcc, o)
        cs_len2, o = uleb(gcc, o)
        lp_off, o = uleb(gcc, o)
        act, o = uleb(gcc, o)
        table.append((func_start + cs_start, cs_len2, func_start + lp_off if lp_off else None, act))
    return table


for t in TARGETS:
    for loc, fde_va in fdes:
        r = parse_fde(fde_va)
        if r is None:
            continue
        pc_begin, pc_range, lsda = r
        if pc_begin <= t < pc_begin + pc_range and lsda:
            print(f'=== func {pc_begin:#x} LSDA ===')
            for cs, cl, lp, act in parse_lsda(lsda, pc_begin):
                mark = ' <<< parse区' if cs <= 0x328b90 < cs + cl else ''
                print(f'  callsite {cs:#x}+{cl:#x} → lp {lp and hex(lp)} act={act}{mark}')
            break
