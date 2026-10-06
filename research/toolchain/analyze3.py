#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyze3.py - 函数指针表引用链 + native_call 全量反汇编 + 混淆串核查"""
import json
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

SO = 'research/artifacts/device_libs/libcore.so'
raw = open(SO, 'rb').read()
elf = ELFFile(open(SO, 'rb'))
secs = []
for s in elf.iter_sections():
    if s['sh_addr'] and s['sh_type'] != 'SHT_NOBITS':
        secs.append((s.name, s['sh_addr'], s['sh_size'], s['sh_offset']))


def va2off(va):
    for name, a, sz, off in secs:
        if a <= va < a + sz:
            return off + (va - a)
    return None


# 0) 混淆串核查
for pat in (b'qPwC', b'p3Jd', b'kFGT', b'F3q22', b'5iW7S0GX'):
    i = raw.find(pat)
    print(f'[str?] {pat!r}: {"@%#x" % i if i >= 0 else "无 → 字符串已加密"}')

BODIES = {
    'EVP_CipherInit_ex': 0x387368, 'EVP_DecryptUpdate': 0x3877d0,
    'RSA_private_decrypt': 0x43e324, 'AES_set_decrypt_key': 0x3845e0,
    'AES_set_encrypt_key': 0x3842ac, 'MD5_Update': 0x422eb0,
    'SHA256_Update': 0x449b10, 'MD5': 0x423ab4, 'SHA256_Final': 0x449c14,
    'EVP_aes_128_cbc': 0x381fe4, 'RAND_bytes': 0x438d18,
}
rev = {v: k for k, v in BODIES.items()}

# 1) .rela.dyn 中指向函数体的 RELATIVE 重定位 (函数指针存储位)
ptr_sites = {}  # body_name -> [r_offset]
dynsym = elf.get_section_by_name('.dynsym')
reladyn = elf.get_section_by_name('.rela.dyn')
cnt = 0
for r in reladyn.iter_relocations():
    t = r['r_info_type']
    addend = r['r_addend'] if t in (0x102, 0x103, 0x105, 0x101, 0x100) else None
    # R_AARCH64_RELATIVE=1027(0x403)? 实际 RELATIVE=1027; 用 addend 匹配即可
    if r['r_addend'] in rev:
        nm = rev[r['r_addend']]
        ptr_sites.setdefault(nm, []).append((r['r_offset'], t))
        cnt += 1
print('[rela] 函数指针存储位:')
for nm, sites in ptr_sites.items():
    print(f'  {nm}: {[(hex(o), hex(t)) for o, t in sites]}')

# 2) 反汇编 .text (重同步)
tname, taddr, tsize, toff = [s for s in secs if s[0] == '.text'][0]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
code = raw[toff:toff + tsize]
ins_all = []
pos = 0
while pos < len(code) - 4:
    chunk = code[pos:min(pos + 65536, len(code))]
    n0 = len(ins_all)
    for x in md.disasm(chunk, taddr + pos):
        ins_all.append((x.address, x.mnemonic, x.op_str, x.size))
        pos = (x.address - taddr) + x.size
    if len(ins_all) == n0:
        pos += 4
print('指令数:', len(ins_all))
addrs = [t[0] for t in ins_all]
idx_of = {a: i for i, (a, m, o, sz) in enumerate(ins_all)}

# 3) adrp+ldr 引用 ptr_sites → 调用者
sites_wanted = {}
for nm, lst in ptr_sites.items():
    for off, t in lst:
        sites_wanted[off] = nm
reg_page = {}
ref_hits = []
for i, (a, m, o, sz) in enumerate(ins_all):
    if m == 'adrp':
        try:
            reg, imm = o.split(', ')
            reg_page[reg] = int(imm, 16)
        except Exception:
            pass
    elif m == 'ldr' and '[' in o:
        try:
            parts = o.split('[')[1].rstrip(']')
            reg, rest = parts.split(',')[0].strip(), parts.split(',')[1].strip()
            if reg in reg_page and rest.startswith('#'):
                full = reg_page[reg] + int(rest[1:].rstrip(']'), 16)
                if full in sites_wanted:
                    ref_hits.append((a, full, sites_wanted[full]))
        except Exception:
            pass
    elif m in ('ret', 'b') and m == 'ret':
        reg_page.clear()
print('[refs] 指针引用点:')
for a, off, nm in ref_hits:
    print(f'  {nm} ptr@{off:#x} referenced @ {a:#x}')
json.dump(ref_hits, open('research/captures/rsa_scan/ptr_refs.json', 'w'))

# 4) native_call 全量反汇编 → 文件
o = va2off(0x307a38)
# 函数长度: 从 0x307a38 反汇编到下一段; 先粗略取 0x800
fc = raw[o:o + 0x900]
lines = []
for x in md.disasm(fc, 0x307a38):
    lines.append('%08x  %-8s %s' % (x.address, x.mnemonic, x.op_str))
open('research/captures/rsa_scan/native_call.asm', 'w').write('\n'.join(lines))
print('native_call asm 行数:', len(lines), '→ native_call.asm')

# 5) parse 调用点 0x328b84 上下文 ±0x200
o = va2off(0x328b84 - 0x200)
fc = raw[o:o + 0x400]
lines = []
for x in md.disasm(fc, 0x328b84 - 0x200):
    lines.append('%08x  %-8s %s' % (x.address, x.mnemonic, x.op_str))
open('research/captures/rsa_scan/parse_site.asm', 'w').write('\n'.join(lines))
print('parse_site asm 行数:', len(lines))
