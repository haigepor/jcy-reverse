#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyze_handler.py - libcore.so 静态分析:
1) api_decrypt 字符串 xref → 分发点
2) PLT 映射 → RSA/EVP/MD5 调用点
3) 输出响应解密函数的反汇编上下文"""
import json
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

SO = sys.argv[1] if len(sys.argv) > 1 else 'research/artifacts/device_libs/libcore.so'
f = open(SO, 'rb')
elf = ELFFile(f)

sections = {}
for s in elf.iter_sections():
    sections[s.name] = (s['sh_addr'], s['sh_size'], s['sh_offset'], s.data() if s['sh_type'] != 'SHT_NOBITS' else b'')
print('sections:', {k: (hex(v[0]), hex(v[1])) for k, v in sections.items() if v[1]})

text_addr, text_size, text_off, text = sections['.text']


def va2off(va):
    for name, (a, sz, off, data) in sections.items():
        if a <= va < a + sz and data:
            return off + (va - a)
    return None


def read_va(va, n):
    o = va2off(va)
    if o is None:
        return None
    f.seek(o)
    return f.read(n)


# ---- 1) 找字符串 ----
for sname in ('.rodata', '.data', '.data.rel.ro'):
    if sname not in sections:
        continue
    a, sz, off, data = sections[sname]
    i = data.find(b'api_decrypt\x00')
    while i >= 0:
        print(f'[str] "api_decrypt" @ {sname} va={a + i:#x} file={off + i:#x}')
        i = data.find(b'api_decrypt\x00', i + 1)
    for pat in (b'api_encrypt\x00', b'clear_key\x00'):
        j = data.find(pat)
        if j >= 0:
            print(f'[str] {pat[:-1].decode()} @ va={a + j:#x}')

# ---- 2) PLT 映射 (rela.plt 顺序 → .plt 桩) ----
got_targets = {}   # got_va -> symbol name
symtab = elf.get_section_by_name('.dynsym')
relaplt = elf.get_section_by_name('.rela.plt')
if relaplt:
    for r in relaplt.iter_relocations():
        sym = symtab.get_symbol(r['r_info_sym']).name
        got_targets[r['r_offset']] = sym
print('GOT 符号数:', len(got_targets))

# .plt 布局: PLT0(32B) + 每项 16B(arm64) 或 32B; 通过解析桩内 adrp/ldr 提取更稳
plt_addr, plt_size, plt_off, plt_data = sections.get('.plt', (0, 0, 0, b''))
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False

plt_map = {}  # stub_va -> symbol
i = 0
stub = 16  # PLT0 大小兜底; 逐项解析
# arm64 plt 桩通常 16B: adrp x16, ...; ldr x17,[x16,#off]; add/br
addr = plt_addr + 32
while addr < plt_addr + plt_size:
    off = va2off(addr)
    if off is None:
        addr += 16
        continue
    code = open(SO, 'rb').read()[off:off + 16]
    try:
        ins = list(md.disasm(code, addr))
    except Exception:
        ins = []
    got = None
    base = None
    for k, x in enumerate(ins):
        if x.mnemonic == 'adrp' and 'x16' in x.op_str:
            base = int(x.op_str.split('#')[1], 16)
        elif x.mnemonic == 'ldr' and base is not None and 'x17' in x.op_str:
            try:
                o = int(x.op_str.split('#')[1].rstrip(']'), 16)
                got = base + o
            except Exception:
                pass
    if got and got in got_targets:
        plt_map[addr] = got_targets[got]
    addr += 16
print('PLT 桩解析:', len(plt_map))
for a, s in sorted(plt_map.items()):
    if any(k in s for k in ('RSA', 'EVP', 'AES', 'MD5', 'SHA', 'RAND')):
        print(f'  {a:#x} {s}')

# ---- 3) 线性扫 .text: BL 目标 + ADRP/ADD 字符串引用 ----
open(SO, 'rb').seek(text_off)
code = open(SO, 'rb').read()[text_off:text_off + text_size]
ins_list = list(md.disasm(code, text_addr))
print('指令数:', len(ins_list))

# PLT 反查: 目标→调用点
plt_by_name = {}
for stubva, sym in plt_map.items():
    plt_by_name.setdefault(sym, []).append(stubva)
WATCH = ['RSA_private_decrypt', 'EVP_DecryptInit_ex', 'EVP_CipherInit_ex',
         'EVP_DecryptUpdate', 'AES_set_decrypt_key', 'AES_set_encrypt_key',
         'MD5_Update', 'MD5_Final', 'MD5', 'SHA256_Update', 'SHA256_Final',
         'EVP_EncryptUpdate', 'RAND_bytes']
callsites = {w: [] for w in WATCH}
adrp_reg = {}  # idx -> {reg: page}
for idx, x in enumerate(ins_list):
    if x.mnemonic == 'bl':
        try:
            tgt = int(x.op_str, 16)
        except Exception:
            continue
        for w in WATCH:
            for stubva in plt_by_name.get(w, []):
                if tgt == stubva:
                    callsites[w].append(x.address)
print('=== 调用点 ===')
for w in WATCH:
    if callsites[w]:
        print(f'{w}: {[hex(a) for a in callsites[w]]}')

json.dump({w: callsites[w] for w in WATCH}, open('research/captures/rsa_scan/callsites.json', 'w'))

# ---- 4) api_decrypt 字符串的 ADRP+ADD xref ----
rodata_addr, rodata_size, rodata_off, rodata = sections.get('.rodata', (0, 0, 0, b''))
targets = {}
for sname in ('.rodata', '.data', '.data.rel.ro'):
    if sname not in sections:
        continue
    a, sz, off, data = sections[sname]
    i = data.find(b'api_decrypt\x00')
    if i >= 0:
        targets['api_decrypt'] = a + i
    i = data.find(b'payload\x00')
    if i >= 0:
        targets['payload'] = a + i
    i = data.find(b'action\x00')
    if i >= 0:
        targets['action'] = a + i
print('串 VA:', {k: hex(v) for k, v in targets.items()})

reg_page = {}
xrefs = []
for idx, x in enumerate(ins_list):
    if x.mnemonic == 'adrp':
        try:
            reg, imm = x.op_str.split(', ')
            reg_page[reg] = int(imm, 16)
        except Exception:
            pass
    elif x.mnemonic == 'add' and reg_page:
        parts = x.op_str.split(', ')
        if len(parts) == 3 and parts[1] in reg_page and parts[2].startswith('#'):
            try:
                full = reg_page[parts[1]] + int(parts[2][1:], 16)
            except Exception:
                continue
            for nm, va in targets.items():
                if full == va:
                    xrefs.append((nm, x.address))
            if parts[0] in reg_page:
                reg_page[parts[0]] = full
    elif x.mnemonic == 'ldr' and reg_page:
        parts = x.op_str.split(', ')
        if len(parts) == 2 and parts[1].startswith('[') and '#' in parts[1]:
            try:
                reg = parts[1][1:].split(',')[0].strip()
                o = int(parts[1].split('#')[1].rstrip(']'), 16)
                full = reg_page[reg] + o
                for nm, va in targets.items():
                    if full == va:
                        xrefs.append((nm, x.address))
            except Exception:
                pass
print('=== api_decrypt/action/payload xref ===')
for nm, a in xrefs:
    print(f'  {nm} @ {a:#x}')
