#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyze_handler2.py - 本地函数体 BL 交叉引用 + 分块重同步反汇编 + 全文件串搜索"""
import json
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

SO = sys.argv[1] if len(sys.argv) > 1 else 'research/artifacts/device_libs/libcore.so'
raw = open(SO, 'rb').read()
elf = ELFFile(open(SO, 'rb'))

secs = []
for s in elf.iter_sections():
    if s['sh_addr'] and s['sh_type'] != 'SHT_NOBITS':
        secs.append((s.name, s['sh_addr'], s['sh_size'], s['sh_offset']))
print('sections:', [(n, hex(a), hex(sz)) for n, a, sz, o in secs if sz])


def va2off(va):
    for name, a, sz, off in secs:
        if a <= va < a + sz:
            return off + (va - a)
    return None


# ---- 全文件字符串搜索 ----
for pat in (b'api_decrypt', b'api_encrypt', b'clear_key', b'\x00action\x00',
            b'\x00payload\x00', b'\x00data\x00', b'\x00path\x00'):
    hits = []
    i = raw.find(pat)
    while i >= 0 and len(hits) < 8:
        # 反查所属 section VA
        va = None
        for name, a, sz, off in secs:
            if off <= i < off + sz:
                va = a + (i - off)
                snm = name
                break
        hits.append((i, va))
        i = raw.find(pat, i + 1)
    print(f'[str] {pat!r}: {[(hex(i), hex(v) if v else None) for i, v in hits]}')

# ---- hunt5 本地函数体地址 ----
BODIES = {
    'EVP_CipherInit_ex': 0x387368, 'EVP_CipherInit': 0x387308,
    'EVP_CipherUpdate': 0x387780, 'EVP_DecryptUpdate': 0x3877d0,
    'EVP_EncryptUpdate': 0x387790, 'RSA_private_decrypt': 0x43e324,
    'AES_set_decrypt_key': 0x3845e0, 'AES_set_encrypt_key': 0x3842ac,
    'MD5_Update': 0x422eb0, 'MD5_Final': 0x4239c0, 'MD5': 0x423ab4,
    'SHA256_Update': 0x449b10, 'SHA256_Final': 0x449c14, 'SHA1': 0x44848c,
    'RAND_bytes': 0x438d18, 'EVP_aes_128_cbc': 0x381fe4,
    'EVP_aes_256_cbc': 0x38208c, 'EVP_CIPHER_CTX_free': 0x3872d8,
    'native_call': 0x307a38, 'native_init': 0x2fdc24,
}
# 验证函数体前 4 字节非零 (合法指令)
for nm, va in BODIES.items():
    o = va2off(va)
    print(f'[body] {nm} @{va:#x} bytes={raw[o:o+8].hex() if o else "N/A"}')

# ---- 分块重同步反汇编 .text ----
text = [s for s in secs if s[0] == '.text'][0]
tname, taddr, tsize, toff = text
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
ins_all = []
pos = 0
code = raw[toff:toff + tsize]
while pos < len(code) - 4:
    chunk = code[pos:min(pos + 65536, len(code))]
    n_before = len(ins_all)
    for x in md.disasm(chunk, taddr + pos):
        ins_all.append((x.address, x.mnemonic, x.op_str))
        pos = (x.address - taddr) + x.size
    if len(ins_all) == n_before:
        pos += 4  # 跳过脏字节重同步
print('指令总数:', len(ins_all))

# BL 直呼本地函数体
callsites = {nm: [] for nm in BODIES}
for a, m, o in ins_all:
    if m == 'bl':
        try:
            t = int(o, 16)
        except Exception:
            continue
        for nm, va in BODIES.items():
            if t == va:
                callsites[nm].append(a)
print('=== BL 调用点 ===')
for nm in BODIES:
    if callsites[nm]:
        print(f'{nm} ({len(callsites[nm])}): {[hex(a) for a in callsites[nm]]}')
json.dump({nm: callsites[nm] for nm in BODIES},
          open('research/captures/rsa_scan/callsites2.json', 'w'))
