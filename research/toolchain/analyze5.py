#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyze5.py - 解混淆调用表: blr 目标 = *(T + A) + B (mod 2^64), 静态重建调用图
T = GOT 0x67c798 的重定位值; V 从 .rela.dyn 或静态内容读取"""
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


def read_u64(va):
    o = va2off(va)
    if o is None:
        return None
    return struct.unpack_from('<Q', raw, o)[0]


# 1) T = GOT 0x67c798
GOT_SLOT = 0x67c798
reloc_map = {}
reladyn = elf.get_section_by_name('.rela.dyn')
for r in reladyn.iter_relocations():
    reloc_map[r['r_offset']] = (r['r_info_type'], r['r_addend'], r['r_info_sym'])
typ, addend, sym = reloc_map.get(GOT_SLOT, (None, None, None))
print(f'[T] GOT {GOT_SLOT:#x} reloc type={typ} addend={addend and hex(addend)} sym={sym}')
if addend is not None:
    T = addend
else:
    T = read_u64(GOT_SLOT)
print('[T] 表基址 T =', hex(T) if T else None)

# 2) 解 blr 调用点
tname, taddr, tsize, toff = [s for s in secs if s[0] == '.text'][0]
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
code = raw[toff:toff + tsize]
ins_all = []
pos = 0
while pos < len(code) - 4:
    chunk = code[pos:min(pos + 65536, len(code))]
    n0 = len(ins_all)
    for x in md.disasm(chunk, taddr + pos):
        ins_all.append((x.address, x.mnemonic, x.op_str))
        pos = (x.address - taddr) + x.size
    if len(ins_all) == n0:
        pos += 4
print('指令数:', len(ins_all))


def parse_mov64(idx):
    """从 idx 起回溯收集 movz/movk 序列构造 64 位常数 (寄存器名一致)"""
    # 正向: 在调用点前找 mov xN,#imm / movk xN,#imm,lsl #s 的完整组
    val = 0
    reg = None
    seen = 0
    j = idx
    while j >= 0 and seen < 5:
        a, m, o = ins_all[j]
        if m == 'movz' and o.startswith('x') and '#' in o:
            r, imm = o.split(', #')
            if reg is None:
                reg = r
                val = int(imm, 16)
                seen += 1
            elif r != reg:
                break
            j -= 1
        elif m == 'movk' and reg and o.startswith(reg + ','):
            imm, sh = o.split(', #')[1].split(', lsl #')
            val |= int(imm, 16) << (int(sh) * 16)
            seen += 1
            j -= 1
        else:
            break
    return reg, val if seen >= 2 else None


calls = []  # (blr_addr, target)
i = 0
n = len(ins_all)
for i in range(n):
    a, m, o = ins_all[i]
    if m != 'blr':
        continue
    reg = o.strip()
    # 向上找 add reg,reg,x21 形态或直接常量
    # 形态1: add x8, x8, x21 (x21 常数), x8 来自 ldr [x9, xA]
    # 收集向前 24 条内的 movz/movk 常数对
    consts = []  # (reg, val) 就近优先
    j = i - 1
    depth = 0
    while j >= 0 and depth < 40:
        aa, mm, oo = ins_all[j]
        if mm in ('movz', 'movk'):
            r2, v = None, None
            if mm == 'movz':
                r2, imm = oo.split(', #')
                v = int(imm, 16)
            else:
                r2, rest = oo.split(', #')
                if ', lsl #' in rest:
                    imm, sh = rest.split(', lsl #')
                    v = int(imm, 16) << (int(sh) * 16)
                else:
                    v = int(rest, 16)
            consts.append((r2, v))
        if mm == 'ldr' and f'[{reg}]' in oo.replace(' ', ''):
            # ldr x8, [x9, x8] -> x8 = *(base + A) 然后加 B
            pass
        depth += 1
        j -= 1
    # 重建: 最近 5 条内 movk 序列属于同一寄存器
    # 简化: 找最近两个不同寄存器的 64 位常数 (A 的寄存器 = ldr 索引, B = add 的加数)
    regA_val = None
    regB_val = None
    seenA = set()
    cur = {}
    order = []
    for r2, v in reversed(consts):  # 时间正序
        if r2 not in cur:
            cur[r2] = 0
            order.append(r2)
        if 'movk' :
            pass
        cur[r2] |= v
    # 上面 OR 法对 movz 也成立 (movz 覆盖低位, movk 叠高位, 但 movz 不清零高位 —
    # 常见模式 movz 清零 + movk 填充, OR 可还原)
    if len(order) >= 2:
        regA, regB = order[0], order[1]
        A = cur[regA]
        B = cur[regB]
        V = read_u64((T + A) % (1 << 64)) if T is not None else None
        if V is not None:
            tgt = (V + B) % (1 << 64)
            calls.append((a, tgt, A, B))

print('解出 blr 目标数:', len(calls))

# 3) 目标分类
BODIES = {
    'EVP_CipherInit_ex': 0x387368, 'EVP_CipherInit': 0x387308,
    'EVP_CipherUpdate': 0x387780, 'EVP_DecryptUpdate': 0x3877d0,
    'EVP_EncryptUpdate': 0x387790, 'RSA_private_decrypt': 0x43e324,
    'AES_set_decrypt_key': 0x3845e0, 'AES_set_encrypt_key': 0x3842ac,
    'MD5_Update': 0x422eb0, 'MD5_Final': 0x4239c0, 'MD5': 0x423ab4,
    'SHA256_Update': 0x449b10, 'SHA256_Final': 0x449c14, 'SHA1': 0x44848c,
    'RAND_bytes': 0x438d18, 'EVP_aes_128_cbc': 0x381fe4,
    'EVP_aes_256_cbc': 0x38208c, 'EVP_CIPHER_CTX_free': 0x3872d8,
    'EVP_DecryptInit_ex': 0x387db4, 'EVP_EncryptInit_ex': 0x387c60,
    'EVP_CIPHER_CTX_new': 0x387250, 'EVP_CIPHER_CTX_ctrl': 0x3879c8,
}
tv = {v: k for k, v in BODIES.items()}
in_text = [(a, t) for a, t, A, B in calls if taddr <= t < taddr + tsize]
print('目标落在 .text:', len(in_text), '/', len(calls))
crypto_calls = [(a, t) for a, t in in_text if t in tv]
print('=== 加密函数调用点 (blr 地址 → 目标) ===')
for a, t in sorted(crypto_calls):
    print(f'  {a:#x} → {tv[t]}')
json.dump([[a, t] for a, t in in_text], open('research/captures/rsa_scan/decalls.json', 'w'))
