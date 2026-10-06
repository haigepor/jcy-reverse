# -*- coding: utf-8 -*-
"""disasm_evpinit.py — 反汇编 builder EVP_EncryptInit_ex 调用点 0x3749d8 上下文,
追踪 x3(key)/x4(iv) 寄存器来源 → 回答 IV 生成点问题。"""
import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "..", "artifacts", "libcore.so")
data = open(SO, "rb").read()

# vaddr → file offset (program headers)
import struct


def vaddr2off(va):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, base)[0]
        if p_type != 1:
            continue
        p_offset = struct.unpack_from("<Q", data, base + 0x08)[0]
        p_vaddr = struct.unpack_from("<Q", data, base + 0x10)[0]
        p_filesz = struct.unpack_from("<Q", data, base + 0x20)[0]
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None


md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

SITES = [
    ("EVP_EncryptInit_ex 调用点", 0x3749d8, 0x3748a0, 0x374a10),
    ("RSA_public_encrypt 调用点", 0x373d70, 0x373c80, 0x373de8),
]


def show(title, va, lo, hi):
    print("=" * 20, title, hex(va), "=" * 20)
    off = vaddr2off(lo)
    if off is None:
        print("vaddr 未映射")
        return
    code = data[off:off + (hi - lo)]
    for ins in md.disasm(code, lo):
        mark = " <<<" if ins.address == va else ""
        print("0x%06x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))


for t, va, lo, hi in SITES:
    show(t, va, lo, hi)
