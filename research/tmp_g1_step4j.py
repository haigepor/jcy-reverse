# -*- coding: utf-8 -*-
"""tmp_g1_step4j.py — dump 字节操作核心段反汇编（0x2d2e00-0x2d3100 + 0x2d7400-0x2d7500）。"""
import os
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "tmp_libcore_dev.so")
data = open(SO, "rb").read()
# DEV_BASE 映射：代码在文件内偏移 = 虚拟偏移（.so 未节加载时通常 ELF 偏移≈虚拟偏移-基址，先按 1:1 试）
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def dis(voff_start, voff_end, title):
    print("\n===== %s (0x%x-0x%x) =====" % (title, voff_start, voff_end))
    # tmp_libcore_dev.so 的映射基址与文件偏移关系：emu 里 DEV_BASE+0x2d9ad4 可执行，
    # 假设文件偏移=虚拟偏移（先前 blutter/dump 都按此对齐过）。若乱码自动向前纠偏。
    raw = data[voff_start:voff_end]
    n_ok = 0
    for ins in md.disasm(raw, voff_start):
        print("  +%#08x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))
        n_ok += 1
    if n_ok < (voff_end - voff_start) // 4 - 2:
        print("  (仅 %d/%d 条解码成功，可能存在数据嵌入)" % (
            n_ok, (voff_end - voff_start) // 4))


dis(0x2D2E00, 0x2D3100, "字节操作核心")
