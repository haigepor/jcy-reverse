# -*- coding: utf-8 -*-
"""tmp_w1_disasm.py — 反汇编轮驱动 0x2da498 与热点轮函数体(0x2d2exx)，找 skip-rounds 补丁点。"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from elftools.elf.elffile import ELFFile  # noqa: E402

SO = os.path.join(HERE, "artifacts", "libcore.so")


def vma2off(vma):
    with open(SO, "rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            a, z = seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"]
            if a <= vma < z:
                return seg["p_offset"] + (vma - a)
    raise ValueError("vma %#x 不在任何 PT_LOAD" % vma)


def dis(start, end, label):
    data = open(SO, "rb").read()
    off = vma2off(start)
    code = data[off:off + (end - start)]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    print("==== %s  %#x - %#x ====" % (label, start, end))
    for ins in md.disasm(code, start):
        tgt = ""
        if ins.mnemonic in ("bl", "b") and ins.op_str.startswith("#"):
            try:
                t = int(ins.op_str.lstrip("#"), 16) if ins.op_str.startswith("0x") else int(ins.op_str.lstrip("#"), 0)
            except Exception:
                t = None
            if t is not None:
                tgt = "   -> %#x" % t
        print("  %#08x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, tgt))


if __name__ == "__main__":
    a = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x2DA498
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 0x120
    dis(a, a + n, "window")
