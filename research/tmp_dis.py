# -*- coding: utf-8 -*-
"""tmp_dis.py — 反汇编 libcore_dev_img.bin 指定区间（ARM64）。

用法::
    python research/tmp_dis.py 0x2d9ed0 0x120
    python research/tmp_dis.py 0x2d9014 0x180
    python research/tmp_dis.py 0x2d7440 0x200
"""
import os
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

HERE = os.path.dirname(os.path.abspath(__file__))
IMG = os.path.join(HERE, "artifacts", "libcore_dev_img.bin")


def main():
    off = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x2D9ED0
    ln = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x100
    data = open(IMG, "rb").read()
    print("img size = 0x%x   range = [0x%x, 0x%x)" % (len(data), off, off + ln))
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    blob = data[off:off + ln]
    for ins in md.disasm(blob, off):
        print("  0x%06x:  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))


if __name__ == "__main__":
    main()
