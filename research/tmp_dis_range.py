# -*- coding: utf-8 -*-
"""tmp_dis_range.py — 用 capstone 反汇编 tmp_img.bin 的指定区间。用法: addr len"""
import sys, os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
HERE = os.path.dirname(os.path.abspath(__file__))
IMG = os.path.join(HERE, 'tmp_img.bin')
BASE = 0x400024a00000
img = open(IMG, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False

off = int(sys.argv[1], 16)
addr = BASE + off
ln = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x200

if off < 0 or off >= len(img):
    print('offset out of range: %#x (img %d bytes)' % (off, len(img)))
    sys.exit(1)
code = img[off:off + ln]
for ins in md.disasm(code, addr):
    print('0x%x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
