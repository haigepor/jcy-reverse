import sys, re
from capstone import *
LIB = sys.argv[3] if len(sys.argv) > 3 else 'research/artifacts/device_libs/libapp.so'
data = open(LIB,'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = False
start, size = int(sys.argv[1],16), int(sys.argv[2],16)
pool = {}
rx = re.compile(r'^\[pp\+(0x[0-9a-f]+)\]\s+(.*)$')
for line in open('research/artifacts/blutter_out/pp.txt', encoding='utf-8', errors='replace'):
    m = rx.match(line)
    if m: pool[int(m.group(1),16)] = m.group(2).strip()
pending = {}
DST = re.compile(r'^(x\d+|w\d+|s\d+|d\d+|q\d+)')
for ins in md.disasm(data[start:start+size], start):
    line = "%#x  %s\t%s" % (ins.address, ins.mnemonic, ins.op_str)
    m2 = re.match(r'(x\d+), x27, #(0x[0-9a-f]+), lsl #12', ins.op_str)
    if ins.mnemonic == 'add' and m2:
        pending[m2.group(1)] = int(m2.group(2),16) << 12
    else:
        m3 = re.match(r'(x\d+), \[(x\d+), ?#?(0x[0-9a-f]+)?\]', ins.op_str)
        if ins.mnemonic == 'ldr' and m3 and m3.group(2) in pending:
            off = pending[m3.group(2)] + (int(m3.group(3),16) if m3.group(3) else 0)
            line += "   ; pp+%x => %s" % (off, pool.get(off,'???')[:100])
            pending.pop(m3.group(2), None)
        # 目的寄存器改写 → 失效
        md_ = DST.match(ins.op_str)
        if md_ and md_.group(1) in pending and not (ins.mnemonic=='ldr' and m3 and m3.group(2)==md_.group(1)):
            pending.pop(md_.group(1), None)
    print(line)
