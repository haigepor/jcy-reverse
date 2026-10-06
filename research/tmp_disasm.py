import sys, re
from capstone import *
LIB = 'research/artifacts/device_libs/libapp.so'
data = open(LIB,'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False
start, size = int(sys.argv[1],16), int(sys.argv[2],16)
calls=[]
for ins in md.disasm(data[start:start+size], start):
    line = f"{ins.address:#x}  {ins.mnemonic}\t{ins.op_str}"
    if ins.mnemonic in ('bl','b') :
        m=re.match(r'#(0x[0-9a-f]+)', ins.op_str)
        if m and ins.mnemonic=='bl': calls.append(int(m.group(1),16))
    if 'pp+' in ins.op_str.lower() or 'pp]' in ins.op_str.lower():
        line += "   ; PP"
    print(line)
print("\n=== CALL TARGETS ===")
for c in calls: print(f"{c:#x}")
