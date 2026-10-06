import sys
from capstone import *
data = open('research/artifacts/device_libs/libcore.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
start = int(sys.argv[1],16); n = int(sys.argv[2],16)
for ins in md.disasm(data[start:start+n], start):
    print(f"{ins.address:#x}  {ins.mnemonic}\t{ins.op_str}")
