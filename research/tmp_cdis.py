import sys
from capstone import *
data = open('research/artifacts/device_libs/libcore.so','rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = False
start, size = int(sys.argv[1],16), int(sys.argv[2],16)
md.skipdata = True
for ins in md.disasm(data[start:start+size], start):
    print("%#x  %s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
