import re
from capstone import *
LIB = 'research/artifacts/device_libs/libapp.so'
data = open(LIB,'rb').read()
TEXT_OFF, TEXT_SZ = 0x500000, 0x7da9e0
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
n_add=0; n_ldrpp=0; n_ins=0; first_add=None
code = data[TEXT_OFF:TEXT_OFF+TEXT_SZ]
for ins in md.disasm(code, TEXT_OFF):
    n_ins+=1
    if ins.mnemonic=='add' and 'x27' in ins.op_str and 'lsl #12' in ins.op_str:
        n_add+=1
        if first_add is None: first_add=(ins.address, ins.mnemonic, ins.op_str)
    if ins.mnemonic=='ldr' and 'x27]' in ins.op_str.replace(' ',''):
        n_ldrpp+=1
print(f"instructions={n_ins} add_x27_lsl12={n_add} ldr_[x27]={n_ldrpp}")
print("first add:", first_add)
