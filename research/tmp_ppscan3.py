import sys, re, os, glob
from capstone import *
LIB = 'research/artifacts/device_libs/libapp.so'
ASM = 'research/artifacts/blutter_out/asm'
data = open(LIB,'rb').read()
targets = {int(t,16) for t in sys.argv[2:]}
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
addre = re.compile(r'// \*\* addr: (0x[0-9a-f]+), size: (0x[0-9a-f]+)')
funcs = []
for f in glob.glob(ASM+'/**/*.dart', recursive=True):
    txt = open(f, encoding='utf-8', errors='ignore').read()
    for m in addre.finditer(txt):
        funcs.append((int(m.group(1),16), int(m.group(2),16), f))
print(f"functions={len(funcs)}")
hits=[]
for addr, size, f in funcs:
    reg_hi = {}
    for ins in md.disasm(data[addr:addr+size], addr):
        m = re.match(r'add (x\d+), x27, #(0x[0-9a-f]+), lsl #12', ins.op_str)
        if m and ins.mnemonic=='add':
            reg_hi[m.group(1)] = int(m.group(2),16)<<12
            continue
        m2 = re.match(r'ldr (x\d+), \[(x\d+), (?:#)?(0x[0-9a-f]+)?\]?', ins.op_str)
        if m2 and ins.mnemonic=='ldr' and m2.group(2) in reg_hi:
            lo = int(m2.group(3),16) if m2.group(3) else 0
            pp = reg_hi[m2.group(2)] + lo
            if pp in targets:
                hits.append((ins.address, pp, f))
            if m2.group(1) != m2.group(2):
                reg_hi.pop(m2.group(2), None)
        if ins.mnemonic=='ldr' and ins.op_str.startswith('x') is False:
            pass
print(f"hits={len(hits)}")
for a, pp, f in hits:
    print(f"{a:#x} pp={pp:#x} {f}")
