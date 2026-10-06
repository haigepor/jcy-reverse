import sys, collections, struct
sys.path.insert(0, 'research/toolchain')
sys.path.insert(0, 'src')
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X29

BASE = 0x400024a00000
from emu_v14 import Emu4
e = Emu4()
K = b'0123456789abcdef'
IV = b'fedcba9876543210'
e.fix_long_string(0x688130, K)
e.fix_long_string(0x688148, IV)
sret = e.alloc(0x40); e.wr(sret, b'\0'*0x40)

reads = []
def on_read(uc, access, address, size, value, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    off = address - BASE
    if 0x66b000 <= off < 0x671000:   # .bss/.data 表区 (GOT 之前)
        reads.append((pc - BASE, off, size, value))
e.uc.hook_add(UC_HOOK_MEM_READ, on_read)

cur = [b'A'*16]; out = {}
def hook(uc, address, size, ud):
    x29 = uc.reg_read(UC_ARM64_REG_X29)
    b, en, _ = struct.unpack('<QQQ', e.rd(x29-0x38, 24))
    if address == BASE + 0x304fb8:
        if en - b == len(cur[0]): e.wr(b, cur[0])
    else:
        out['body'] = e.rd(b, en-b)
for a in (BASE + 0x304fb8, BASE + 0x3050fc):
    e.uc.hook_add(UC_HOOK_CODE, hook, begin=a, end=a+4)

def b64len(n): return 4*((n+2)//3)
pt = b'A'*16
L = next(c for c in range(1, len(pt)+1) if b64len(c) == len(pt))
inp = e.mkstr(b'\0'*L)
e.call(BASE + 0x304eb0, (inp, BASE + 0x688130, BASE + 0x688148), sret=sret, timeout=300_000_000)
print('body:', out.get('body', b'').hex())
print('table-region reads:', len(reads))
# 访问序列前 60 条
for pc, off, sz, val in reads[:60]:
    print('  pc=%06x off=%06x sz%d val=%016x' % (pc, off, sz, val))
# 被读地址直方图
h = collections.Counter(off for _,off,_,_ in reads)
print('top addrs:', [(hex(a), n) for a,n in h.most_common(10)])
# dump 表区
lo, hi = 0x66e000, 0x670000
blob = e.rd(BASE+lo, hi-lo)
open('research/tmp_tabdump.bin','wb').write(blob)
print('dumped %x-%x (%d B) to research/tmp_tabdump.bin' % (lo, hi, hi-lo))
