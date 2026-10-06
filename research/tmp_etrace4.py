import sys, collections, struct, pickle
sys.path.insert(0, 'research/toolchain')
sys.path.insert(0, 'src')
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X29

BASE = 0x400024a00000
from emu_v14 import Emu4
e = Emu4()
K = b'0123456789abcdef'
IV = b'fedcba9876543210'
e.fix_long_string(0x688130, K)
e.fix_long_string(0x688148, IV)
sret = e.alloc(0x40); e.wr(sret, b'\0'*0x40)

events = []  # (kind, pc_off, addr_off, size, value)  addr_off=-1 表示非 libcore 地址
def on_read(uc, access, address, size, value, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC) - BASE
    off = address - BASE
    events.append((0, pc, off if 0 <= off < 0x700000 else -1, size, value))
def on_write(uc, access, address, size, value, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC) - BASE
    off = address - BASE
    events.append((1, pc, off if 0 <= off < 0x700000 else -1, size, value))
e.uc.hook_add(UC_HOOK_MEM_READ, on_read)
e.uc.hook_add(UC_HOOK_MEM_WRITE, on_write)

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
e.call(BASE + 0x304eb0, (inp, BASE + 0x688130, BASE + 0x688148), sret=sret, timeout=600_000_000)
print('body:', out.get('body', b'').hex()[:32])
print('events:', len(events))
pickle.dump(events, open('research/tmp_events.pkl','wb'))
# 分析: 字节读(sz1)的地址分布
b1 = [ev for ev in events if ev[0]==0 and ev[3]==1]
print('byte reads:', len(b1))
h = collections.Counter(ev[2] for ev in b1 if ev[2] >= 0)
print('top byte-read addrs:', [(hex(a), n) for a,n in h.most_common(12)])
# sz4 读
w4 = [ev for ev in events if ev[0]==0 and ev[3]==4]
h4 = collections.Counter(ev[2] for ev in w4 if ev[2] >= 0)
print('word reads:', len(w4), 'top:', [(hex(a), n) for a,n in h4.most_common(12)])
# 写分布
wr = [ev for ev in events if ev[0]==1]
hw = collections.Counter(ev[2] for ev in wr if ev[2] >= 0)
print('writes:', len(wr), 'top:', [(hex(a), n) for a,n in hw.most_common(12)])
