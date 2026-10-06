import sys, os, struct, collections
sys.path.insert(0, 'research/toolchain')
sys.path.insert(0, 'research/deliverables')
sys.path.insert(0, 'research/captures/rsa_scan')
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_PC

BASE = 0x400024a00000
E_LO, E_HI = BASE + 0x2d6f78, BASE + 0x2d8800

code_pcs = []           # E 范围内指令序列
reads = []              # (pc, addr, size, value) 全局读
e = None
def build():
    from emu_v14 import Emu4
    from emu_v11 import HEAP, HEAP_SIZE
    global e
    e = Emu4()
    K = b'0123456789abcdef'
    IV = b'fedcba9876543210'
    e.fix_long_string(0x688130, K)
    e.fix_long_string(0x688148, IV)
    sret = e.alloc(0x40); e.wr(sret, b'\0'*0x40)
    e.uc.hook_add(UC_HOOK_CODE, lambda uc,a,s,ud: code_pcs.append(a), begin=E_LO, end=E_HI)
    def on_read(uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        reads.append((pc, address, size, value))
    e.uc.hook_add(UC_HOOK_MEM_READ, on_read)
    return sret

sret = build()
from e_oracle import EOracle
o = EOracle()
o.s = type('S', (), {})()  # placeholder
# 直接用底层: 复用 o 的逻辑但注入我们的 emu
import e_oracle
o.e = e
o.sret = sret
o._cur = [b'A'*16]
o._out = {}
inp = e.mkstr(b'AAAAAAAAAAAAAAAA')  # 长度只影响 A1 长度, A1 会被覆写
# 但 _pipe_input_from_a1 需要 a1... 直接模仿 EOracle.enc:
def b64len(n): return 4*((n+2)//3)
pt = b'A'*16
L = next(c for c in range(1, len(pt)+1) if b64len(c) == len(pt))
o._cur[0] = pt
import jcy_protocol.auth as A
inp = e.mkstr(A.custom_b64d('A'*L) if False else b'\0'*L)
e.call(BASE + 0x304eb0, (inp, BASE + 0x688130, BASE + 0x688148), sret=sret, timeout=300_000_000)
print('pipeline done, out=', o._out.get('body', b'').hex() if o._out else 'NONE')

print('E-range instructions:', len(code_pcs))
hist = collections.Counter(code_pcs)
print('top pcs:')
for pc, n in hist.most_common(12):
    print('  %x (off %x) x%d' % (pc, pc-BASE, n))
print('reads total:', len(reads))
# E 范围 pc 的读
ereads = [r for r in reads if E_LO <= r[0] < E_HI]
print('reads from E:', len(ereads))
addr_hist = collections.Counter((r[1], r[2]) for r in ereads)
print('top read addrs:')
for (ad, sz), n in addr_hist.most_common(15):
    print('  %x sz%d x%d' % (ad, sz, n))
import pickle
pickle.dump({'code': code_pcs, 'reads': reads}, open('research/tmp_etrace.pkl','wb'))
print('saved research/tmp_etrace.pkl')
