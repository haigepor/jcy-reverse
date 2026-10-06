import sys, collections
sys.path.insert(0, 'research/toolchain')
sys.path.insert(0, 'research/deliverables')
sys.path.insert(0, 'research/captures/rsa_scan')
sys.path.insert(0, 'src')
from unicorn import UC_HOOK_CODE

BASE = 0x400024a00000
from emu_v14 import Emu4
e = Emu4()
K = b'0123456789abcdef'
IV = b'fedcba9876543210'
e.fix_long_string(0x688130, K)
e.fix_long_string(0x688148, IV)
sret = e.alloc(0x40); e.wr(sret, b'\0'*0x40)

pcs = collections.Counter()
def on_code(uc, address, size, ud):
    pcs[address] += 1
e.uc.hook_add(UC_HOOK_CODE, on_code)

import jcy_protocol.auth as A
from unicorn.arm64_const import UC_ARM64_REG_PC
# 用 e_oracle 同款输入流程
def b64len(n): return 4*((n+2)//3)
pt = b'A'*16
L = next(c for c in range(1, len(pt)+1) if b64len(c) == len(pt))
# UnicornESession 的 A1 hook 逻辑需要 OFF_AFTER_A1/E hook; 手动补:
import struct as st
from unicorn import UC_HOOK_CODE as UCC
cur = [pt]; out = {}
def hook(uc, address, size, ud):
    x29 = uc.reg_read(0x1d)  # X29? unicorn arm64 X29 reg id — 用常量
e2 = e
from unicorn.arm64_const import UC_ARM64_REG_X29
def hook(uc, address, size, ud):
    x29 = uc.reg_read(UC_ARM64_REG_X29)
    b, en, _ = st.unpack('<QQQ', e.rd(x29-0x38, 24))
    if address == BASE + 0x304fb8:
        if en - b == len(cur[0]):
            e.wr(b, cur[0])
    else:
        out['body'] = e.rd(b, en-b)
for a in (BASE + 0x304fb8, BASE + 0x3050fc):
    e.uc.hook_add(UCC, hook, begin=a, end=a+4)

inp = e.mkstr(b'\0'*L)
e.call(BASE + 0x304eb0, (inp, BASE + 0x688130, BASE + 0x688148), sret=sret, timeout=300_000_000)
print('body len', len(out.get('body', b'')), out.get('body', b'').hex()[:64])
print('total instr:', sum(pcs.values()), 'unique pcs:', len(pcs))
# 聚合到 64B 粒度的函数簇
clusters = collections.Counter()
for pc, n in pcs.items():
    off = pc - BASE
    if 0 <= off < 0x624d70:
        clusters[off & ~0x3f] += n
print('top 64B clusters (off, count):')
for c, n in clusters.most_common(20):
    print('  %06x x%d' % (c, n))
import pickle
pickle.dump(dict(pcs), open('research/tmp_pcs.pkl','wb'))
