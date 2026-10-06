#!/usr/bin/env python3
"""emu_dec_trace.py - trace 0x375048 守卫函数内所有 bl/blr 目标 + EVP 参数 dump."""
import base64
import collections
import json
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
GUARD_LO, GUARD_HI = 0x375048, 0x375868
CFG = json.dumps(CONFIG, separators=(',', ':'))

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
img = open('research/tmp_img.bin', 'rb').read()

BL = {}   # addr -> static target
BLR = []  # addr of blr (dynamic)
for i in md.disasm(img[GUARD_LO:GUARD_HI], GUARD_LO):
    if i.mnemonic == 'bl':
        BL[i.address] = int(i.op_str.replace('#', ''), 16)
    elif i.mnemonic == 'blr':
        BLR.append(i.address)
print('[*] static bl=%d blr=%d' % (len(BL), len(BLR)), flush=True)

callseq = []


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = base64.b64encode(plain.encode()).decode()

    e = Emu()

    def code_cb(uc, address, size, ud):
        off = address - DEV_BASE
        if off in BL:
            tgt = BL[off]
            args = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                             UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
            callseq.append(('bl', off, tgt, args))
        elif off in BLR_SET:
            tgt = uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_X8)
            # blr 的寄存器操作数可能是 x8/x9/x16... 统一读几个
            cands = [uc.reg_read(r) for r in (unicorn.arm64_const.UC_ARM64_REG_X8,
                                              unicorn.arm64_const.UC_ARM64_REG_X9,
                                              unicorn.arm64_const.UC_ARM64_REG_X16,
                                              unicorn.arm64_const.UC_ARM64_REG_X17)]
            args = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                             UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
            callseq.append(('blr', off, cands, args))

    BLR_SET = set(BLR)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, code_cb,
                  begin=DEV_BASE + GUARD_LO, end=DEV_BASE + GUARD_HI)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print('[*] init done', flush=True)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    print('[*] call x0=0x%x, 调用序列 %d 条' % (out, len(callseq)), flush=True)

    # bl 目标统计
    blcnt = collections.Counter(t for k, o, t, a in callseq if k == 'bl')
    print('[*] bl 目标 top30:')
    for t, c in blcnt.most_common(30):
        print('    0x%x  x%d' % (t, c), flush=True)
    # blr 目标统计(四候选取 DEV_BASE 区内的)
    blrcnt = collections.Counter()
    for k, o, cands, a in callseq:
        if k != 'blr':
            continue
        real = [c for c in cands if DEV_BASE + 0x1000 <= c < DEV_BASE + 0x800000]
        blrcnt[tuple(hex(c - DEV_BASE) for c in real[:2])] += 1
    print('[*] blr 目标 top30:')
    for t, c in blrcnt.most_common(30):
        print('    %s  x%d' % (t, c), flush=True)

    with open('research/tmp_guard_calls.json', 'w') as f:
        json.dump([['bl' if k == 'bl' else 'blr', hex(o),
                    hex(t) if k == 'bl' else [hex(c) for c in t],
                    [hex(v) for v in a]] for k, o, t, a in callseq], f, indent=0)
    print('[*] 序列已存 research/tmp_guard_calls.json', flush=True)


if __name__ == '__main__':
    main()
