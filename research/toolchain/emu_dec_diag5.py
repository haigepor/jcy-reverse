#!/usr/bin/env python3
"""emu_dec_diag5.py - 强制 0x375354 br 走 EVP 段(0x375360), trace 段内动态调用."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X8, UC_ARM64_REG_X9,
                                 UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_W0)
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))

BR_PATCH = 0x375354      # br x8 -> 强制 0x375360
EVP_ENTRY = 0x375360
BLRS = [0x3753a0, 0x3753cc, 0x375410, 0x375474, 0x3754d0, 0x375514,
        0x37557c, 0x3755c0, 0x375604, 0x37566c]


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = base64.b64encode(plain.encode()).decode()

    e = Emu()
    hits = {}

    def rd2(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    def code_cb(uc, address, size, ud):
        off = address - DEV_BASE
        if off == 0x375300 and hits.get(off, 0) == 0:
            hits[off] = 1
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            m = rd2(x1, 64)
            if m:
                print('[0x375300] x1 heap 64B: %r' % m, flush=True)
        elif off == BR_PATCH:
            w0 = uc.reg_read(UC_ARM64_REG_W0)
            x8 = uc.reg_read(UC_ARM64_REG_X8)
            print('[0x375354] w0=%d 原目标=0x%x -> 强制 0x%x'
                  % (w0, x8 - DEV_BASE, EVP_ENTRY), flush=True)
            uc.reg_write(UC_ARM64_REG_X8, DEV_BASE + EVP_ENTRY)
        elif off in BLRS:
            cands = {uc.reg_read(r) for r in (UC_ARM64_REG_X8, UC_ARM64_REG_X9,
                                              UC_ARM64_REG_X16, UC_ARM64_REG_X17)}
            real = [c - DEV_BASE for c in cands
                    if DEV_BASE + 0x1000 <= c < DEV_BASE + 0x800000]
            hits[off] = hits.get(off, 0) + 1
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            print('[blr 0x%x#%d] tgt=%s x0=0x%x x1=0x%x'
                  % (off, hits[off], [hex(r) for r in real], x0, x1), flush=True)
            for tag, p in (('x0', x0), ('x1', x1)):
                m = rd2(p, 32)
                if m and any(32 <= c < 127 for c in m[:16]):
                    print('    %s: %r' % (tag, m), flush=True)

    e.uc.hook_add(unicorn.UC_HOOK_CODE, code_cb,
                  begin=DEV_BASE + 0x375048, end=DEV_BASE + 0x375868)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print('[*] init done', flush=True)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    print('[*] call x0=0x%x' % out, flush=True)
    for l in e.logs[-10:]:
        print('   ', l)


if __name__ == '__main__':
    main()
