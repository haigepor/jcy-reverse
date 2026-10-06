#!/usr/bin/env python3
"""emu_dec_diag4.py - dump E 管线调用点内存对象 + 动态 br 目标 + RSA 路径数据."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X8)
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))

WATCH = [0x37511c, 0x375144, 0x37521c, 0x375244, 0x37526c, 0x375300, 0x3753a0, 0x3753cc,
         0x375410, 0x375474, 0x3754d0, 0x375514, 0x37557c, 0x3755c0, 0x375604, 0x37566c,
         0x3756b0, 0x375180, 0x375198, 0x3750b8]
BRS = [0x375354, 0x375440]


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
        if off in WATCH:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            k = '0x%x#%d' % (off, hits.get(off, 0) + 1)
            hits[off] = hits.get(off, 0) + 1
            print('[%s] x0=0x%x x1=0x%x x2=0x%x x3=0x%x' % (k, x0, x1, x2, x3), flush=True)
            for tag, p in (('x0.mem', x0), ('x1.mem', x1)):
                m = rd2(p, 48)
                if m:
                    print('    %s: %s' % (tag, m.hex()), flush=True)
                    if all(32 <= c < 127 or c == 0 for c in m[:32]):
                        print('    %s.asc: %r' % (tag, m.split(b'\x00')[0]), flush=True)
        elif off in BRS:
            x8 = uc.reg_read(UC_ARM64_REG_X8)
            hits[off] = hits.get(off, 0) + 1
            print('[br 0x%x#%d] -> 0x%x' % (off, hits[off], x8 - DEV_BASE), flush=True)

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


if __name__ == '__main__':
    main()
