#!/usr/bin/env python3
"""emu_dec_diag6.py - hook EVP 调用点(0x3751b0/0x375284/0x375314), dump cipher/key/iv."""
import base64
import json
import struct
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4)
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))

EVP_INIT = 0x3751b0     # bl EVP_DecryptInit_ex
EVP_UPD = 0x375284      # bl EVP_DecryptUpdate
EVP_FIN = 0x375314      # bl EVP_DecryptFinal_ex
WATCH = (EVP_INIT, EVP_UPD, EVP_FIN)


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = base64.b64encode(plain.encode()).decode()

    e = Emu()
    cnt = {}

    def rdb(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    def code_cb(uc, address, size, ud):
        off = address - DEV_BASE
        if off not in WATCH:
            return
        cnt[off] = cnt.get(off, 0) + 1
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x3 = uc.reg_read(UC_ARM64_REG_X3)
        x4 = uc.reg_read(UC_ARM64_REG_X4)
        tag = ('Init', 'Update', 'Final')[WATCH.index(off)]
        print('[%s#%d] x0=0x%x x1=0x%x x2=0x%x x3=0x%x x4=0x%x'
              % (tag, cnt[off], x0, x1, x2, x3, x4), flush=True)
        if off == EVP_INIT:
            # EVP_CIPHER* = x1: nid(bs-4?) dump 0x60B
            if x1:
                raw = rdb(x1 - 4, 0x60)
                if raw:
                    nid, bs, kl, ivl, ctxs = struct.unpack_from('<iiiii', raw, 0)
                    print('    cipher nid=%d bs=%d kl=%d ivl=%d ctxs=%#x raw=%s'
                          % (nid, bs, kl, ivl, ctxs, raw[:0x40].hex()), flush=True)
                    ptrs = struct.unpack_from('<7Q', raw, 0x24)
                    print('    fn ptrs: %s'
                          % [hex(p - DEV_BASE) if DEV_BASE <= p < DEV_BASE + 0x800000 else hex(p)
                             for p in ptrs], flush=True)
            # key=x3, iv=x4
            for tag2, p in (('key', x3), ('iv', x4)):
                m = rdb(p, 16)
                if m:
                    print('    %s: %s | %r' % (tag2, m.hex(), m), flush=True)
        elif off == EVP_UPD:
            outl = rdb(x2, 4)
            m = rdb(x3, 48)
            if m:
                print('    in[48]: %s' % m.hex(), flush=True)
        elif off == EVP_FIN:
            m = rdb(x0, 0xa8)
            if m:
                print('    ctx dump: %s' % m.hex(), flush=True)

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
    for l in e.logs[-8:]:
        print('   ', l)


if __name__ == '__main__':
    main()
