#!/usr/bin/env python3
"""emu_dec_final.py - 正确输入协议(ch_encrypt) + 真机信封格式 → 走通 P1 解密."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4)
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG
from emu_keyhook import ch_encrypt

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))

EVP_INIT = 0x3751b0
EVP_UPD = 0x375284
EVP_FIN = 0x375314
WATCH = (EVP_INIT, EVP_UPD, EVP_FIN)
N = {EVP_INIT: 'Init', EVP_UPD: 'Update', EVP_FIN: 'Final'}


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())
    print('[*] 输入: ch_encrypt(%dB) -> b64 %dB' % (len(plain), len(enc_b64)), flush=True)

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
        tag = N[off]
        print('[%s#%d] x0=0x%x x1=0x%x x2=0x%x x3=0x%x x4=0x%x'
              % (tag, cnt[off], x0, x1, x2, x3, x4), flush=True)
        if off == EVP_INIT:
            for t2, p in (('key', x3), ('iv', x4)):
                m = rdb(p, 16)
                if m:
                    print('    %s: %s | %r' % (t2, m.hex(), m), flush=True)
        elif off == EVP_UPD:
            inl = x4
            m = rdb(x3, min(inl, 48))
            if m:
                print('    in(%dB head48): %s' % (inl, m.hex()), flush=True)
            outl = rdb(x2, 4)
        elif off == EVP_FIN:
            outl = rdb(x2, 4)
            print('    Final outl ptr=0x%x' % (outl and int.from_bytes(outl, 'little')), flush=True)
            # Final 后 out 缓冲内容下一轮读; 先记 x1
            e._fin_out = x1

    e.uc.hook_add(unicorn.UC_HOOK_CODE, code_cb,
                  begin=DEV_BASE + 0x375048, end=DEV_BASE + 0x375868)

    def upd_ret(uc, address, size, ud):
        # Update 返回后读 outl 与 out
        off = address - DEV_BASE
        if off == 0x375288 and cnt.get(EVP_UPD):
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            try:
                outl = int.from_bytes(bytes(e.rd(x2, 4)), 'little')
            except Exception:
                outl = -1
            m = rdb(x1, min(max(outl, 0), 512))
            print('    [upd-ret] outl=%d out=%r' % (outl, (m or b'')[:400]), flush=True)

    e.uc.hook_add(unicorn.UC_HOOK_CODE, upd_ret,
                  begin=DEV_BASE + 0x375288, end=DEV_BASE + 0x37528c)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print('[*] init done', flush=True)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    print('[*] call x0=0x%x' % out, flush=True)
    if out > 0x1000:
        s = rdb(out, 8192) or b''
        s = s.split(b'\x00')[0]
        print('[*] 返回串(%dB): %r' % (len(s), s[:600]), flush=True)
        open('research/tmp_final_ret.bin', 'wb').write(s)
    for l in e.logs[-8:]:
        print('   ', l)


if __name__ == '__main__':
    main()
