#!/usr/bin/env python3
"""emu_dec_diag7.py - ch_encrypt 输入 + EVP hook + throw 消息/栈回溯."""
import base64
import json
import struct
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X29)
from emu_v11 import Emu, DEV_BASE, VaList
from emu_apidecrypt import CONFIG
from emu_keyhook import ch_encrypt

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))

EVP_INIT = 0x3751b0
EVP_UPD = 0x375284
EVP_FIN = 0x375314
CTOR_RT = 0x612e00
THROW = 0x612ed0
WATCH = (EVP_INIT, EVP_UPD, EVP_FIN)
N = {EVP_INIT: 'Init', EVP_UPD: 'Update', EVP_FIN: 'Final'}


class EmuDiag7(Emu):
    def _do_stub(self, nm, uc):
        if nm == 'vasprintf':
            bufp = uc.reg_read(UC_ARM64_REG_X0)
            fmt = uc.reg_read(UC_ARM64_REG_X1)
            ap = uc.reg_read(UC_ARM64_REG_X2)
            try:
                va = VaList(self, ap)
                s, _ = self._fmt_va(uc, fmt, va)
            except Exception:
                s = self.cstr(fmt, 256)
            print('[vasprintf] %r' % s, flush=True)
            try:
                self._ensure(bufp, len(s) + 1)
                self.wr(bufp, s + b"\x00")
                buf = struct.unpack('<Q', self.rd(bufp, 8))[0]
                self._ensure(buf, len(s) + 1)
                self.wr(buf, s + b"\x00")
            except Exception:
                pass
            uc.reg_write(UC_ARM64_REG_X0, 0)
            return
        if nm == 'android_set_abort_message':
            msg = uc.reg_read(UC_ARM64_REG_X0)
            try:
                m = self.cstr(msg, 512)
            except Exception:
                m = b'?'
            print('[abort_msg] %r' % m, flush=True)
            fp = uc.reg_read(UC_ARM64_REG_X29)
            for i in range(20):
                try:
                    nx, lr = struct.unpack('<QQ', self.rd(fp, 16))
                except Exception:
                    break
                off = lr - DEV_BASE
                print('  fp 0x%x lr_off=0x%x' % (fp, off if 0 < off < 0x800000 else -1), flush=True)
                if nx <= fp:
                    break
                fp = nx
            return super()._do_stub(nm, uc)
        return super()._do_stub(nm, uc)


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = EmuDiag7()
    cnt = {}

    def rdb(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    def code_cb(uc, address, size, ud):
        off = address - DEV_BASE
        if off in WATCH:
            cnt[off] = cnt.get(off, 0) + 1
            x3 = uc.reg_read(UC_ARM64_REG_X3)
            x4 = uc.reg_read(UC_ARM64_REG_X4)
            tag = N[off]
            if off == EVP_INIT:
                k = rdb(x3, 16)
                iv = rdb(x4, 16)
                print('[%s#%d] key=%r iv=%r' % (tag, cnt[off], k, iv), flush=True)
            elif off == EVP_UPD:
                x3v = x3
                m = rdb(x3v, 32)
                print('[%s#%d] inl=0x%x in32=%s' % (tag, cnt[off], x4, (m or b'').hex()), flush=True)
        elif off == CTOR_RT:
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            s = rdb(x1, 300) or b'?'
            print('[runtime_error ctor] %r' % s.split(b'\x00')[0], flush=True)
        elif off == THROW:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            ti = uc.reg_read(UC_ARM64_REG_X1)
            tname = b'?'
            try:
                vptr = int.from_bytes(rdb(ti, 8), 'little')
                namep = int.from_bytes(rdb(vptr + 8, 8), 'little')
                tname = (rdb(namep, 80) or b'?').split(b'\x00')[0]
            except Exception:
                pass
            print('[__cxa_throw] type=%r obj_hex=%s' % (tname, (rdb(x0, 0x20) or b'').hex()), flush=True)
            uc.emu_stop()

    e.uc.hook_add(unicorn.UC_HOOK_CODE, code_cb,
                  begin=DEV_BASE + 0x375048, end=DEV_BASE + 0x375868)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, code_cb,
                  begin=DEV_BASE + CTOR_RT, end=DEV_BASE + CTOR_RT + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, code_cb,
                  begin=DEV_BASE + THROW, end=DEV_BASE + THROW + 4)

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
        print('[*] 返回串(%dB): %r' % (len(s), s[:500]), flush=True)
        open('research/tmp_final_ret.bin', 'wb').write(s)


if __name__ == '__main__':
    main()
