#!/usr/bin/env python3
"""emu_dec_diag.py - 诊断 api_decrypt abort: vasprintf 格式化 + fp 链回溯 + syscall dump."""
import base64
import json
import struct
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X8, UC_ARM64_REG_X29,
                                 UC_ARM64_REG_LR)
from emu_v11 import Emu, DEV_BASE, VaList
from emu_apidecrypt import CONFIG

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))


class EmuDiag(Emu):
    def _do_stub(self, nm, uc):
        if nm == 'vasprintf':
            bufp = uc.reg_read(UC_ARM64_REG_X0)
            fmt = uc.reg_read(UC_ARM64_REG_X1)
            ap = uc.reg_read(UC_ARM64_REG_X2)
            try:
                va = VaList(self, ap)
                s, _ = self._fmt_va(uc, fmt, va)
            except Exception as ex:
                s = b'<fmt err %s | fmt=%s>' % (str(ex).encode(), self.cstr(fmt, 256))
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
            print('[backtrace] fp=0x%x' % fp, flush=True)
            for i in range(24):
                try:
                    nx, lr = struct.unpack('<QQ', self.rd(fp, 16))
                except Exception:
                    break
                print('  frame#%d fp=0x%x lr=0x%x off=0x%x' % (i, fp, lr, (lr - DEV_BASE) if DEV_BASE <= lr < DEV_BASE + 0x800000 else -1), flush=True)
                if nx <= fp or nx < 0x70000000 or nx > 0x71000000 and nx < 0x400000000000:
                    break
                fp = nx
            return super()._do_stub(nm, uc)
        if nm == 'syscall':
            nr = uc.reg_read(UC_ARM64_REG_X8)
            args = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                             UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
            print('[syscall] nr=%d args=%s' % (nr, [hex(v) for v in args]), flush=True)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            return
        if nm == 'dl_iterate_phdr':
            cb = uc.reg_read(UC_ARM64_REG_X0)
            data = uc.reg_read(UC_ARM64_REG_X1)
            print('[dl_iterate_phdr] cb_off=0x%x data=0x%x' % (cb - DEV_BASE, data), flush=True)
            uc.reg_write(UC_ARM64_REG_X0, 0)
            return
        return super()._do_stub(nm, uc)


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = base64.b64encode(plain.encode()).decode()

    e = EmuDiag()
    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print('[*] init done', flush=True)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    print('[*] call x0=0x%x' % out, flush=True)
    for l in e.logs[-25:]:
        print('   ', l)


if __name__ == '__main__':
    main()
