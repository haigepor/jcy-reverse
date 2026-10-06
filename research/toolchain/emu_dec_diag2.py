#!/usr/bin/env python3
"""emu_dec_diag2.py - hook runtime_error ctor / __cxa_throw, 抓守卫异常消息."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CTOR_RT = 0x612e00   # std::runtime_error::runtime_error(char const*)
THROW = 0x612ed0     # __cxa_throw
CFG = json.dumps(CONFIG, separators=(',', ':'))


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = base64.b64encode(plain.encode()).decode()

    e = Emu()

    def ctor_cb(uc, address, size, ud):
        msg = uc.reg_read(UC_ARM64_REG_X1)
        try:
            s = e.cstr(msg, 300)
        except Exception as ex:
            s = b'<err %s>' % str(ex).encode()
        print('[runtime_error ctor] msg=%r  lr_off=0x%x'
              % (s, uc.reg_read(30) - DEV_BASE), flush=True)

    def throw_cb(uc, address, size, ud):
        obj = uc.reg_read(UC_ARM64_REG_X0)
        ti = uc.reg_read(UC_ARM64_REG_X1)
        info = {}
        for tag, ptr in (('obj', obj), ('tinfo', ti)):
            try:
                raw = bytes(e.rd(ptr, 0x30))
                info[tag] = raw.hex()
                # tinfo: vptr; vptr+8 = name ptr
                if tag == 'tinfo':
                    vptr = int.from_bytes(raw[0:8], 'little')
                    namep = int.from_bytes(e.rd(vptr + 8, 8), 'little')
                    info['tname'] = e.cstr(namep, 80)
                if tag == 'obj':
                    # libc++ runtime_error: vptr + string(SSO)
                    sp = int.from_bytes(raw[8:16], 'little')
                    try:
                        info['what_sso'] = e.cstr(sp, 200)
                    except Exception:
                        pass
            except Exception as ex:
                info[tag] = 'err %s' % ex
        print('[__cxa_throw] obj=0x%x tinfo=0x%x\n   obj=%s\n   tname=%s what_sso=%r'
              % (obj, ti, info.get('obj'), info.get('tname'), info.get('what_sso')),
              flush=True)
        uc.emu_stop()

    e.uc.hook_add(unicorn.UC_HOOK_CODE, ctor_cb,
                  begin=DEV_BASE + CTOR_RT, end=DEV_BASE + CTOR_RT + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, throw_cb,
                  begin=DEV_BASE + THROW, end=DEV_BASE + THROW + 4)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print('[*] init done (ctor hits during init 见上)', flush=True)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    print('[*] call x0=0x%x' % out, flush=True)


if __name__ == '__main__':
    main()
