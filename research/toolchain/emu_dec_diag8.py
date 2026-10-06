#!/usr/bin/env python3
"""emu_dec_diag8.py - upd 返回读 out + nlohmann 解析输入定位(0x309564 调用点参数)."""
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

EVP_UPD = 0x375284
UPD_RET = 0x375288
CALLSITE_NL = 0x309564   # parse_error 栈帧 0x309568 的调用点
CTOR_RT = 0x612e00
THROW = 0x612ed0


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = Emu()
    cnt = {'upd': 0, 'nl': 0}

    def rdb(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    def code_cb(uc, address, size, ud):
        off = address - DEV_BASE
        if off == CALLSITE_NL:
            cnt['nl'] += 1
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            print('[nlohmann callsite#%d @0x309564] x0=0x%x x1=0x%x x2=0x%x'
                  % (cnt['nl'], x0, x1, x2), flush=True)
            for tag, p in (('x0', x0), ('x1', x1)):
                m = rdb(p, 96)
                if m:
                    pr = m.split(b'\x00')[0]
                    print('    %s 96B: %r' % (tag, pr if len(pr) > 8 else m.hex()), flush=True)
                    # 若是 libc++ string, 前 8B 可能是 SSO 判定位, 试着偏移读
                    m2 = rdb(p + 8, 96)
                    if m2:
                        pr2 = m2.split(b'\x00')[0]
                        print('    %s+8 96B: %r' % (tag, pr2 if len(pr2) > 8 else m2[:32].hex()), flush=True)
        elif off == CTOR_RT:
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            s = rdb(x1, 300) or b'?'
            print('[ctor] %r' % s.split(b'\x00')[0], flush=True)
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
            print('[throw] %r' % tname, flush=True)
            uc.emu_stop()

    def upd_ret_cb(uc, address, size, ud):
        cnt['upd'] += 1
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        try:
            outl = int.from_bytes(rdb(x2, 4), 'little')
        except Exception:
            outl = -1
        m = rdb(x1, 96) or b''
        print('[upd-ret#%d] outl=%d out96=%r' % (cnt['upd'], outl, m[:96]), flush=True)

    e.uc.hook_add(unicorn.UC_HOOK_CODE, code_cb,
                  begin=DEV_BASE + CALLSITE_NL, end=DEV_BASE + CALLSITE_NL + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, code_cb,
                  begin=DEV_BASE + CTOR_RT, end=DEV_BASE + CTOR_RT + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, code_cb,
                  begin=DEV_BASE + THROW, end=DEV_BASE + THROW + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, upd_ret_cb,
                  begin=DEV_BASE + UPD_RET, end=DEV_BASE + UPD_RET + 4)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print('[*] init done', flush=True)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    print('[*] call x0=0x%x' % out, flush=True)
    if out > 0x1000:
        s = (rdb(out, 8192) or b'').split(b'\x00')[0]
        print('[*] 返回串(%dB): %r' % (len(s), s[:500]), flush=True)
        open('research/tmp_final_ret.bin', 'wb').write(s)


if __name__ == '__main__':
    main()
