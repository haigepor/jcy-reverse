#!/usr/bin/env python3
"""emu_dec_diag9.py - 精确 dump: qPwC 解密输出(调用前记 out) + nlohmann 输入串解引用."""
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
from emu_keyhook import ch_encrypt

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))

EVP_UPD = 0x375284
UPD_RET = 0x375288
CALLSITE_NL = 0x309564
THROW = 0x612ed0


def main():
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = Emu()
    cnt = {'upd': 0, 'nl': 0, 'throw': 0}
    upd_out = [0, 0]

    def rdb(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    def upd_pre(uc, address, size, ud):
        upd_out[0] = uc.reg_read(UC_ARM64_REG_X1)
        upd_out[1] = uc.reg_read(UC_ARM64_REG_X2)
        inl = uc.reg_read(UC_ARM64_REG_X4)
        cnt['upd'] += 1
        print('[upd-pre#%d] out=0x%x outl_ptr=0x%x inl=0x%x'
              % (cnt['upd'], upd_out[0], upd_out[1], inl), flush=True)

    def upd_post(uc, address, size, ud):
        try:
            outl = int.from_bytes(rdb(upd_out[1], 4), 'little')
        except Exception:
            outl = -1
        m = rdb(upd_out[0], 96) or b''
        print('[upd-post#%d] outl=%s out96=%r' % (cnt['upd'], outl, m), flush=True)
        if outl and outl > 0:
            m2 = rdb(upd_out[0], min(outl, 4096))
            if m2:
                print('    out 全量头 200: %r' % m2[:200], flush=True)
                open('research/tmp_upd_out_%d.bin' % cnt['upd'], 'wb').write(m2)

    def nl_pre(uc, address, size, ud):
        cnt['nl'] += 1
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        raw = rdb(x0, 24)
        if raw:
            a, b, p = struct.unpack('<QQQ', raw)
            print('[nlohmann#%d] cap=%d size=%d ptr=0x%x' % (cnt['nl'], a, b, p), flush=True)
            m = rdb(p, 128)
            if m:
                print('    串头 128: %r' % m, flush=True)
                open('research/tmp_nl_in.bin', 'wb').write(m)

    def throw_cb(uc, address, size, ud):
        cnt['throw'] += 1
        if cnt['throw'] > 3:
            uc.emu_stop()
            return
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        tname = b'?'
        try:
            vptr = int.from_bytes(rdb(x1, 8), 'little')
            namep = int.from_bytes(rdb(vptr + 8, 8), 'little')
            tname = (rdb(namep, 80) or b'?').split(b'\x00')[0]
        except Exception:
            pass
        print('[throw#%d] %r' % (cnt['throw'], tname), flush=True)
        uc.emu_stop()

    e.uc.hook_add(unicorn.UC_HOOK_CODE, upd_pre,
                  begin=DEV_BASE + EVP_UPD, end=DEV_BASE + EVP_UPD + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, upd_post,
                  begin=DEV_BASE + UPD_RET, end=DEV_BASE + UPD_RET + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, nl_pre,
                  begin=DEV_BASE + CALLSITE_NL, end=DEV_BASE + CALLSITE_NL + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, throw_cb,
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
        s = (rdb(out, 8192) or b'').split(b'\x00')[0]
        print('[*] 返回串(%dB): %r' % (len(s), s[:500]), flush=True)
        open('research/tmp_final_ret.bin', 'wb').write(s)


if __name__ == '__main__':
    main()
