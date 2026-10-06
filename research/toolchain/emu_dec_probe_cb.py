#!/usr/bin/env python3
"""emu_dec_probe_cb.py - call(inp, callback) 第二参数传 ret-gadget, 走通回调槽."""
import base64
import json
import struct
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4,
                                 UC_ARM64_REG_PC, UC_ARM64_REG_LR)
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG
from emu_keyhook import ch_encrypt

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))
RET_GADGET = 0x2cdc90    # 纯 ret 指令
CTOR_RT = 0x612e00
UPD = 0x375284


def run(data_val, label):
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    if data_val is not None:
        env['payload']['data'] = data_val
        env['payload']['path'] = data_val
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = Emu()

    def rdb(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    msgs = []

    def ctor_cb(uc, address, size, ud):
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        s = (rdb(x1, 300) or b'?').split(b'\x00')[0]
        msgs.append(s)
        print('  [ctor] %r' % s, flush=True)
        if len(msgs) >= 6:
            uc.emu_stop()

    def upd_cb(uc, address, size, ud):
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x3 = uc.reg_read(UC_ARM64_REG_X3)
        x4 = uc.reg_read(UC_ARM64_REG_X4)
        m = rdb(x3, 24)
        print('  [EVP-Upd] out=0x%x inl=0x%x in24=%s' % (x1, x4, (m or b'').hex()), flush=True)

    e.uc.hook_add(unicorn.UC_HOOK_CODE, ctor_cb,
                  begin=DEV_BASE + CTOR_RT, end=DEV_BASE + CTOR_RT + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, upd_cb,
                  begin=DEV_BASE + UPD, end=DEV_BASE + UPD + 4)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    cb = e.alloc(8)
    e.wr(cb, struct.pack('<I', 0xd65f03c0))  # ret
    print('== %s' % label, flush=True)
    try:
        out = e.call(DEV_BASE + CALL_OFF, (inp, cb), timeout=600_000_000)
        if out > 0x1000:
            s = (rdb(out, 8192) or b'').split(b'\x00')[0]
            print('  [ret] %dB: %r' % (len(s), s[:400]), flush=True)
            open('research/tmp_cb_ret.bin', 'wb').write(s)
        else:
            print('  [call] x0=0x%x' % out, flush=True)
    except unicorn.unicorn_py3.unicorn.UcError as ex:
        pc = e.uc.reg_read(UC_ARM64_REG_PC)
        lr = e.uc.reg_read(UC_ARM64_REG_LR)
        print('  [CRASH] %s PC_off=0x%x LR_off=0x%x' % (ex, pc - DEV_BASE, lr - DEV_BASE), flush=True)
    for l in e.logs[-6:]:
        print('   ', l)


if __name__ == '__main__':
    run('{"a":1}', 'data={"a":1}')
    run(None, 'data=P0.P1 原样')
