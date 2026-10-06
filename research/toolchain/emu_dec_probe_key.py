#!/usr/bin/env python3
"""emu_dec_probe_key.py - 喂 {"a":1} 钓 nlohmann out_of_range 的字段名."""
import base64
import json
import struct
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_PC, UC_ARM64_REG_LR
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG
from emu_keyhook import ch_encrypt

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))
CTOR_RT = 0x612e00


def run(data_val, max_throw=4):
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    env['payload']['data'] = data_val
    env['payload']['path'] = data_val
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = Emu()
    info = {'msgs': []}

    def rdb(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    def ctor_cb(uc, address, size, ud):
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        s = (rdb(x1, 300) or b'?').split(b'\x00')[0]
        info['msgs'].append(s)
        print('[ctor] %r' % s, flush=True)
        if len(info['msgs']) >= max_throw:
            uc.emu_stop()

    e.uc.hook_add(unicorn.UC_HOOK_CODE, ctor_cb,
                  begin=DEV_BASE + CTOR_RT, end=DEV_BASE + CTOR_RT + 4)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    try:
        out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
        if out > 0x1000:
            s = (rdb(out, 8192) or b'').split(b'\x00')[0]
            print('[ret] %r' % s[:300], flush=True)
            info['ret'] = s
        else:
            print('[call] x0=0x%x' % out, flush=True)
    except unicorn.unicorn_py3.unicorn.UcError as ex:
        pc = e.uc.reg_read(UC_ARM64_REG_PC)
        lr = e.uc.reg_read(UC_ARM64_REG_LR)
        print('[CRASH] %s PC_off=0x%x LR_off=0x%x' % (ex, pc - DEV_BASE, lr - DEV_BASE), flush=True)
    for l in e.logs[-6:]:
        print('   ', l)
    return info


if __name__ == '__main__':
    print('======== data = {"a":1} ========')
    run('{"a":1}')
