#!/usr/bin/env python3
"""emu_dec_closedloop.py - 双调用闭环: 先 api_encrypt(填 key store) 再 api_decrypt(真信封)."""
import base64
import json
import struct
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X3,
                                 UC_ARM64_REG_X4, UC_ARM64_REG_PC, UC_ARM64_REG_LR)
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG
from emu_keyhook import ch_encrypt

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))
CTOR_RT = 0x612e00
THROW = 0x612ed0
UPD = 0x375284
KSA = 0x2cd8b0
NL_CALL = 0x309564
RET_GADGET_OFF = 0x2cdc90

PARAMS = ('{"device_id":"cddc4dcf-260d-4684-a8e7-463b2db261e5",'
          '"appid":"4150439554430529","version":"1.5.8.0",'
          '"code_version":"2020-09-17","app_name":"jcymh"}')


def mk_env(action, data_val, path_val, decoys=True):
    env = {}
    if decoys:
        for k, v in json.load(open('research/tmp_real_env.json', encoding='utf-8')).items():
            if k not in ('action', 'payload') and isinstance(v, str) and len(v) == 16:
                env[k] = v
    env['action'] = action
    env['payload'] = {'data': data_val, 'path': path_val}
    return json.dumps(env, separators=(',', ':'))


def main():
    real = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    body = real['payload']['data']   # P0.P1 裸串

    e = Emu()
    state = {'upd': 0, 'ksa': 0, 'nl': 0, 'throws': []}

    def rdb(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    def cb_factory(tag):
        def cb(uc, address, size, ud):
            off = address - DEV_BASE
            if off == CTOR_RT:
                x1 = uc.reg_read(UC_ARM64_REG_X1)
                s = (rdb(x1, 300) or b'?').split(b'\x00')[0]
                state['throws'].append(s)
                print('  [%s][ctor] %r' % (tag, s), flush=True)
                if len(state['throws']) >= 4:
                    uc.emu_stop()
            elif off == UPD:
                state['upd'] += 1
                x3 = uc.reg_read(UC_ARM64_REG_X3)
                x4 = uc.reg_read(UC_ARM64_REG_X4)
                m = rdb(x3, 24)
                print('  [%s][EVP-Upd#%d] inl=0x%x in24=%s'
                      % (tag, state['upd'], x4, (m or b'').hex()), flush=True)
            elif off == KSA:
                state['ksa'] += 1
                x0 = uc.reg_read(UC_ARM64_REG_X0)
                x1 = uc.reg_read(UC_ARM64_REG_X1)
                x2 = uc.reg_read(UC_ARM64_REG_X2)
                m1 = rdb(x1, 16)
                print('  [%s][KSA#%d] x0=0x%x x1=%r x2=0x%x'
                      % (tag, state['ksa'], x0, m1, x2), flush=True)
            elif off == NL_CALL:
                state['nl'] += 1
                x0 = uc.reg_read(UC_ARM64_REG_X0)
                raw = rdb(x0, 24)
                if raw:
                    a, b, p = struct.unpack('<QQQ', raw)
                    m = rdb(p, 48)
                    print('  [%s][nlohmann#%d] size=%d 头=%r'
                          % (tag, state['nl'], b, (m or b'')[:48]), flush=True)
        return cb

    for off, n in ((CTOR_RT, 4), (THROW, 4), (UPD, 4), (KSA, 4), (NL_CALL, 4)):
        pass  # hooks 加全区段一次即可
    e.uc.hook_add(unicorn.UC_HOOK_CODE, cb_factory('pre'),
                  begin=DEV_BASE + 0x2cd8b0, end=DEV_BASE + 0x2cd8b4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, cb_factory('main'),
                  begin=DEV_BASE + CTOR_RT, end=DEV_BASE + CTOR_RT + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, cb_factory('main'),
                  begin=DEV_BASE + THROW, end=DEV_BASE + THROW + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, cb_factory('main'),
                  begin=DEV_BASE + UPD, end=DEV_BASE + UPD + 4)
    e.uc.hook_add(unicorn.UC_HOOK_CODE, cb_factory('main'),
                  begin=DEV_BASE + NL_CALL, end=DEV_BASE + NL_CALL + 4)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print('[*] init done', flush=True)

    cb = e.alloc(8)
    e.wr(cb, struct.pack('<I', 0xd65f03c0))  # ret gadget

    def do_call(tag, payload_json):
        enc_b64 = ch_encrypt(payload_json.encode())
        inp = e.alloc(len(enc_b64) + 1)
        e.wr(inp, enc_b64.encode() + b"\x00")
        print('[%s] 输入 %dB(明文 %dB)' % (tag, len(enc_b64), len(payload_json)), flush=True)
        try:
            out = e.call(DEV_BASE + CALL_OFF, (inp, cb), timeout=600_000_000)
            if out > 0x1000:
                s = (rdb(out, 16384) or b'').split(b'\x00')[0]
                print('[%s] 返回 %dB: %r' % (tag, len(s), s[:300]), flush=True)
                open('research/tmp_cl_%s.bin' % tag, 'wb').write(s)
            else:
                print('[%s] x0=0x%x' % (tag, out), flush=True)
        except Exception as ex:
            pc = e.uc.reg_read(UC_ARM64_REG_PC)
            lr = e.uc.reg_read(UC_ARM64_REG_LR)
            print('[%s] CRASH %s PC_off=0x%x LR_off=0x%x'
                  % (tag, ex, pc - DEV_BASE, lr - DEV_BASE), flush=True)

    # 第 1 步: api_encrypt(填 store, 触发 RAND)
    do_call('enc', mk_env('api_encrypt', PARAMS, '/app/video/device-base'))
    # 第 2 步: api_decrypt(真机格式裸 P0.P1)
    do_call('dec', mk_env('api_decrypt', body, body))
    print('[*] 统计: upd=%d ksa=%d nlohmann=%d throws=%d'
          % (state['upd'], state['ksa'], state['nl'], len(state['throws'])), flush=True)


if __name__ == '__main__':
    main()
