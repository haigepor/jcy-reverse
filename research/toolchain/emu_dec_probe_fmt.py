#!/usr/bin/env python3
"""emu_dec_probe_fmt.py - data 格式探索: 喂候选 JSON, 观察 nlohmann 后行为与报错."""
import base64
import json
import struct
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
from emu_v11 import Emu, DEV_BASE
from emu_apidecrypt import CONFIG
from emu_keyhook import ch_encrypt

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CFG = json.dumps(CONFIG, separators=(',', ':'))

CALLSITE_NL = 0x309564
THROW = 0x612ed0


def run_once(e_hooks=True, data_val=None, quiet=False):
    env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
    if data_val is not None:
        env['payload']['data'] = data_val
        env['payload']['path'] = data_val
    plain = json.dumps(env, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = Emu()
    info = {'throws': [], 'nl_in': None, 'ret': None}

    def rdb(a, n):
        try:
            return bytes(e.rd(a, n))
        except Exception:
            return None

    def nl_pre(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        raw = rdb(x0, 24)
        if raw:
            a, b, p = struct.unpack('<QQQ', raw)
            m = rdb(p, 64)
            info['nl_in'] = (b, p, (m or b'')[:64])

    def throw_cb(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        tname = b'?'
        msg = b''
        try:
            vptr = int.from_bytes(rdb(x1, 8), 'little')
            namep = int.from_bytes(rdb(vptr + 8, 8), 'little')
            tname = (rdb(namep, 80) or b'?').split(b'\x00')[0]
            # runtime_error: obj+8 = string
            raw = rdb(x0, 0x20)
            if raw:
                sp = int.from_bytes(raw[8:16], 'little')
                msg = (rdb(sp, 200) or b'').split(b'\x00')[0]
        except Exception:
            pass
        info['throws'].append((tname, msg))
        uc.emu_stop()

    if e_hooks:
        e.uc.hook_add(unicorn.UC_HOOK_CODE, nl_pre,
                      begin=DEV_BASE + CALLSITE_NL, end=DEV_BASE + CALLSITE_NL + 4)
        e.uc.hook_add(unicorn.UC_HOOK_CODE, throw_cb,
                      begin=DEV_BASE + THROW, end=DEV_BASE + THROW + 4)

    cfg_p = e.alloc(len(CFG) + 1)
    e.wr(cfg_p, CFG.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    if out > 0x1000:
        s = (rdb(out, 8192) or b'').split(b'\x00')[0]
        info['ret'] = s
    return e, info


def main():
    data = json.load(open('research/tmp_real_env.json', encoding='utf-8'))['payload']['data']
    p0, p1 = data.split('.', 1)

    cases = [
        ('原样 P0.P1', None),
        ('空对象 {}', '{}'),
        ('包一层 data', json.dumps({"data": data}, separators=(',', ':'))),
        ('数组 [P0,P1]', json.dumps([p0, p1], separators=(',', ':'))),
        ('{"p","c"}', json.dumps({"p": p0, "c": p1}, separators=(',', ':'))),
        ('{"0","1"}', json.dumps({"0": p0, "1": p1}, separators=(',', ':'))),
        ('{"p0","p1"}', json.dumps({"p0": p0, "p1": p1}, separators=(',', ':'))),
    ]
    for name, dv in cases:
        e, info = run_once(data_val=dv)
        nl = info['nl_in']
        print('== %s' % name, flush=True)
        if nl:
            print('   nlohmann size=%d 头=%r' % (nl[0], nl[2]), flush=True)
        for t, m in info['throws'][:2]:
            print('   throw %r msg=%r' % (t, m[:160]), flush=True)
        if info['ret']:
            print('   返回: %r' % info['ret'][:200], flush=True)
        if not info['throws'] and not info['ret']:
            print('   (无 throw 无返回, logs 尾) %s' % e.logs[-3:], flush=True)


if __name__ == '__main__':
    main()
