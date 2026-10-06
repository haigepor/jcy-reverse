#!/usr/bin/env python3
"""emu_dec_seed.py - encrypt 填会话对后, 种子 K16resp 到 0x500028d8, 再 api_decrypt 看是否真解密."""
import base64
import json
import struct
import sys

sys.path.insert(0, 'research/toolchain')
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import unicorn
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
from unicorn.unicorn_const import UC_HOOK_CODE
from emu_keyhook import EmuKey, ch_encrypt, CONFIG, CALL_OFF, INIT_OFF

DEV_BASE = 0x400024a00000
CB_ADDR = 0x62000000
PAIR = 0x500028d8            # [IV 16B][KEY 16B] (encrypt 运行实测)
KSA = DEV_BASE + 0x2cd8b0
KS_KEY = DEV_BASE + 0x689528
KS_IV = DEV_BASE + 0x689540

K16RESP = b'HWE2HYC3QRJNEVKS'   # bodies_now device-base 响应 P0 解封

body = None
for line in open('research/captures/rsa_scan/bodies_now.jsonl', encoding='utf-8', errors='replace'):
    try:
        o = json.loads(line)
    except Exception:
        continue
    if '/app/video/device-base' in o.get('req', ''):
        r = o.get('resp_body_ascii', '')
        if r.count('.') == 1 and len(r) > 400:
            body = r.strip()
assert body

e = EmuKey()
state = {'ksa': [], 'result': None}


def cb_factory(tag):
    def cb(uc, addr, size, ud):
        off = addr - DEV_BASE
        if off == 0x2cd8b0:
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            try:
                k = bytes(uc.mem_read(x1, 16))
            except Exception:
                k = b'?'
            state['ksa'].append(k)
            print('[%s][KSA] x1=%r' % (tag, k), flush=True)
    return cb


def cb_hook(uc, addr, size, ud):
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    try:
        raw = bytes(uc.mem_read(x0, 16384)).split(b'\x00')[0]
        state['result'] = raw
        print('[CB] 结果 %dB: %s...' % (len(raw), raw[:80]), flush=True)
    except Exception as ex:
        print('[CB] 读取失败 %s' % ex, flush=True)


e.uc.hook_add(UC_HOOK_CODE, cb_factory('enc'), begin=DEV_BASE + KSA, end=DEV_BASE + KSA)
e.uc.hook_add(UC_HOOK_CODE, cb_hook, begin=CB_ADDR, end=CB_ADDR)

cfg = json.dumps(CONFIG, separators=(',', ':'))
cfg_p = e.alloc(len(cfg) + 1)
e.wr(cfg_p, cfg.encode() + b'\x00')
e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
print('[*] init 完成', flush=True)

e.uc.mem_map(CB_ADDR, 0x1000)
e.uc.mem_write(CB_ADDR, (0xD65F03C0).to_bytes(4, 'little'))


def do_call(tag, env):
    enc = ch_encrypt(json.dumps(env, separators=(',', ':')).encode())
    inp = e.alloc(len(enc) + 1)
    e.wr(inp, enc.encode() + b'\x00')
    try:
        out = e.call(DEV_BASE + CALL_OFF, (inp, CB_ADDR), timeout=600_000_000)
        print('[%s] call x0=0x%x' % (tag, out), flush=True)
    except Exception as ex:
        pc = e.uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
        print('[%s] crash %s PC_off=0x%x' % (tag, ex, pc - DEV_BASE), flush=True)


# 1) api_encrypt — 生成会话对 (崩溃在序列化, 不影响状态)
PARAMS = '{"device_id":"cddc4dcf-260d-4684-a8e7-463b2db261e5","appid":"4150439554430529","version":"1.5.8.0","code_version":"2020-09-17","app_name":"jcymh"}'
do_call('enc', {"action": "api_encrypt", "payload": {"data": PARAMS, "path": '/app/video/device-base'}})

# 2) 种子: 会话对写入 K16resp
iv = K16RESP[::-1]
e.wr(PAIR, iv + K16RESP)
print('[seed] 0x%x = iv=%r key=%r' % (PAIR, iv, K16RESP), flush=True)
# 通道槽也换成 K16resp (响应对的 E 通道可能从这里取)
# (先不动 0x689528 — 那会破坏输入通道解密!)

# 3) api_decrypt (quoted data)
do_call('dec', {"action": "api_decrypt", "payload": {"data": json.dumps(body), "path": '/app/video/device-base'}})

# 4) 解结果
if state['result']:
    try:
        raw = base64.b64decode(state['result'])
        pt = AES.new(b'qPwClBj7j7ZQraSm', AES.MODE_CBC, b'p3JdVQl3q7WQJIgG').decrypt(raw)
        pt = unpad(pt, 16)
        obj = json.loads(pt)
        data = obj.get('payload', {}).get('data', '')
        print('[*] action=%r code=%s' % (obj.get('action'), obj.get('code')), flush=True)
        print('[*] payload.data(%d): %s' % (len(data), data[:500]), flush=True)
        if data and not data.startswith('i2sHJzS0'):
            open('research/tmp_dec_oracle_out.json', 'w', encoding='utf-8').write(data)
            print('[!!] 疑似解密明文已存 tmp_dec_oracle_out.json', flush=True)
    except Exception as ex:
        print('[*] 结果解码失败 %s' % ex, flush=True)
else:
    print('[*] 无回调结果', flush=True)
