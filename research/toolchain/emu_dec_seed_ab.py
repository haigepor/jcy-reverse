#!/usr/bin/env python3
"""emu_dec_seed_ab.py - 变体 a/b: 种子 0x50003b40 与 PAIR 布局 [KEY][IV], 带读取探针.
探针: dec 期间若 PAIR/0x50003b40 被读, 记录 pc — 判定 decrypt 是否真的看这些地址."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import unicorn
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_PC
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_MEM_READ
from emu_keyhook import EmuKey, ch_encrypt, CONFIG, CALL_OFF, INIT_OFF

DEV_BASE = 0x400024a00000
CB_ADDR = 0x62000000
PAIR = 0x500028d8            # [IV 16B][KEY 16B]
SPOT3 = 0x50003b40           # 第三 RAND 落点
KSA = DEV_BASE + 0x2cd8b0

K16RESP = b'HWE2HYC3QRJNEVKS'
IV16 = K16RESP[::-1]

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
state = {'result': None}
reads = {'a': {}, 'b': {}}
phase = ['enc']


def cb_factory(tag):
    def cb(uc, addr, size, ud):
        off = addr - DEV_BASE
        if off == 0x2cd8b0:
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            try:
                k = bytes(uc.mem_read(x1, 16))
            except Exception:
                k = b'?'
            print('[%s][KSA] key=%r' % (tag, k), flush=True)
    return cb


def cb_hook(uc, addr, size, ud):
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    try:
        raw = bytes(uc.mem_read(x0, 16384)).split(b'\x00')[0]
        state['result'] = raw
        print('[CB] 结果 %dB: %s...' % (len(raw), raw[:60]), flush=True)
    except Exception as ex:
        print('[CB] 读取失败 %s' % ex, flush=True)


def wp(uc, access, address, size, value, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    ent = reads[phase[0]].setdefault(address, [0, pc])
    ent[0] += 1


e.uc.hook_add(UC_HOOK_CODE, cb_factory('enc'), begin=DEV_BASE + 0x2cd8b0, end=DEV_BASE + 0x2cd8b0)
e.uc.hook_add(UC_HOOK_MEM_READ, wp, begin=PAIR, end=PAIR + 0x20)
e.uc.hook_add(UC_HOOK_MEM_READ, wp, begin=SPOT3, end=SPOT3 + 0x10)

cfg = json.dumps(CONFIG, separators=(',', ':'))
cfg_p = e.alloc(len(cfg) + 1)
e.wr(cfg_p, cfg.encode() + b'\x00')
e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
print('[*] init 完成', flush=True)

e.uc.hook_add(UC_HOOK_CODE, cb_hook, begin=CB_ADDR, end=CB_ADDR)
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
        pc = e.uc.reg_read(UC_ARM64_REG_PC)
        print('[%s] crash %s PC_off=0x%x' % (tag, ex, pc - DEV_BASE), flush=True)


def show_result(tag):
    if not state['result']:
        print('[%s] 无回调结果' % tag, flush=True)
        return
    try:
        raw = base64.b64decode(state['result'])
        pt = AES.new(b'qPwClBj7j7ZQraSm', AES.MODE_CBC, b'p3JdVQl3q7WQJIgG').decrypt(raw)
        pt = unpad(pt, 16)
        obj = json.loads(pt)
        data = obj.get('payload', {}).get('data', '')
        echo = data.startswith('"i2sHJzS0')
        print('[%s] action=%r code=%s echo=%s data[:80]=%s' % (
            tag, obj.get('action'), obj.get('code'), echo, data[:80]), flush=True)
    except Exception as ex:
        print('[%s] 结果解码失败 %s' % (tag, ex), flush=True)
    state['result'] = None


# enc: 预期崩 0x5a5c0c (RAND 之前), 无所谓 — 本实验只测 dec 对种子地址的读取
phase[0] = 'enc'
do_call('enc', {"action": "api_encrypt", "payload": {"data": '{"device_id":"cddc4dcf-260d-4684-a8e7-463b2db261e5"}', "path": '/app/video/device-base'}})

# ---- 变体 a: PAIR=[IV][KEY] + SPOT3=K16resp ----
phase[0] = 'a'
e.wr(PAIR, IV16 + K16RESP)
e.wr(SPOT3, K16RESP)
print('[a] PAIR=[IV][KEY], SPOT3=K16resp', flush=True)
do_call('a', {"action": "api_decrypt", "payload": {"data": json.dumps(body), "path": '/app/video/device-base'}})
show_result('a')

# ---- 变体 b: PAIR=[KEY][IV] (SPOT3 保持) ----
phase[0] = 'b'
e.wr(PAIR, K16RESP + IV16)
print('[b] PAIR=[KEY][IV]', flush=True)
do_call('b', {"action": "api_decrypt", "payload": {"data": json.dumps(body), "path": '/app/video/device-base'}})
show_result('b')

for ph in ('a', 'b'):
    print('[*] 变体 %s dec 期间探针地址读取: %s' % (ph, reads[ph] if reads[ph] else '无 — 两个种子地址均未被读'), flush=True)
