#!/usr/bin/env python3
"""emu_dec_full_enc.py - 决定性实验: 让 api_encrypt 完整走通, 会话提交后 api_decrypt.
手段:
  1) UC_HOOK_MEM_UNMAPPED 自动零页映射 — 放行 0x5a5c0c mem-fault (历史 datakey 路径)
  2) RAND_bytes(0x438d18) 函数跳过: buf<-K16resp, x0=1, PC=LR — 会话 key 定为 K16resp
     (ASCII 可序列化, 避免响应序列化 type_error.316; 且与目标 body 的 P1 密钥一致)
成功判据: dec 回调 payload.data 不再是原样 body 而是 JSON 明文."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import unicorn
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_PC, \
    UC_ARM64_REG_LR
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from emu_keyhook import EmuKey, ch_encrypt, CONFIG, CALL_OFF, INIT_OFF

DEV_BASE = 0x400024a00000
CB_ADDR = 0x62000000
RAND = DEV_BASE + 0x438d18
KSA = DEV_BASE + 0x2cd8b0
PAIR = 0x500028d8

K16RESP = b'HWE2HYC3QRJNEVKS'

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
state = {'result': None, 'rand_n': 0}

faults = []


def on_unmapped(uc, access, address, size, value, ud):
    faults.append((access, address, uc.reg_read(UC_ARM64_REG_PC) - DEV_BASE))
    pg = address & ~0xFFF
    try:
        uc.mem_map(pg, 0x1000, UC_PROT_ALL)
    except Exception:
        pass
    return True


from unicorn.unicorn_const import UC_PROT_ALL


def rand_hook(uc, addr, size, ud):
    buf = uc.reg_read(UC_ARM64_REG_X0)
    num = uc.reg_read(UC_ARM64_REG_X1)
    state['rand_n'] += 1
    if num == 16:
        uc.mem_write(buf, K16RESP)
        uc.reg_write(UC_ARM64_REG_X0, 1)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
        print('[RAND] #1 buf=0x%x 强制 K16resp (函数跳过)' % buf, flush=True)
    else:
        print('[RAND] num=%d buf=0x%x 放行' % (num, buf), flush=True)


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


e.uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
e.uc.hook_add(UC_HOOK_CODE, rand_hook, begin=RAND, end=RAND)
e.uc.hook_add(UC_HOOK_CODE, cb_factory('enc'), begin=DEV_BASE + 0x2cd8b0, end=DEV_BASE + 0x2cd8b0)

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
        return True
    except Exception as ex:
        pc = e.uc.reg_read(UC_ARM64_REG_PC)
        print('[%s] crash %s PC_off=0x%x' % (tag, ex, pc - DEV_BASE), flush=True)
        return False


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
        print('[%s] action=%r code=%s status=%s echo=%s' % (
            tag, obj.get('action'), obj.get('code'), obj.get('payload', {}).get('status'), echo), flush=True)
        print('[%s] data(%d): %s' % (tag, len(data), data[:600]), flush=True)
        if data and not echo:
            open('research/tmp_dec_oracle_out.json', 'w', encoding='utf-8').write(data)
            print('[!!] 疑似解密明文已存 research/tmp_dec_oracle_out.json', flush=True)
    except Exception as ex:
        print('[%s] 结果解码失败 %s' % (tag, ex), flush=True)
    state['result'] = None


# 1) 完整 api_encrypt
do_call('enc', {"action": "api_encrypt", "payload": {
    "data": '{"device_id":"cddc4dcf-260d-4684-a8e7-463b2db261e5","appid":"4150439554430529","version":"1.5.8.0","code_version":"2020-09-17","app_name":"jcymh"}',
    "path": '/app/video/device-base'}})
show_result('enc')
print('[*] RAND 调用次数: %d, mem-fault 映射: %s' % (state['rand_n'], faults[:6]), flush=True)
print('[*] PAIR 当前: %s' % bytes(e.uc.mem_read(PAIR, 32)).hex(), flush=True)

# 2) api_decrypt 目标 body
do_call('dec', {"action": "api_decrypt", "payload": {"data": json.dumps(body), "path": '/app/video/device-base'}})
show_result('dec')
