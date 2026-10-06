#!/usr/bin/env python3
"""emu_dec_globals_trace.py - 全调用期间 .data/.bss(0x660000-0x6F0000) 读取追踪.
输出每个被读全局: 首次读取 pc_off、次数、当时值(16B). 找 emu 中为 0 的 store 根候选."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import unicorn
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_MEM_READ
from emu_keyhook import EmuKey, ch_encrypt, CONFIG, CALL_OFF, INIT_OFF

DEV_BASE = 0x400024a00000
CB_ADDR = 0x62000000
G_LO, G_HI = 0x660000, 0x6F0000

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
state = {'result': None}
reads = {}


def gread(uc, access, address, size, value, ud):
    off = address - DEV_BASE
    if not (G_LO <= off < G_HI):
        return
    pc = uc.reg_read(UC_ARM64_REG_PC) - DEV_BASE
    ent = reads.get(off)
    if ent is None:
        try:
            v = bytes(uc.mem_read(address, 16))
        except Exception:
            v = b'?'
        reads[off] = [1, pc, v]
    else:
        ent[0] += 1


def cb_hook(uc, addr, size, ud):
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    try:
        raw = bytes(uc.mem_read(x0, 16384)).split(b'\x00')[0]
        state['result'] = raw
        print('[CB] 结果 %dB' % len(raw), flush=True)
    except Exception as ex:
        print('[CB] 读取失败 %s' % ex, flush=True)


cfg = json.dumps(CONFIG, separators=(',', ':'))
cfg_p = e.alloc(len(cfg) + 1)
e.wr(cfg_p, cfg.encode() + b'\x00')
e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
print('[*] init 完成', flush=True)

e.uc.hook_add(UC_HOOK_MEM_READ, gread)
e.uc.hook_add(UC_HOOK_CODE, cb_hook, begin=CB_ADDR, end=CB_ADDR)
e.uc.mem_map(CB_ADDR, 0x1000)
e.uc.mem_write(CB_ADDR, (0xD65F03C0).to_bytes(4, 'little'))

env = {"action": "api_decrypt", "payload": {"data": json.dumps(body), "path": '/app/video/device-base'}}
enc = ch_encrypt(json.dumps(env, separators=(',', ':')).encode())
inp = e.alloc(len(enc) + 1)
e.wr(inp, enc.encode() + b'\x00')
try:
    out = e.call(DEV_BASE + CALL_OFF, (inp, CB_ADDR), timeout=600_000_000)
    print('[*] call x0=0x%x' % out, flush=True)
except Exception as ex:
    pc = e.uc.reg_read(UC_ARM64_REG_PC)
    print('[!!] crash %s PC_off=0x%x' % (ex, pc - DEV_BASE), flush=True)

print('[*] 被读全局地址数: %d' % len(reads), flush=True)
rows = sorted(reads.items(), key=lambda kv: (kv[1][2] == b'\x00' * 16 and 0 or 1, -kv[1][0]))
zero_rows = [(a, v) for a, v in reads.items() if v[2] == b'\x00' * 16]
print('[*] 其中值全 0 的: %d 个' % len(zero_rows), flush=True)
print('--- 值非 0 的 top40 (按次数) ---')
nz = sorted([kv for kv in reads.items() if kv[1][2] != b'\x00' * 16], key=lambda kv: -kv[1][0])[:40]
for a, (cnt, pc, v) in nz:
    print('  +0x%x cnt=%d pc=+0x%x val=%s' % (a, cnt, pc, v.hex()))
print('--- 值全 0 的 top40 (按 pc 排序, 候选 store 根) ---')
zr = sorted(zero_rows, key=lambda kv: kv[1][1])[:40]
for a, (cnt, pc, v) in zr:
    print('  +0x%x cnt=%d first_pc=+0x%x val=0' % (a, cnt, pc))
