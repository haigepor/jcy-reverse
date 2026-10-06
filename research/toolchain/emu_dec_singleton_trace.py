#!/usr/bin/env python3
"""emu_dec_singleton_trace.py - 谁在读 0x68dad8/0x68db50 单例? 记录 pc/LR/FP 链/寄存器."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

import unicorn
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_FP, \
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_MEM_READ
from emu_keyhook import EmuKey, ch_encrypt, CONFIG, CALL_OFF, INIT_OFF

DEV_BASE = 0x400024a00000
CB_ADDR = 0x62000000
WATCH = (0x68dad8, 0x68db50)
PHASE = ['init']

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
seen = set()


def fpchain(uc, depth=6):
    out = []
    fp = uc.reg_read(UC_ARM64_REG_FP)
    for _ in range(depth):
        try:
            lr = int.from_bytes(bytes(uc.mem_read(fp + 8, 8)), 'little')
            fpv = int.from_bytes(bytes(uc.mem_read(fp, 8)), 'little')
            if not (DEV_BASE <= lr < DEV_BASE + 0x800000):
                break
            out.append('0x%x' % (lr - DEV_BASE))
            fp = fpv
        except Exception:
            break
    return '<-'.join(out)


def wread(uc, access, address, size, value, ud):
    off = address - DEV_BASE
    if off not in WATCH:
        return
    key = (off, uc.reg_read(UC_ARM64_REG_PC))
    if key in seen:
        return
    seen.add(key)
    pc = uc.reg_read(UC_ARM64_REG_PC) - DEV_BASE
    lr = uc.reg_read(UC_ARM64_REG_LR) - DEV_BASE
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    x1 = uc.reg_read(UC_ARM64_REG_X1)
    print('[%s] 读 +0x%x @pc=+0x%x lr=+0x%x x0=0x%x x1=0x%x fp链=%s' % (
        PHASE[0], off, pc, lr, x0, x1, fpchain(uc)), flush=True)


def cb_hook(uc, addr, size, ud):
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    try:
        raw = bytes(uc.mem_read(x0, 16384)).split(b'\x00')[0]
        print('[CB] 结果 %dB: %s...' % (len(raw), raw[:60]), flush=True)
    except Exception as ex:
        print('[CB] fail %s' % ex, flush=True)


cfg = json.dumps(CONFIG, separators=(',', ':'))
cfg_p = e.alloc(len(cfg) + 1)
e.wr(cfg_p, cfg.encode() + b'\x00')
e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
print('[*] init 完成, 单例值: dad8=%s db50=%s' % (
    bytes(e.uc.mem_read(DEV_BASE + 0x68dad8, 8)).hex(),
    bytes(e.uc.mem_read(DEV_BASE + 0x68db50, 8)).hex()), flush=True)

PHASE[0] = 'dec'
e.uc.hook_add(UC_HOOK_MEM_READ, wread, begin=DEV_BASE + 0x68dad8, end=DEV_BASE + 0x68dad8)
e.uc.hook_add(UC_HOOK_MEM_READ, wread, begin=DEV_BASE + 0x68db50, end=DEV_BASE + 0x68db50)
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

print('[*] 结束时单例值: dad8=%s db50=%s' % (
    bytes(e.uc.mem_read(DEV_BASE + 0x68dad8, 8)).hex(),
    bytes(e.uc.mem_read(DEV_BASE + 0x68db50, 8)).hex()), flush=True)
