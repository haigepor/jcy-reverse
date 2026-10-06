#!/usr/bin/env python3
"""emu_keystore_trace.py - 追踪 16 槽 key store (0x68daf0..0x68db80) 的写入与 getter 调用.
跨 init / enc / dec 三阶段. 目标: 找到 setter 触发路径或确认 emu 永不填槽."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_LR, UC_ARM64_REG_X0, \
    UC_ARM64_REG_X1, UC_ARM64_REG_X2
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
from emu_keyhook import EmuKey, ch_encrypt, CONFIG, CALL_OFF, INIT_OFF

DEV_BASE = 0x400024a00000
CB_ADDR = 0x62000000
KS_LO, KS_HI = 0x68daf0, 0x68db80
GETTER = DEV_BASE + 0x404cec
PHASE = ['init']

e = EmuKey()
seen = set()


def kwrite(uc, access, address, size, value, ud):
    off = address - DEV_BASE
    pc = uc.reg_read(UC_ARM64_REG_PC) - DEV_BASE
    key = (off, pc, value)
    if key in seen:
        return
    seen.add(key)
    lr = uc.reg_read(UC_ARM64_REG_LR) - DEV_BASE
    print('[%s] WR +0x%x sz=%d val=0x%x @pc=+0x%x lr=+0x%x' % (
        PHASE[0], off, size, value, pc, lr), flush=True)


def gwrite(uc, access, address, size, value, ud):
    off = address - DEV_BASE
    pc = uc.reg_read(UC_ARM64_REG_PC) - DEV_BASE
    key = (off, pc, value)
    if key in seen:
        return
    seen.add(key)
    print('[%s] FLAG WR +0x%x sz=%d val=0x%x @pc=+0x%x' % (PHASE[0], off, size, value, pc), flush=True)


def getter_cb(uc, addr, size, ud):
    x0 = uc.reg_read(UC_ARM64_REG_X0)
    print('[%s] GETTER idx=%d' % (PHASE[0], x0 & 0xffffffff), flush=True)


cfg = json.dumps(CONFIG, separators=(',', ':'))
cfg_p = e.alloc(len(cfg) + 1)
e.wr(cfg_p, cfg.encode() + b'\x00')

e.uc.hook_add(UC_HOOK_MEM_WRITE, kwrite, begin=DEV_BASE + KS_LO, end=DEV_BASE + KS_HI)
e.uc.hook_add(UC_HOOK_MEM_WRITE, gwrite, begin=DEV_BASE + 0x68db78, end=DEV_BASE + 0x68db80)
e.uc.hook_add(UC_HOOK_CODE, getter_cb, begin=GETTER, end=GETTER)

e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
print('[*] init 完成', flush=True)

PHASE[0] = 'enc'
e.uc.hook_add(UC_HOOK_CODE, lambda uc, a, s, u: None, begin=CB_ADDR, end=CB_ADDR) \
    if False else None
e.uc.mem_map(CB_ADDR, 0x1000)
e.uc.mem_write(CB_ADDR, (0xD65F03C0).to_bytes(4, 'little'))
seen.clear()

PARAMS = '{"device_id":"cddc4dcf-260d-4684-a8e7-463b2db261e5","appid":"4150439554430529"}'
enc = ch_encrypt(json.dumps({"action": "api_encrypt", "payload": {"data": PARAMS, "path": '/app/video/device-base'}},
                            separators=(',', ':')).encode())
inp = e.alloc(len(enc) + 1)
e.wr(inp, enc.encode() + b'\x00')
try:
    e.call(DEV_BASE + CALL_OFF, (inp, CB_ADDR), timeout=600_000_000)
except Exception as ex:
    print('[enc] crash %s' % ex, flush=True)

PHASE[0] = 'dec'
seen.clear()
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
enc = ch_encrypt(json.dumps({"action": "api_decrypt", "payload": {"data": json.dumps(body), "path": '/app/video/device-base'}},
                            separators=(',', ':')).encode())
inp = e.alloc(len(enc) + 1)
e.wr(inp, enc.encode() + b'\x00')
try:
    e.call(DEV_BASE + CALL_OFF, (inp, CB_ADDR), timeout=600_000_000)
except Exception as ex:
    print('[dec] crash %s' % ex, flush=True)

print('[*] 槽数据终态:')
for i in range(16):
    v = int.from_bytes(bytes(e.uc.mem_read(DEV_BASE + 0x68daf0 + i * 8, 8)), 'little')
    if v:
        print('  slot[%d] = 0x%x' % (i, v))
print('[*] flags: 0x68db70=%s 0x68db78=%s 0x68db7c=%s' % (
    bytes(e.uc.mem_read(DEV_BASE + 0x68db70, 8)).hex(),
    bytes(e.uc.mem_read(DEV_BASE + 0x68db78, 4)).hex(),
    bytes(e.uc.mem_read(DEV_BASE + 0x68db7c, 4)).hex()))
