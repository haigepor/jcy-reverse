#!/usr/bin/env python3
"""emu_dec_branch.py - 捕获 api_decrypt 在 parse→build 窗口内的 .data/.bss 读取, 定位 store."""
import json
import sys

sys.path.insert(0, 'research/toolchain')
import unicorn
from unicorn.arm64_const import UC_ARM64_REG_PC
from unicorn.unicorn_const import UC_HOOK_MEM_READ, UC_HOOK_CODE
from emu_keyhook import EmuKey, ch_encrypt, CONFIG, CALL_OFF, INIT_OFF

DEV_BASE = 0x400024a00000
IMG_DATA_LO = DEV_BASE + 0x660000
IMG_DATA_HI = DEV_BASE + 0x6F0000
PARSE_RET = DEV_BASE + 0x309568
BUILD = DEV_BASE + 0x30cba4
DISPATCH_LO = DEV_BASE + 0x2f0000
DISPATCH_HI = DEV_BASE + 0x320000
CB_ADDR = 0x62000000

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
reads = {}        # addr -> [count, first_pc]
window = [False]


def mem_read(uc, access, address, size, value, ud):
    if not window[0]:
        return
    pc = uc.reg_read(UC_ARM64_REG_PC)
    if not (DISPATCH_LO <= pc < DISPATCH_HI):
        return
    for k in range(size):
        a = address + k
        if IMG_DATA_LO <= a < IMG_DATA_HI:
            ent = reads.get(a)
            if ent is None:
                reads[a] = [1, pc]
            else:
                ent[0] += 1


def code_cb(uc, addr, size, ud):
    if addr == PARSE_RET:
        window[0] = True
        print('[*] 窗口开 (parse 返回)', flush=True)
    elif addr == BUILD:
        window[0] = False
        print('[*] 窗口关 (响应构建)', flush=True)


cfg = json.dumps(CONFIG, separators=(',', ':'))
cfg_p = e.alloc(len(cfg) + 1)
e.wr(cfg_p, cfg.encode() + b'\x00')
e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
print('[*] init 完成', flush=True)

e.uc.hook_add(UC_HOOK_CODE, code_cb, begin=PARSE_RET, end=PARSE_RET)
e.uc.hook_add(UC_HOOK_CODE, code_cb, begin=BUILD, end=BUILD)
e.uc.hook_add(UC_HOOK_MEM_READ, mem_read)

env = {"action": "api_decrypt", "payload": {"data": json.dumps(body), "path": '/app/video/device-base'}}
enc = ch_encrypt(json.dumps(env, separators=(',', ':')).encode())
inp = e.alloc(len(enc) + 1)
e.wr(inp, enc.encode() + b'\x00')

e.uc.mem_map(CB_ADDR, 0x1000)
e.uc.mem_write(CB_ADDR, (0xD65F03C0).to_bytes(4, 'little'))

try:
    out = e.call(DEV_BASE + CALL_OFF, (inp, CB_ADDR), timeout=600_000_000)
    print('[*] call x0=0x%x' % out, flush=True)
except Exception as ex:
    print('[!!] %s' % ex, flush=True)

print('[*] 窗口内 .data/.bss 读取地址数: %d' % len(reads), flush=True)
items = sorted(reads.items(), key=lambda kv: -kv[1][0])[:80]
for a, (cnt, pc) in items:
    try:
        raw = bytes(e.uc.mem_read(a, 24))
    except Exception:
        raw = b'?'
    print('  @0x%x (img+0x%x) cnt=%d pc=img+0x%x val=%s' % (
        a, a - DEV_BASE, cnt, pc - DEV_BASE, raw.hex()), flush=True)
