#!/usr/bin/env python3
"""emu_schedscan.py - api_decrypt throw 停机瞬间扫 Unicorn 内存中的 AES 调度."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_LR
import unicorn
from emu_v11 import Emu, DEV_BASE, HEAP, HEAP_SIZE, STACK, STACK_SIZE
from scan_aes_sched2 import scan

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24

CONFIG = {
    "app_id": "4150439554430529",
    "device_id": "cddc4dcf-260d-4684-a8e7-463b2db261e5",
    "code_version": "2020-09-17",
    "app_version": "1.5.8.0",
    "files_path": "/data/user/0/com.tudou.tool/files",
    "tcp": "43.145.33.254:27990",
}


def gstr(uc, addr, n=512):
    if not addr or addr < 0x1000:
        return None
    try:
        buf = bytes(uc.mem_read(addr, n))
    except unicorn.unicorn.UcError:
        out = bytearray()
        for off in range(0, n, 16):
            try:
                b = bytes(uc.mem_read(addr + off, 16))
            except unicorn.unicorn.UcError:
                break
            out += b
            if 0 in b:
                break
        return bytes(out).split(b"\x00")[0] or None
    return buf.split(b"\x00")[0]


def main():
    body = None
    path = '/app/video/device-base'
    for line in open('research/captures/rsa_scan/bodies_now.jsonl',
                     encoding='utf-8', errors='replace'):
        try:
            o = json.loads(line)
        except Exception:
            continue
        if path in o.get('req', ''):
            r = o.get('resp_body_ascii', '')
            if r.count('.') == 1 and len(r) > 400:
                body = r.strip()

    payload = {"action": "api_decrypt", "payload": {"data": body, "path": path}}
    for i in range(10):
        payload['n%d' % i] = 'N0ISE%02dXYZABCD' % i
    plain = json.dumps(payload, separators=(',', ':'))
    enc_b64 = base64.b64encode(plain.encode()).decode()

    e = Emu()
    state = {}

    def on_inline_throw(uc, addr, size, ud):
        state['thrown'] = True
        lr = uc.reg_read(UC_ARM64_REG_LR)
        print("\n!!! throw at lr_off=0x%x, 停机扫内存" % (lr - DEV_BASE), flush=True)
        uc.emu_stop()

    e.uc.hook_add(unicorn.UC_HOOK_CODE, on_inline_throw,
                  begin=DEV_BASE + 0x60cc2c, end=DEV_BASE + 0x60cc30)

    cfg = json.dumps(CONFIG, separators=(',', ':'))
    cfg_p = e.alloc(len(cfg) + 1)
    e.wr(cfg_p, cfg.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print("[*] init 完成", flush=True)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    print("[*] call x0=0x%x thrown=%s" % (out, state.get('thrown')), flush=True)

    for label, base, size in (('HEAP', HEAP, HEAP_SIZE), ('STACK', STACK, STACK_SIZE)):
        raw = bytes(e.uc.mem_read(base, size))
        scan(raw, label, maxhits=20)


if __name__ == '__main__':
    main()
