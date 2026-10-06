#!/usr/bin/env python3
"""emu_apidecrypt.py - Unicorn 跑 native api_decrypt 处理真实 body, 读返回串."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_LR)
import unicorn
from emu_v11 import Emu, DEV_BASE

CALL_OFF = 0x307a38
INIT_OFF = 0x2fdc24
CH_KEY = b"qPwClBj7j7ZQraSm"
CH_IV = b"p3JdVQl3q7WQJIgG"

CONFIG = {
    "app_id": "4150439554430529",
    "device_id": "cddc4dcf-260d-4684-a8e7-463b2db261e5",
    "code_version": "2020-09-17",
    "app_version": "1.5.8.0",
    "files_path": "/data/user/0/com.tudou.tool/files",
    "tcp": "43.145.33.254:27990",
}


def ch_encrypt(plain: bytes) -> str:
    return base64.b64encode(AES.new(CH_KEY, AES.MODE_CBC, CH_IV).encrypt(pad(plain, 16))).decode()


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


class EmuThrow(Emu):
    throw_seen = False

    def _do_stub(self, nm, uc):
        if nm in ('vasprintf', 'vfprintf', '__vfprintf', 'openlog', 'syslog'):
            regs = [uc.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                             UC_ARM64_REG_X2, UC_ARM64_REG_X3)]
            parts = []
            for i, v in enumerate(regs):
                if v and 0x1000 < v < 0x400100000000:
                    s = gstr(uc, v, 200)
                    if s and 32 <= s[0] < 127:
                        parts.append('x%d=%r' % (i, s[:160]))
            if parts:
                print('  [%s] %s' % (nm, ' '.join(parts)), flush=True)
        if nm == 'android_set_abort_message':
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            msg = gstr(uc, x0, 512)
            print("\n!!! ABORT 消息 ptr=0x%x: %r" % (x0, msg), flush=True)
            if not msg:
                try:
                    print('!!! ptr 区 raw:', bytes(uc.mem_read(x0 & ~0xf, 96)).hex(), flush=True)
                except Exception as ex:
                    print('!!! raw 读失败: %s' % ex, flush=True)
        if nm == '__cxa_throw' and not self.throw_seen:
            self.throw_seen = True
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            lr = uc.reg_read(UC_ARM64_REG_LR)
            tyname = None
            if x1:
                try:
                    p = int.from_bytes(bytes(uc.mem_read(x1 + 8, 8)), 'little')
                    tyname = gstr(uc, p, 128)
                except unicorn.unicorn.UcError:
                    pass
            msg = None
            try:
                raw = bytes(uc.mem_read(x0, 96))
                for off in (8, 16, 24):
                    s = gstr(uc, x0 + off, 256)
                    if s and sum(32 <= c < 127 for c in s) > len(s) * 0.8:
                        msg = s
                        break
                    p = int.from_bytes(raw[off:off + 8], 'little')
                    if 0x400024000000 < p < 0x400030000000:
                        s = gstr(uc, p, 256)
                        if s:
                            msg = s
                            break
            except unicorn.unicorn.UcError:
                pass
            print("\n!!! __cxa_throw type=%r msg=%r lr_off=0x%x" % (tyname, msg, lr - DEV_BASE))
            uc.emu_stop()
            return
        return super()._do_stub(nm, uc)


def main():
    body = sys.argv[1] if len(sys.argv) > 1 else None
    path = sys.argv[2] if len(sys.argv) > 2 else '/app/video/device-base'
    if not body:
        # 取 bodies_now 中该 path 最新一条
        best = None
        for line in open('research/captures/rsa_scan/bodies_now.jsonl',
                         encoding='utf-8', errors='replace'):
            try:
                o = json.loads(line)
            except Exception:
                continue
            if path in o.get('req', ''):
                r = o.get('resp_body_ascii', '')
                if r.count('.') == 1 and len(r) > 400:
                    best = r
        body = best
        if not body:
            sys.exit('未找到 %s 的 body' % path)
    body = body.strip()
    print('body len=%d head=%s...' % (len(body), body[:40]), flush=True)

    cfg = json.dumps(CONFIG, separators=(',', ':'))
    payload = {"action": "api_decrypt", "payload": {"data": body, "path": path}}
    # 10 条噪声
    for i in range(10):
        payload['n%d' % i] = 'N0ISE%02dXYZABCD' % i
    plain = json.dumps(payload, separators=(',', ':'))
    # native 输入协议 = std_b64(明文 JSON), 无通道层 (通道 AES 只用于 TCP)
    enc_b64 = base64.b64encode(plain.encode()).decode()

    e = EmuThrow()

    def on_inline_throw(uc, addr, size, ud):
        if e.throw_seen:
            return
        e.throw_seen = True
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        tyname = msg = None
        try:
            if x1:
                p = int.from_bytes(bytes(uc.mem_read(x1 + 8, 8)), 'little')
                tyname = gstr(uc, p, 128)
            raw = bytes(uc.mem_read(x0, 96))
            for off in (8, 16, 24):
                s = gstr(uc, x0 + off, 256)
                if s and sum(32 <= c < 127 for c in s) > len(s) * 0.8:
                    msg = s
                    break
                p = int.from_bytes(raw[off:off + 8], 'little')
                if 0x400024000000 < p < 0x400030000000:
                    s = gstr(uc, p, 256)
                    if s:
                        msg = s
                        break
        except unicorn.unicorn.UcError:
            pass
        print("\n!!! 内联 throw: type=%r msg=%r lr_off=0x%x obj=0x%x"
              % (tyname, msg, lr - DEV_BASE, x0), flush=True)
        uc.emu_stop()

    e.uc.hook_add(unicorn.UC_HOOK_CODE, on_inline_throw,
                  begin=DEV_BASE + 0x60cc2c, end=DEV_BASE + 0x60cc30)

    cfg_p = e.alloc(len(cfg) + 1)
    e.wr(cfg_p, cfg.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print("[*] init 完成, throw_seen=%s" % e.throw_seen, flush=True)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=600_000_000)
    print("[*] call x0=0x%x throw_seen=%s" % (out, e.throw_seen), flush=True)
    if out > 0x1000 and not e.throw_seen:
        s = gstr(e.uc, out, 8192)
        print("[*] 返回串: %r" % s, flush=True)
        if s and s.startswith(b'{'):
            open('research/captures/rsa_scan/pair2/emu_pt.json', 'wb').write(s)
            print('[!!] 明文已存 pair2/emu_pt.json')
    for l in e.logs[-15:]:
        print("   ", l)


if __name__ == '__main__':
    main()
