#!/usr/bin/env python3
"""emu_call3.py - init + call, 在 __cxa_throw 处停机抓异常类型/消息/抛出点."""
import base64
import json
import sys

sys.path.insert(0, 'research/toolchain')
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_LR
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


def gstr(uc, addr, n=256):
    if not addr:
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
        if nm == "__cxa_throw" and not self.throw_seen:
            self.throw_seen = True
            x0 = uc.reg_read(UC_ARM64_REG_X0)   # exception object
            x1 = uc.reg_read(UC_ARM64_REG_X1)   # type_info*
            lr = uc.reg_read(UC_ARM64_REG_LR)
            tyname = None
            if x1:
                p = int.from_bytes(bytes(uc.mem_read(x1 + 8, 8)), 'little')
                tyname = gstr(uc, p, 128)
            print("\n!!! __cxa_throw: type=%r obj=0x%x lr=0x%x (libcore off 0x%x)" % (tyname, x0, lr, lr - DEV_BASE))
            try:
                raw = bytes(uc.mem_read(x0, 96))
                print("!!! obj dump:", raw.hex())
                for off in (8, 16, 24):
                    s = gstr(uc, x0 + off, 128)
                    if s and sum(32 <= c < 127 for c in s) > len(s) * 0.8:
                        print("!!! obj+%d 字符串: %r" % (off, s))
                    p = int.from_bytes(raw[off:off + 8], 'little')
                    if 0x400024000000 < p < 0x400030000000:
                        s = gstr(uc, p, 256)
                        if s:
                            print("!!! obj+%d -> ptr 字符串: %r" % (off, s))
            except unicorn.unicorn.UcError as ex:
                print("!!! obj 读取失败: %s" % ex)
            uc.emu_stop()
            return
        return super()._do_stub(nm, uc)


def main():
    body = open('research/captures/one_response_now.txt', encoding='utf-8').read().strip()
    cfg = json.dumps(CONFIG, separators=(',', ':'))
    payload = {"action": "api_decrypt", "payload": {"data": body, "path": "/app/banners/0"}}
    plain = json.dumps(payload, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = EmuThrow()
    cfg_p = e.alloc(len(cfg) + 1)
    e.wr(cfg_p, cfg.encode() + b"\x00")
    e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print("[*] init 完成, throw_seen=%s" % e.throw_seen)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=300_000_000)
    print("[*] call 返回 x0=0x%x, throw_seen=%s" % (out, e.throw_seen))
    print("[*] 最近桩日志:")
    for l in e.logs[-25:]:
        print("   ", l)


if __name__ == "__main__":
    main()
