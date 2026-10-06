#!/usr/bin/env python3
"""emu_call2.py - 先 init(config) 再 call(input, callback), 捕获异常消息."""
import base64
import hashlib
import json
import sys

sys.path.insert(0, 'research/toolchain')
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
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
    ct = AES.new(CH_KEY, AES.MODE_CBC, CH_IV).encrypt(pad(plain, 16))
    return base64.b64encode(ct).decode()


def ch_decrypt(b64s: str) -> bytes:
    return AES.new(CH_KEY, AES.MODE_CBC, CH_IV).decrypt(base64.b64decode(b64s))


def gstr(uc, addr, n=256):
    """守卫式读 C 字符串."""
    if not addr:
        return None
    out = bytearray()
    try:
        buf = bytes(uc.mem_read(addr, n))
    except unicorn.unicorn.UcError:
        # 退化为逐 16 字节试读
        for off in range(0, n, 16):
            try:
                buf = bytes(uc.mem_read(addr + off, 16))
            except unicorn.unicorn.UcError:
                break
            out += buf
            if 0 in buf:
                break
        return bytes(out).split(b"\x00")[0] or None
    return buf.split(b"\x00")[0]


class EmuDbg(Emu):
    def _do_stub(self, nm, uc):
        if nm in ("vasprintf", "asprintf"):
            fmt = gstr(uc, uc.reg_read(UC_ARM64_REG_X1))
            print("  [vasprintf] fmt=%r" % fmt)
        elif nm == "android_set_abort_message":
            print("  [abort_msg] %r" % gstr(uc, uc.reg_read(UC_ARM64_REG_X0)))
        elif nm == "syslog":
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            print("  [syslog] pri=%d fmt=%r msg=%r" % (
                uc.reg_read(UC_ARM64_REG_X0) & 0xff, gstr(uc, x1, 64), gstr(uc, x2, 512)))
        return super()._do_stub(nm, uc)


def main():
    body = open('research/captures/one_response_now.txt', encoding='utf-8').read().strip()
    cfg = json.dumps(CONFIG, separators=(',', ':'))
    payload = {"action": "api_decrypt", "payload": {"data": body, "path": "/app/banners/0"}}
    plain = json.dumps(payload, separators=(',', ':'))
    enc_b64 = ch_encrypt(plain.encode())

    e = EmuDbg()
    cfg_p = e.alloc(len(cfg) + 1)
    e.wr(cfg_p, cfg.encode() + b"\x00")
    print("[*] init(config) cfg=%s" % cfg)
    r = e.call(DEV_BASE + INIT_OFF, (cfg_p,), timeout=120_000_000)
    print("[*] init 返回 x0=0x%x" % r)

    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    print("[*] call(input) 输入 len=%d" % len(enc_b64))
    out = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=300_000_000)
    print("[*] call 返回 x0=0x%x" % out)
    if out:
        raw = e.cstr(out, 1 << 22)
        print("[*] 返回串 len=%d head=%r" % (len(raw), raw[:120]))
        try:
            dec = ch_decrypt(raw.decode())
            print("===== 通道解密结果 =====")
            print(dec.decode("utf-8", "replace")[:4000])
        except Exception as ex:
            print("通道解密失败: %s" % ex)


if __name__ == "__main__":
    main()
