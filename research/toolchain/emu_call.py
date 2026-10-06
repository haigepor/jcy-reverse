# -*- coding: utf-8 -*-
"""emu_call.py — 用 Unicorn 跑 libcore.so 的 call() 分发器 (api_decrypt).

用法:
    python emu_call.py "<P0_b64>.<P1_b64>" [/app/banners/0]
    python emu_call.py --test            # 自测: 通道编解码往返
"""
import base64
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from emu_v11 import Emu, DEV_BASE

CALL_OFF = 0x307a38          # libcore.so!call
INIT_OFF = 0x2fdc24          # libcore.so!init

CH_KEY = b"qPwClBj7j7ZQraSm"
CH_IV = b"p3JdVQl3q7WQJIgG"


def ch_encrypt(plain: bytes) -> str:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    ct = AES.new(CH_KEY, AES.MODE_CBC, CH_IV).encrypt(pad(plain, 16))
    return base64.b64encode(ct).decode()


def ch_decrypt(b64text: str) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    ct = base64.b64decode(b64text)
    return unpad(AES.new(CH_KEY, AES.MODE_CBC, CH_IV).decrypt(ct), 16)


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--test":
        msg = json.dumps({"action": "api_decrypt", "payload": {"data": "AA.BB"}}).encode()
        print(ch_decrypt(ch_encrypt(msg)).decode())
        return

    body = sys.argv[1]
    path = sys.argv[2] if len(sys.argv) > 2 else "/app/banners/0"
    payload = {"action": "api_decrypt", "payload": {"data": body, "path": path}}
    plain = json.dumps(payload, separators=(",", ":"))
    print("[*] 明文 action JSON: %s" % plain[:120])
    enc_b64 = ch_encrypt(plain.encode())
    print("[*] 通道加密 b64 len=%d" % len(enc_b64))

    e = Emu()
    inp = e.alloc(len(enc_b64) + 1)
    e.wr(inp, enc_b64.encode() + b"\x00")
    out_ptr = e.call(DEV_BASE + CALL_OFF, (inp, 0), timeout=300_000_000)
    print("[*] call 返回 x0 = 0x%x" % out_ptr)
    if out_ptr:
        raw = e.cstr(out_ptr, 1 << 22)
        print("[*] 返回串 len=%d head=%r" % (len(raw), raw[:80]))
        try:
            dec = ch_decrypt(raw.decode())
            print("===== 解密结果 =====")
            print(dec.decode("utf-8", "replace")[:4000])
        except Exception as ex:
            print("通道解密失败: %s" % ex)


if __name__ == "__main__":
    main()
