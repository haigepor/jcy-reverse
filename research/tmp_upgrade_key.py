# -*- coding: utf-8 -*-
"""tmp_upgrade_key.py — 试解 /app/upgrade 的 E 密文（无 RSA 层，160B 请求 / 896B 响应）。

块 0 与 iv 无关的标准形式：pt_0 = F_inv(ct_0 ^ C(K)) ^ iv
只需一次 16B 加密定出 C(K)（≈2s/候选），故可快速网格试探。
"""
import base64
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables"))
sys.path.insert(0, os.path.join(ROOT, "src"))

from jcy_protocol.auth import ALPHABET, STD_B64  # noqa: E402
import decrypt_e as D  # noqa: E402

T = str.maketrans(ALPHABET, STD_B64)


def b64(s):
    s = s.strip().translate(T)
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def main():
    rows = [json.loads(l) for l in open(os.path.join(ROOT, "research", "captures",
                                                     "proxy_bodies.jsonl"), encoding="utf-8") if l.strip()]
    up = [d for d in rows if "/app/upgrade" in d.get("req", "")]
    req = b64(up[0]["req_body_ascii"])
    resp = b64(up[0]["resp_body_ascii"])
    print("req=%dB(%d块)  resp=%dB(%d块)" % (len(req), len(req) // 16, len(resp), len(resp) // 16))

    dec = D.EDecryptor()
    keys = {
        "AES_KEY[:16]": b"ziISjqkXPsGUMRNG",
        "AES_KEY[16:]": b"yWigxDGtJbfTdcGv",
        "AES_IV": b"WonrnVkxeIxDcFbv",
        "qPwC": b"qPwClBj7j7ZQraSm",
        "p3Jd": b"p3JdVQl3q7WQJIgG",
        "zero": bytes(16),
    }
    ivs = {"rev": None, "AES_IV": b"WonrnVkxeIxDcFbv", "qPwC": b"qPwClBj7j7ZQraSm",
           "p3Jd": b"p3JdVQl3q7WQJIgG", "zero": bytes(16)}

    for ct_name, ct in (("req", req), ("resp", resp)):
        c0 = ct[:16]
        print("== %s blk0 ct=%s" % (ct_name, c0.hex()))
        for kn, K in keys.items():
            try:
                C, rk, CONST, Cb = dec.calibrate(K, 1)
            except Exception as e:  # noqa: BLE001
                print("   %-14s 标定失败 %r" % (kn, e)); continue
            base0 = D.F_inv(D.xr(c0, C), rk)
            for ivn, iv in ivs.items():
                if iv is None:
                    iv = K[::-1]
                pt = D.xr(base0, iv)
                printable = all(32 <= b < 127 for b in pt)
                mark = "  <== 可打印" if printable else ""
                print("   %-14s iv=%-7s -> %r%s" % (kn, ivn, pt, mark))


if __name__ == "__main__":
    main()
