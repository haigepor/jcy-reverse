# -*- coding: utf-8 -*-
"""upgrade_static_scan.py — 对 /app/upgrade 明文(无点)请求/响应试静态 key 组合。

候选: ziIS...(32B auth key) / Wonrn...(auth iv) / qPwC... / p3Jd...
模式: CBC / ECB / CTR / CFB, 全组合。
"""
import base64
import json

from Crypto.Cipher import AES
from Crypto.Util import Counter

K32 = b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"
IV16 = b"WonrnVkxeIxDcFbv"
K1 = b"qPwClBj7j7ZQraSm"
K2 = b"p3JdVQl3q7WQJIgG"


def bd(s):
    s = s.strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))


def load_plain_pair(path):
    for line in open(path, "rb"):
        r = json.loads(line)
        rb = r.get("req_body_ascii") or ""
        sb = r.get("resp_body_ascii") or ""
        if "." in rb or "." in sb:
            continue
        return rb, sb
    raise RuntimeError("无 plain 对")


def score(pt):
    return sum(1 for x in pt[:64] if 32 <= x < 127)


def main():
    rb, sb = load_plain_pair("research/captures/rsa_scan/bodies_now.jsonl")
    raw_r = bd(rb)
    raw_s = bd(sb)
    print("len req=%d resp=%d" % (len(raw_r), len(raw_s)))
    keys = [
        (K32, IV16, "ziIS32/Wonrn"),
        (IV16 * 2, IV16, "Wonrnx2/Wonrn"),
        (K32[:16], K32[16:32], "ziISa/ziISb"),
        (K32[16:32], K32[:16], "ziISb/ziISa"),
        (K1, K2, "qPwC/p3Jd"),
        (K2, K1, "p3Jd/qPwC"),
        (K1, K1, "qPwC/qPwC"),
        (K2, K2, "p3Jd/p3Jd"),
        (K1, IV16, "qPwC/Wonrn"),
        (K32, K2, "ziIS32/p3Jd"),
        (K32, K1, "ziIS32/qPwC"),
    ]
    for tag, raw in (("REQ", raw_r), ("RESP", raw_s)):
        for key, iv, kn in keys:
            for mode in ("CBC", "ECB", "CTR", "CFB"):
                try:
                    if mode == "CBC":
                        c = AES.new(key, AES.MODE_CBC, iv)
                    elif mode == "ECB":
                        c = AES.new(key, AES.MODE_ECB)
                    elif mode == "CTR":
                        c = AES.new(key, AES.MODE_CTR, counter=Counter.new(
                            128, initial_value=int.from_bytes(iv, "big")))
                    else:
                        c = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
                    pt = c.decrypt(raw)
                except Exception:
                    continue
                if score(pt) > 40:
                    print(tag, kn, mode, repr(pt[:150]))
    print("scan done")


if __name__ == "__main__":
    main()
