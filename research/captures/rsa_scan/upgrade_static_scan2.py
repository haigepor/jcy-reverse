# -*- coding: utf-8 -*-
"""upgrade_static_scan2.py — upgrade 请求/响应全对称假设扫描。

维度: 字母表(std/custom) × key 候选 × {CBC静态iv, CBC内嵌iv前缀, ECB, CTR, CFB}
     × {AES, SM4}。
"""
import base64
import json

from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALPHA = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

K32 = b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"
IV16 = b"WonrnVkxeIxDcFbv"
K1 = b"qPwClBj7j7ZQraSm"
K2 = b"p3JdVQl3q7WQJIgG"
KE = b"Ee&AVzdgru^$hX%j"
KM = b"M0KylhhHyj1HZ&Mi"

KEYS16 = [IV16, K1, K2, KE, KM, K32[:16], K32[16:32]]
KEYS = [(k, k) for k in KEYS16] + \
       [(k, v) for k in KEYS16 for v in KEYS16 if k is not v] + \
       [(K32, IV16), (K32[:16] + K32[16:32], IV16)]


def bd(s, custom):
    s = s.strip()
    if custom:
        s = s.translate(str.maketrans(ALPHA, STD))
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
    return sum(1 for x in pt[:48] if 32 <= x < 127)


def try_ciphers(key, iv, raw):
    """产出 (标签, 明文)。"""
    out = []
    if len(key) == 32:
        out.append(("AES-CBC", AES.new(key, AES.MODE_CBC, iv).decrypt(raw)))
        out.append(("AES-ECB", AES.new(key, AES.MODE_ECB).decrypt(raw)))
        out.append(("AES-CBC/emb", AES.new(key, AES.MODE_CBC, raw[:16]).decrypt(raw[16:])))
        out.append(("AES-CTR", AES.new(key, AES.MODE_CTR, counter=Counter.new(
            128, initial_value=int.from_bytes(iv, "big"))).decrypt(raw)))
        out.append(("AES-CFB", AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(raw)))
    else:
        for name, mk in (("AES", False), ("SM4", True)):
            try:
                if not mk:
                    c = Cipher(algorithms.AES(key), modes.CBC(iv))
                else:
                    c = Cipher(algorithms.SM4(key), modes.CBC(iv))
                d = c.decryptor()
                out.append(("%s-CBC" % name, d.update(raw) + d.finalize()))
                d = (Cipher(algorithms.AES(key), modes.ECB()) if not mk
                     else Cipher(algorithms.SM4(key), modes.ECB())).decryptor()
                out.append(("%s-ECB" % name, d.update(raw) + d.finalize()))
                d = (Cipher(algorithms.AES(key), modes.CBC(raw[:16])) if not mk
                     else Cipher(algorithms.SM4(key), modes.CBC(raw[:16]))).decryptor()
                out.append(("%s-CBC/emb" % name, d.update(raw[16:]) + d.finalize()))
                d = (Cipher(algorithms.AES(key), modes.CFB(iv)) if not mk
                     else Cipher(algorithms.SM4(key), modes.CFB(iv))).decryptor()
                out.append(("%s-CFB" % name, d.update(raw) + d.finalize()))
            except Exception:
                continue
    return out


def main():
    rb, sb = load_plain_pair("research/captures/rsa_scan/bodies_now.jsonl")
    hits = 0
    for custom in (False, True):
        raw_r = bd(rb, custom)
        raw_s = bd(sb, custom)
        for tag, raw in (("REQ", raw_r), ("RESP", raw_s)):
            for key, iv in KEYS:
                if len(key) not in (16, 32) or len(iv) != 16:
                    continue
                for name, pt in try_ciphers(key, iv, raw):
                    if score(pt) > 36:
                        print("HIT custom=%s %s key=%s iv=%s: %r"
                              % (custom, name, key[:8], iv[:8], pt[:120]))
                        hits += 1
    print("hits:", hits)


if __name__ == "__main__":
    main()
