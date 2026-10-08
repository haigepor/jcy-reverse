# -*- coding: utf-8 -*-
"""resp_p1_probe.py — 响应 P1 (48B, 3块 CBC) 的 key/iv 派生网格。

前提：live_check_resp.txt P0 用 priv_from_go 解出 K16resp=3ME483VJDBQTEHD6。
响应 P1 = 48 字节 → 整块 CBC。穷举 key/iv 派生候选，找 JSON 明文。
"""
import base64
import hashlib
import itertools
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
for p in (os.path.join(ROOT, "src", "tools"), os.path.join(ROOT, "research", "deliverables")):
    if p not in sys.path:
        sys.path.insert(0, p)

from jcy_protocol.auth import custom_b64d  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402

P1 = "G7vGwcdWqj8X6+vDO5Ba9Y9/CKnxvVgOADAUwjzhdY9eDWlexMJGWxVJnczXFlyz"
K16RESP = b"3ME483VJDBQTEHD6"
MON_K = b"qPwClBj7j7ZQraSm"
SIG_K = b"p3JdVQl3q7WQJIgG"

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def std_b64d(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def printable(b):
    if not b:
        return 0.0
    ok = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return ok / len(b)


def main():
    blob_custom = custom_b64d(P1)
    blob_std = std_b64d(P1)
    print(f"[1] P1 len={len(P1)} chars; custom={len(blob_custom)}B std={len(blob_std)}B")
    print(f"    custom hex={blob_custom.hex()}")
    print(f"    std    hex={blob_std.hex()}")

    keys = {
        "K16resp": K16RESP,
        "md5(K16resp)": hashlib.md5(K16RESP).digest(),
        "sha256(K16)[:16]": hashlib.sha256(K16RESP).digest()[:16],
        "sha256(K16)[:16]hex": hashlib.sha256(K16RESP).hexdigest()[:16].encode(),
        "md5hex16(K16)": hashlib.md5(K16RESP).hexdigest()[:16].encode(),
        "MON_K": MON_K,
        "SIG_K": SIG_K,
        "K16resp+K16resp": K16RESP + K16RESP,
        "md5(K16+K16)": hashlib.md5(K16RESP + K16RESP).digest(),
        "sha1(K16)[:16]": hashlib.sha1(K16RESP).digest()[:16],
        "K16resp.lower": K16RESP.lower(),
        "K16resp.upper": K16RESP.upper(),
    }
    ivs = {
        "zero": b"\x00" * 16,
        "K16resp": K16RESP,
        "md5(K16)": hashlib.md5(K16RESP).digest(),
        "sha256(K16)[:16]": hashlib.sha256(K16RESP).digest()[:16],
        "sha256(K16)[:16]hex": hashlib.sha256(K16RESP).hexdigest()[:16].encode(),
        "md5hex16(K16)": hashlib.md5(K16RESP).hexdigest()[:16].encode(),
        "MON_K": MON_K,
        "SIG_K": SIG_K,
        "K16rev": K16RESP[::-1],
        "K16resp*2[:16]": (K16RESP * 2)[:16],
    }

    hits = []
    for blob_name, blob in (("custom", blob_custom), ("std", blob_std)):
        for kn, k in keys.items():
            if len(k) not in (16, 24, 32):
                continue
            # 直接 CBC 整块
            for ivn, iv in ivs.items():
                pt = AES.new(k, AES.MODE_CBC, iv).decrypt(blob)
                p = printable(pt)
                if p > 0.85 or b"code" in pt or b"{" == pt[:1]:
                    hits.append((blob_name, "CBC", kn, ivn, p, pt))
            # blob[:16] 当 IV
            pt = AES.new(k, AES.MODE_CBC, blob[:16]).decrypt(blob[16:])
            p = printable(pt)
            if p > 0.85 or b"code" in pt:
                hits.append((blob_name, "CBC(iv=blk0)", kn, "blk0", p, pt))
            # ECB
            pt = AES.new(k, AES.MODE_ECB).decrypt(blob)
            p = printable(pt)
            if p > 0.85 or b"code" in pt:
                hits.append((blob_name, "ECB", kn, "-", p, pt))
            # CTR 全块
            from Crypto.Util import Counter
            ctr = Counter.new(128, initial_value=int.from_bytes(b"\x00" * 16, "big"))
            pt = AES.new(k, AES.MODE_CTR, counter=ctr).decrypt(blob)
            p = printable(pt)
            if p > 0.85 or b"code" in pt:
                hits.append((blob_name, "CTR0", kn, "zero", p, pt))
            for ivn, iv in ivs.items():
                ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
                pt = AES.new(k, AES.MODE_CTR, counter=ctr).decrypt(blob)
                p = printable(pt)
                if p > 0.85 or b"code" in pt:
                    hits.append((blob_name, "CTR", kn, ivn, p, pt))
            # CFB/OFB
            for ivn, iv in ivs.items():
                pt = AES.new(k, AES.MODE_CFB, iv, segment_size=128).decrypt(blob)
                if printable(pt) > 0.85 or b"code" in pt:
                    hits.append((blob_name, "CFB128", kn, ivn, printable(pt), pt))
                pt = AES.new(k, AES.MODE_OFB, iv).decrypt(blob)
                if printable(pt) > 0.85 or b"code" in pt:
                    hits.append((blob_name, "OFB", kn, ivn, printable(pt), pt))

    print(f"\n[2] 命中 {len(hits)} 条:")
    for h in hits:
        print(f"  {h[0]} {h[1]} key={h[2]} iv={h[3]} printable={h[4]:.2f}")
        print(f"    pt={h[5][:80]!r}")
    if not hits:
        print("  无命中 — key 不在候选内或派生更复杂")


if __name__ == "__main__":
    main()
