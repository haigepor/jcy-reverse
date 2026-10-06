# -*- coding: utf-8 -*-
# hash_hypo.py — 用语料检验 O 是否等于标准哈希/HMAC
import json, hashlib, hmac, itertools, os

HERE = os.path.dirname(os.path.abspath(__file__))
CORP = os.path.join(HERE, "..", "v9", "brute", "O_true_corpus.json")
D = json.load(open(CORP, encoding="utf-8"))
norm = [r for r in D if r["family"] == "normal"]
print("norm entries:", len(norm))

MAGIC = bytes.fromhex("23754ae9d0cbe749f5441e769b4514")
B15 = bytes([62])
DEVHASH = "16613a7076284a15bc723d018bcd67e1"
CODEC = "3.0.0.8"
APPV = "1.5.8.0"
APPID = "default"

KEYS = {
    "magic15": MAGIC,
    "magic16": MAGIC + B15,
    "magic_hex": b"23754ae9d0cbe749f5441e769b4514",
    "ziIS": b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv",
    "Wonrn": b"WonrnVkxeIxDcFbv",
    "qPwC": b"qPwClBj7j7ZQraSm",
    "p3Jd": b"p3JdVQl3q7WQJIgG",
    "EeAV": b"Ee&AVzdgru^$hX%j",
    "M0Ky": b"M0KylhhHyj1HZ&Mi",
    "empty": b"",
    "ziIS+Wonrn": b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGvWonrnVkxeIxDcFbv",
}

HASHES = {
    "md5": lambda b: hashlib.md5(b).digest(),
    "sha1": lambda b: hashlib.sha1(b).digest(),
    "sha256": lambda b: hashlib.sha256(b).digest(),
    "sha512": lambda b: hashlib.sha512(b).digest(),
    "sha384": lambda b: hashlib.sha384(b).digest(),
    "sha3_256": lambda b: hashlib.sha3_256(b).digest(),
    "sha3_512": lambda b: hashlib.sha3_512(b).digest(),
    "blake2b32": lambda b: hashlib.blake2b(b, digest_size=32).digest(),
    "blake2b64": lambda b: hashlib.blake2b(b, digest_size=64).digest(),
    "blake2s": lambda b: hashlib.blake2s(b).digest(),
}


def msgs(ts):
    t = str(ts)
    S = "%s-%s-Android-%s-%s-%s" % (CODEC, t, APPV, DEVHASH, APPID)
    out = {
        "S": S.encode(),
        "ts": t.encode(),
        "ts_nonce": None,
    }
    return out


target = norm[0]
ts = target["ts"]
O = bytes.fromhex(target["O"])
print("ts", ts, "O[:32]", O[:32].hex())

hits = []
for mn, msg in msgs(ts).items():
    if msg is None:
        continue
    for hn, hf in HASHES.items():
        d = hf(msg)
        if O.startswith(d[:32]) or d[:32] == O[:32]:
            hits.append(("plain", hn, mn))
        for kn, kv in KEYS.items():
            for combo, cb in (("k+m", kv + msg), ("m+k", msg + kv)):
                d = hf(cb)
                if d[:32] == O[:32]:
                    hits.append((combo, hn, mn, kn))
        for kn, kv in KEYS.items():
            for hmn, hmf in (("hmac_sha256", hashlib.sha256), ("hmac_sha512", hashlib.sha512),
                             ("hmac_sha1", hashlib.sha1), ("hmac_md5", hashlib.md5)):
                d = hmac.new(kv, msg, hmf).digest()
                if d[:32] == O[:32]:
                    hits.append((hmn, kn, mn))
print("hits:", hits[:20])

# 检查 O[0:32] 与 O[32:64] 的关系
print("O[32:64]", O[32:64].hex())
for hn, hf in HASHES.items():
    if hf(O[:32])[:32] == O[32:64]:
        print("O[32:64] == %s(O[:32])" % hn)
    if hf(O[32:64])[:32] == O[:32]:
        print("O[0:32] == %s(O[32:64])" % hn)
# 检查 64B 确定性块是否可能是 sha512(S)
for mn, msg in msgs(ts).items():
    if msg is None:
        continue
    for hn, hf in HASHES.items():
        d = hf(msg)
        if d[:64] == O[:64]:
            print("O[:64] == %s(%s)" % (hn, mn))
# 全量语料一致性: 检验 O[:64] 只依赖 ts
import collections
g = collections.defaultdict(set)
for r in norm:
    g[r["ts"]].add(r["O"][:128])
bad = [(k, len(v)) for k, v in g.items() if len(v) > 1]
print("ts with inconsistent O[:64]:", len(bad), bad[:5])
