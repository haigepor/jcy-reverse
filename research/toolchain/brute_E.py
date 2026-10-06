# -*- coding: utf-8 -*-
# brute_E.py — 用已知 (输入,输出) 对爆破 E 的算法
import base64, itertools, hashlib
from Crypto.Cipher import AES

ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
FWD = str.maketrans(STD, ALPHA)
S = "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
A1 = base64.b64encode(S.encode()).decode().translate(FWD).encode()
OUT = bytes.fromhex("23754ae9d0cbe749f5441e769b45143e"
                    "2b3ef9d5b6c78fd91e33fb5136486918"
                    "f70e50af61d497be95acdd0fd7ffae85"
                    "c5d33b3dfcc0702635ae5565fa98a5ed"
                    "c390790538d8262e8d01182c01292be0"
                    "b4f1260c528929f81df179d0eb6fc929"
                    "cc4077a891b446e45a55fa7ccf268594")
A2 = b"A" * 104
OUT2 = bytes.fromhex("2dbf07f1db23e031496b629f76af6558"
                     "34200590d59ac270aa5f0c7630721f25"
                     "179fd951601717f88ba731dc994e2f68"
                     "5c7cb9f97fe7544949589340fd5466d9"
                     "99cf3bdee51c5b84e045209c4da37b06"
                     "430e5d07f1fb179f41f04ad300a87ca8"
                     "f55ae08d7b4c0155f92615862760c9f5")

KEYSTR = b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"
IVSTR = b"WonrnVkxeIxDcFbv"

KEYC = [KEYSTR, KEYSTR[:16], KEYSTR[16:], IVSTR, IVSTR + b"\0" * 16,
        hashlib.md5(KEYSTR).digest(), hashlib.sha256(KEYSTR).digest(),
        hashlib.sha256(KEYSTR).digest()[:16], hashlib.md5(IVSTR).digest(),
        b"\0" * 16, b"\0" * 32]
IVC = [IVSTR, b"\0" * 16, KEYSTR[:16], KEYSTR[16:], hashlib.md5(IVSTR).digest(),
       hashlib.sha256(IVSTR).digest()[:16], b"\x01" * 16]

def pad16(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n

PT = {
    "A1+pkcs7": pad16(A1),
    "A1+zero8": A1 + b"\0" * 8,
    "A1+space8": A1 + b" " * 8,
    "S+pad": pad16(S.encode()),
    "b64dec(A1)+pad": pad16(base64.b64decode(A1.decode().translate(str.maketrans(ALPHA, STD)))),
    "A1+0x08x8": A1 + b"\x08" * 8,
}
PT2 = {
    "A1+pkcs7": pad16(A2),
    "A1+zero8": A2 + b"\0" * 8,
    "A1+0x08x8": A2 + b"\x08" * 8,
}

MODES = [("CBC", AES.MODE_CBC), ("ECB", AES.MODE_ECB), ("CFB", AES.MODE_CFB),
         ("OFB", AES.MODE_OFB), ("CTR", AES.MODE_CTR), ("CFB8", AES.MODE_CFB),
         ("OPENPGP", AES.MODE_OPENPGP)]

hits = 0
for kn, k in enumerate(KEYC):
    for mn, mode in MODES:
        for ivn, iv in enumerate(IVC):
            for pn, p in PT.items():
                for direction in ("enc", "dec"):
                    try:
                        if mode in (AES.MODE_ECB,):
                            c = AES.new(k, mode)
                        elif mode == AES.MODE_CTR:
                            c = AES.new(k, mode, nonce=b"", initial_value=int.from_bytes(iv, "big"))
                        else:
                            c = AES.new(k, mode, iv=iv)
                        r = c.encrypt(p) if direction == "enc" else c.decrypt(p)
                    except Exception:
                        continue
                    if r == OUT:
                        print("*** HIT base: key#%d(%d) %s iv#%d %s pt=%s dir=%s" % (kn, len(k), mn, ivn, pn, direction))
                        hits += 1
                    if len(r) >= 16 and r[:16] == OUT[:16]:
                        print("    prefix16-hit: key#%d(%d) %s iv#%d %s pt=%s dir=%s" % (kn, len(k), mn, ivn, pn, direction))
print("hits:", hits)

# 也试试"输出即明文"方向: 是否有 E 使得 out = AES.decrypt(...)
print("--- 反向: OUT 解密后是否是 A1 ---")
for kn, k in enumerate(KEYC):
    for ivn, iv in enumerate(IVC):
        for mode, mname in ((AES.MODE_CBC, "CBC"), (AES.MODE_ECB, "ECB")):
            try:
                c = AES.new(k, mode) if mode == AES.MODE_ECB else AES.new(k, mode, iv=iv)
                d = c.decrypt(OUT)
            except Exception:
                continue
            if d[:len(A1)] == A1 or A1 in d:
                print("*** A1 出现在解密结果 key#%d %s iv#%d: %s" % (kn, mname, ivn, d.hex()))
print("done")
