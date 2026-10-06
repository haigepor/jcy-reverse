# -*- coding: utf-8 -*-
"""try_custom_aes.py — 验证假设：E = AES 结构 + 自定义 S 盒（RC4 式 KSA 生成）

已知事实:
  * E 是 CBC，16 字节分组
  * 代码里存在 AES 的 xtime(0x1b) 与 GF(2^8) 乘法累加（MixColumns）
  * 0x2cd8b0 = 以 AES S-box 为初值、用 key 做 RC4 式 KSA 生成 256 字节表
      j = (j + dst[i] + key[i % len(key)]) & 0xff;  swap(dst[i], dst[j])

本脚本枚举 S 盒 / 密钥 / IV / 轮数 组合，与已知 (明文, 密文) 对比对。
"""
import base64, hashlib, itertools

AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]

ALPHABET = b'5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
KEY32 = b'ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv'
IV16 = b'WonrnVkxeIxDcFbv'

STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
FWD = str.maketrans(STD, '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj')
S_INPUT = "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
A1 = base64.b64encode(S_INPUT.encode()).decode().translate(FWD).encode()
OUT = bytes.fromhex(
    "23754ae9d0cbe749f5441e769b45143e"
    "2b3ef9d5b6c78fd91e33fb5136486918"
    "f70e50af61d497be95acdd0fd7ffae85"
    "c5d33b3dfcc0702635ae5565fa98a5ed"
    "c390790538d8262e8d01182c01292be0"
    "b4f1260c528929f81df179d0eb6fc929"
    "cc4077a891b446e45a55fa7ccf268594")


def ksa(sbox: bytes, key: bytes) -> bytes:
    """以 sbox 为初值、key 为密钥做 RC4 式 KSA，返回 256 字节表。"""
    dst = bytearray(sbox)
    j = 0
    for i in range(256):
        j = (j + dst[i] + key[i % len(key)]) & 0xFF
        dst[i], dst[j] = dst[j], dst[i]
    return bytes(dst)


def gm(a, b):
    """GF(2^8) 乘法，模 0x11b。"""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def expand_key(key: bytes, sbox: bytes, nk_words: int, nr: int):
    """标准 AES 密钥扩展，SubWord 使用给定 sbox。"""
    nk = len(key) // 4
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [sbox[b] for b in t]
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [sbox[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [bytes(b for word in w[4 * r:4 * r + 4] for b in word) for r in range(nr + 1)]


def aes_block(block: bytes, rk, sbox: bytes) -> bytes:
    s = [block[i] ^ rk[0][i] for i in range(16)]
    nr = len(rk) - 1
    for rnd in range(1, nr + 1):
        s = [sbox[b] for b in s]
        # ShiftRows
        s = [s[0], s[5], s[10], s[15],
             s[4], s[9], s[14], s[3],
             s[8], s[13], s[2], s[7],
             s[12], s[1], s[6], s[11]]
        if rnd != nr:
            ns = [0] * 16
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                ns[4 * c + 0] = gm(a0, 2) ^ gm(a1, 3) ^ a2 ^ a3
                ns[4 * c + 1] = a0 ^ gm(a1, 2) ^ gm(a2, 3) ^ a3
                ns[4 * c + 2] = a0 ^ a1 ^ gm(a2, 2) ^ gm(a3, 3)
                ns[4 * c + 3] = gm(a0, 3) ^ a1 ^ a2 ^ gm(a3, 2)
            s = ns
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
    return bytes(s)


def cbc(key, iv, pt, sbox):
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    rk = expand_key(key, sbox, nk, nr)
    out = b""
    prev = iv
    for i in range(0, len(pt), 16):
        blk = bytes(a ^ b for a, b in zip(pt[i:i + 16], prev))
        prev = aes_block(blk, rk, sbox)
        out += prev
    return out


def pad16(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def main():
    # 自检：标准 AES-256-CBC
    from Crypto.Cipher import AES
    k = bytes(range(32))
    iv = bytes(range(16))
    pt = bytes(range(32))
    assert cbc(k, iv, pt, AES_SBOX) == AES.new(k, AES.MODE_CBC, iv).encrypt(pt), "AES 自检失败"
    print("AES 实现自检: OK")

    PT = pad16(A1)
    SBOXES = {
        "AES": AES_SBOX,
        "KSA(sbox,KEY32)": ksa(AES_SBOX, KEY32),
        "KSA(sbox,ALPHA64)": ksa(AES_SBOX, ALPHABET),
        "KSA(KSA(sbox,ALPHA),KEY32)": ksa(ksa(AES_SBOX, ALPHABET), KEY32),
        "KSA(KSA(sbox,KEY32),ALPHA)": ksa(ksa(AES_SBOX, KEY32), ALPHABET),
    }
    KEYS = {
        "KEY32": KEY32,
        "KEY32[:16]": KEY32[:16],
        "KEY32[16:]": KEY32[16:],
        "KEY32[:24]": KEY32[:24],
        "IV16": IV16,
        "md5(KEY32)": hashlib.md5(KEY32).digest(),
        "sha256(KEY32)": hashlib.sha256(KEY32).digest(),
    }
    IVS = {"IV16": IV16, "zero16": bytes(16), "KEY32[:16]": KEY32[:16], "KEY32[16:]": KEY32[16:]}

    hits = 0
    checked = 0
    for sn, sb in SBOXES.items():
        for kn, k in KEYS.items():
            for ivn, iv in IVS.items():
                try:
                    c = cbc(k, iv, PT, sb)
                except Exception:
                    continue
                checked += 1
                if c == OUT:
                    print("*** HIT  sbox=%s key=%s iv=%s" % (sn, kn, ivn))
                    hits += 1
                elif c[:16] == OUT[:16]:
                    print("    首块命中 sbox=%s key=%s iv=%s" % (sn, kn, ivn))
    print("组合检查 %d 个，命中 %d 个" % (checked, hits))


if __name__ == "__main__":
    main()
