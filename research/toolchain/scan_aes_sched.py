#!/usr/bin/env python3
"""scan_aes_sched.py - 在 emu 内存转储中扫 AES-128 密钥扩展 (176B) 并验证."""
import glob
import os
import sys

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def expand(key16):
    w = [list(key16[i*4:(i+1)*4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i//4 - 1]
        w.append([a ^ b for a, b in zip(w[i-4], t)])
    out = bytearray()
    for x in w:
        out += bytes(x)
    return bytes(out)


def w4check(buf, off):
    """廉价过滤: W[4] == W[0] ^ SubWord(RotWord(W[3])) ^ rcon1."""
    w0 = buf[off:off+4]
    w3 = buf[off+12:off+16]
    rot = bytes([SBOX[w3[1]], SBOX[w3[2]], SBOX[w3[3]], SBOX[w3[0]]])
    w4 = bytes(a ^ b ^ 0x01 for a, b in zip(w0, rot))
    return w4 == buf[off+16:off+20]


def main():
    files = sorted(glob.glob('research/captures/rsa_scan/emu_mem/*.bin'))
    needle = b'BT5YPBE8A7AUKPXK'
    for f in files:
        raw = open(f, 'rb').read()
        # 1) 会话密钥串上下文
        pos = 0
        while True:
            p = raw.find(needle, pos)
            if p < 0:
                break
            ctx = raw[max(0, p-64):p+96]
            print('[key-str] %s @0x%x ctx=%r' % (os.path.basename(f), p, ctx))
            pos = p + 1
        # 2) AES-128 调度扫描 (4 字节对齐)
        n = len(raw)
        hits = []
        for off in range(0, n - 176, 4):
            if w4check(raw, off):
                if expand(raw[off:off+16]) == raw[off:off+176]:
                    hits.append(off)
        if hits:
            for h in hits:
                print('[AES128] %s @0x%x key=%r full=%s' % (
                    os.path.basename(f), h, raw[h:h+16], raw[h:h+176].hex()[:64]))
    print('[done]')


if __name__ == '__main__':
    main()
