#!/usr/bin/env python3
"""scan_aes_sched2.py - 扫 AES-128 加密型+解密型密钥扩展.

加密调度: rk[4] = rk[0] ^ SubWord(RotWord(rk[3])) ^ 01
解密调度 (OpenSSL AES_KEY decrypt): rk[0..3]=key, rk[40..43]=加密调度末轮,
rk[4..39]=InvMixColumns(加密调度中间轮) => rk[4] = rk[0] ^ InvMixColumns(SubWord(RotWord(rk[3])) ^ 01)
"""
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

# GF(2^8) 乘法表
def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

MUL = [[_gmul(a, b) for b in range(256)] for a in (2, 3, 9, 11, 13, 14)]
IMC = [0x0e, 0x0b, 0x0d, 0x09]  # InvMixColumns 矩阵首行 (列循环)


def inv_mix_col(w):
    """w = 4 字节列, 返回 InvMixColumns 后的 4 字节."""
    return bytes(
        MUL[4][w[0]] ^ MUL[1][w[1]] ^ MUL[2][w[2]] ^ MUL[3][w[3]],
    ) + bytes(
        MUL[3][w[0]] ^ MUL[4][w[1]] ^ MUL[1][w[2]] ^ MUL[2][w[3]],
    ) + bytes(
        MUL[2][w[0]] ^ MUL[3][w[1]] ^ MUL[4][w[2]] ^ MUL[1][w[3]],
    ) + bytes(
        MUL[1][w[0]] ^ MUL[2][w[1]] ^ MUL[3][w[2]] ^ MUL[4][w[3]],
    )


def expand_enc(key16):
    w = [list(key16[i*4:(i+1)*4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36][i//4 - 1]
        w.append([a ^ b for a, b in zip(w[i-4], t)])
    return bytes(b for x in w for b in x)


def expand_dec(key16):
    """OpenSSL 解密调度: 等价逆密钥 (EqDC): rk = dec schedule with InvMixColumns on middle rounds."""
    enc = expand_enc(key16)
    out = bytearray(enc[:16])
    for r in range(1, 10):
        blk = enc[r*16:(r+1)*16]
        col = bytearray(16)
        for c in range(4):
            col[c*4:(c+1)*4] = inv_mix_col(blk[c*4:(c+1)*4])
        out += col
    out += enc[160:176]
    return bytes(out)


def w4check(buf, off, inv=False):
    w0 = buf[off:off+4]
    w3 = buf[off+12:off+16]
    rot = bytes([SBOX[w3[1]], SBOX[w3[2]], SBOX[w3[3]], SBOX[w3[0]]])
    t = bytes(a ^ 0x01 for a in rot)  # ^ rcon1
    if inv:
        t4 = inv_mix_col(t)
    else:
        t4 = t
    w4 = bytes(a ^ b for a, b in zip(w0, t4))
    return w4 == buf[off+16:off+20]


def scan(raw, label, maxhits=40):
    hits = []
    n = len(raw)
    for off in range(0, n - 176, 4):
        inv = w4check(raw, off, inv=True)
        enc = False if inv else w4check(raw, off, inv=False)
        if not (inv or enc):
            continue
        k = raw[off:off+16]
        want = expand_dec(k) if inv else expand_enc(k)
        if raw[off:off+176] == want:
            hits.append((off, 'dec' if inv else 'enc', k))
            if len(hits) >= maxhits:
                break
    for off, kind, k in hits:
        print('[%s调度] %s @0x%x key=%r' % (kind, label, off, k))
    return hits


def main():
    targets = []
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        targets = sorted(glob.glob('research/captures/rsa_scan/emu_mem/*.bin'))
        targets += sorted(glob.glob('research/captures/rsa_scan/live/n_*.bin'))
        for t in ('263_737dd28e1000', '281_737ddf382000', '271_737dda2ce000',
                  '376_737e41c00000', '264_737dd57ec000', '297_737de137d000'):
            p = 'research/captures/rsa_scan/memdump/%s.bin' % t
            if os.path.exists(p):
                targets.append(p)
    for f in targets:
        raw = open(f, 'rb').read()
        print('== %s (%.1fMB)' % (os.path.basename(f), len(raw)/1048576), flush=True)
        scan(raw, os.path.basename(f))
    print('[done]')


if __name__ == '__main__':
    main()
