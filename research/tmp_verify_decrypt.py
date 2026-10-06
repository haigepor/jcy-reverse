# -*- coding: utf-8 -*-
"""tmp_verify_decrypt.py — 用已验证模型实现解密, 端到端验证锚点 hit21 与 bfpairs。

模型 (已实测确认):
    E(x) = T( SR( SB( AES9( T(x) ^ rk0 ) ) ) ) ^ C(K)
    T = 4x4 字节转置;  AES9 = 标准 AES 前 9 轮;  C(K) 由一次预言机调用确定。
    P1 = CBC-E(key=K16, iv=reverse(K16), PKCS7-16(明文))
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa

SO = open(os.path.join(HERE, 'artifacts', 'libcore.so'), 'rb').read()
SBOX = SO[0x1dfc00:0x1dfc00 + 256]
ISBOX = bytes(SBOX.index(i) for i in range(256))


def xt(a):
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = xt(a)
        b >>= 1
    return r


def expand(key):
    w = [list(key[i*4:i*4+4]) for i in range(4)]
    rc = 1
    for i in range(4, 44):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rc
            rc = xt(rc)
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4*r:4*r+4], [])) for r in range(11)]


def SB(s):
    return [SBOX[x] for x in s]


def ISB(s):
    return [ISBOX[x] for x in s]


def SR(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c+r) % 4)+r]
    return o


def ISR(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c-r) % 4)+r]
    return o


def MC(s):
    o = [0]*16
    for c in range(4):
        a = s[4*c:4*c+4]
        o[4*c+0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4*c+1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        o[4*c+2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        o[4*c+3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)
    return o


def IMC(s):
    o = [0]*16
    for c in range(4):
        a = s[4*c:4*c+4]
        o[4*c+0] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9)
        o[4*c+1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13)
        o[4*c+2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11)
        o[4*c+3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14)
    return o


def T(s):
    o = [0]*16
    for r in range(4):
        for c in range(4):
            o[4*r+c] = s[4*c+r]
    return o


def xr(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def state9_from_A0(A0, rk):
    s = list(A0)
    for r in range(1, 10):
        s = MC(SR(SB(s)))
        s = [x ^ y for x, y in zip(s, rk[r])]
    return bytes(s)


def determine_C(o, K):
    """一次预言机调用确定 C(K)。pt=0, iv=0 -> E 输入 0。"""
    rk = expand(K)
    A0 = [x ^ y for x, y in zip(T(list(bytes(16))), rk[0])]  # = rk0
    G9 = state9_from_A0(A0, rk)
    st10 = SR(SB(list(G9)))
    ct = o.enc(bytes(16), K, bytes(16))[:16]
    return xr(ct, T(st10))


def E(x, K, C):
    rk = expand(K)
    A0 = [a ^ b for a, b in zip(T(list(x)), rk[0])]
    s = A0
    for r in range(1, 10):
        s = MC(SR(SB(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    st10 = SR(SB(s))
    return bytes(xr(T(st10), C))


def E_inv(y, K, C):
    rk = expand(K)
    st10 = T(list(xr(y, C)))
    s = ISR(ISB(st10))
    for r in range(9, 0, -1):
        s = xr(s, rk[r])
        s = ISB(ISR(IMC(s)))
    A0 = s
    return bytes(T(list(xr(A0, rk[0]))))


def decrypt(P1, K, C, iv=None):
    if iv is None:
        iv = K[::-1]
    rk = expand(K)
    assert len(P1) % 16 == 0 and len(P1) > 0
    prev = iv
    out = b''
    for i in range(0, len(P1), 16):
        blk = P1[i:i+16]
        x = E_inv(blk, K, C)
        out += xr(x, prev)
        prev = blk
    # strip PKCS7-16
    n = out[-1]
    if 1 <= n <= 16 and out[-n:] == bytes([n])*n:
        out = out[:-n]
    return out


def main():
    o = EOracle()
    K = b'X8TEUA3DEXZNW2TN'
    C = determine_C(o, K)
    print('C(K) =', C.hex())

    # 自检: E 与预言机一致 (单块, iv=0)
    for pt in [bytes(16), bytes(range(16)), bytes([0x10]*16)]:
        ct_or = o.enc(pt, K, bytes(16))
        print('  单块 enc 一致(pt=%s): %s' % (pt.hex(), E(pt, K, C) == ct_or[:16]))

    # 锚点 hit21
    pl = json.load(open(os.path.join(HERE, 'tmp_plains.json')))
    pairs = json.load(open(os.path.join(HERE, 'tmp_pairs.json')))
    plain = pl[5]['text'].encode('utf-8')
    h21 = [bytes.fromhex(e['p1_hex']) for e in pairs if e.get('hit') == 21][0]
    rec = decrypt(h21, K, C)
    print('hit21 解密 len=%d' % len(rec))
    print('  期望 len=%d' % len(plain))
    print('  完全相等:', rec == plain)
    if rec != plain:
        print('  rec   :', repr(rec[:120]))
        print('  plain :', repr(plain[:120]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
