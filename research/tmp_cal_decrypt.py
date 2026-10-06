# -*- coding: utf-8 -*-
"""tmp_cal_decrypt.py — 标定法解密原型 + 验证。
标定: 用同 K 的 dummy 加密, hook 轮驱动读 x_b, 得 CONST_b / Cb_b (仅依赖 K,b)。
解密: x_b = F_inv(ct_b ^ C(K) ^ Cb_b); pt_b = x_b ^ ct_{b-1} ^ CONST_b。
"""
import os, sys, struct, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X1  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

A_DRV = DEV_BASE + 0x2da498
Z = bytes(16)
X = V.xr
Tb = lambda b: bytes(V.T(list(b)))
u64 = lambda o, a: struct.unpack('<Q', o.s.e.rd(a, 8))[0]


def _b64len(n):
    return 4 * ((n + 2) // 3)


def enc_big(o, pt, key, iv, timeout=3_000_000_000):
    """EOracle.enc 的大超时版本 (Unicorn timeout 单位 µs)。"""
    from authgen import OFF_PIPE
    s = o.s
    s.e.fix_long_string(0x688130, key)
    s.e.fix_long_string(0x688148, iv)
    L = None
    for cand in range(1, len(pt) + 1):
        if _b64len(cand) == len(pt):
            L = cand
            break
    if L is None:
        raise ValueError('len %d' % len(pt))
    s._cur[0] = pt
    s._out.clear()
    inp = s.e.mkstr(b'\x00' * L)
    s.e.call(DEV_BASE + OFF_PIPE, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
             sret=s.sret, timeout=timeout)
    return s._out.get('body', b'')


def rows24(o, x):
    b = u64(o, x)
    return b''.join(o.s.e.rd(u64(o, b + i * 24), 4) for i in range(4))


def F(x, rk):
    s = [a ^ b for a, b in zip(V.T(list(x)), rk[0])]
    for r in range(1, 10):
        s = V.MC(V.SR(V.SB(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(V.T(V.SR(V.SB(s))))


def F_inv(w, rk):
    # E_inv(w, K, 0)
    st10 = Tb(list(w))
    s = V.ISR(V.ISB(st10))
    for r in range(9, 0, -1):
        s = X(s, rk[r])
        s = V.ISB(V.ISR(V.IMC(s)))
    return bytes(Tb(list(X(s, rk[0]))))


class CalDec:
    def __init__(self):
        self.o = EOracle()
        self.cap = []
        self.o.s.e.uc.hook_add(unicorn.UC_HOOK_CODE, self._cb,
                               begin=A_DRV, end=A_DRV + 4)

    def _cb(self, uc_, address, size, ud):
        self.cap.append(rows24(self.o, uc_.reg_read(UC_ARM64_REG_X1)))

    def calibrate(self, K, nblk):
        C = V.determine_C(self.o, K)
        rk = V.expand(K)
        iv = K[::-1]
        dummy = bytes(16 * nblk)
        self.cap.clear()
        ctd = enc_big(self.o, dummy, K, iv)
        xs = [Tb(self.cap[i]) for i in range(0, len(self.cap), 2)]
        assert len(xs) >= nblk, 'captured %d < nblk %d' % (len(xs), nblk)
        CONST, Cb = [], []
        for b in range(nblk):
            xb = xs[b]
            prev = ctd[b*16-16:b*16] if b else iv
            CONST.append(X(X(xb, dummy[b*16:(b+1)*16]), prev))
            Cb.append(X(ctd[b*16:(b+1)*16], X(F(xb, rk), C)))
        return C, rk, CONST, Cb

    def decrypt(self, P1, K):
        nblk = len(P1) // 16
        C, rk, CONST, Cb = self.calibrate(K, nblk)
        iv = K[::-1]
        out = b''
        for b in range(nblk):
            ctb = P1[b*16:(b+1)*16]
            xb = F_inv(X(X(ctb, C), Cb[b]), rk)
            prev = P1[b*16-16:b*16] if b else iv
            out += X(X(xb, prev), CONST[b])
        n = out[-1]
        if 1 <= n <= 16 and out[-n:] == bytes([n])*n:
            out = out[:-n]
        return out


def main():
    cd = CalDec()
    pairs = json.load(open(os.path.join(HERE, 'tmp_pairs.json')))
    for e in pairs:
        if not e.get('k16'):
            continue
        K = e['k16'].encode()
        P1 = bytes.fromhex(e['p1_hex'])
        try:
            got = cd.decrypt(P1, K)
        except Exception as ex:
            print('hit=%s K=%s ERR %s' % (e['hit'], K.decode(), ex))
            continue
        print('hit=%-4s K=%s len=%d  %r' % (e['hit'], K.decode(), len(got), got[:100]))


if __name__ == '__main__':
    main()
