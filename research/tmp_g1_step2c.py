# -*- coding: utf-8 -*-
"""tmp_g1_step2c.py — A: CONST 链 = AES9/E 变体组合穷举（金料直测）。

假设：生成器内部是「状态链」state_{b+1} = Cipher(state_b ⊕ in_xor) ⊕ out_xor，
Cipher ∈ {标准 AES-128, F(E 去 C), E=F^C(K)}，key ∈ 常见派生，xor 常量 ∈ 已知量。
全部在金料（8 K × 128 块）上直接验证，任何一条命中 = 闭式算法到手。
"""
import itertools
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import EDecryptor, F, expand, xr, T, SB, SR, MC  # noqa: E402
from jcy_protocol.auth import AES_KEY, AES_IV  # noqa: E402

GOLDEN = os.path.join(HERE, "reports", "const_golden.json")
golden = json.load(open(GOLDEN))
d = EDecryptor()


def aes_ecb(key, data):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB).encrypt(bytes(data))


def cands_keys(K):
    iv = K[::-1]
    ks = {"K": K, "rev": iv, "ziIS32": AES_KEY.encode()[:16], "ziIS-last16": AES_KEY.encode()[16:],
          "Wonrn": AES_IV.encode(), "K^zi": xr(K, AES_KEY.encode()[:16])}
    return ks


def cands_ciphers(K):
    rk = expand(K)
    C = d.calibrate(K, 2)[0]
    Cb = bytes(C)
    out = {
        "AES(K)": (lambda x, k=K: aes_ecb(k, x)),
        "AES(rev)": (lambda x, k=K[::-1]: aes_ecb(k, x)),
        "F": (lambda x, rk=rk: F(x, rk)),
        "E": (lambda x, rk=rk, Cb=Cb: xr(F(x, rk), Cb)),
    }
    return out


def test_seq(name, fn, seq, xor_ins, xor_outs):
    """state_1=CONST[1];  state_{b+1} = fn(state_b ^ xi) ^ xo，逐条候选验证。"""
    for xi_name, xi in xor_ins:
        for xo_name, xo in xor_outs:
            ok = True
            st = bytes.fromhex(seq[1])
            for b in range(2, min(12, len(seq))):
                y = fn(xr(st, xi))
                y = xr(y, xo)
                if y != bytes.fromhex(seq[b]):
                    ok = False
                    break
                st = y
            if ok:
                print("  ✅ 命中: %s  in_xor=%s out_xor=%s" % (name, xi_name, xo_name))
                return True
    return False


XOR_INS = [("0", bytes(16))]
XOR_OUTS = [("0", bytes(16))]

print("=== A. 状态链穷举（in/out xor 常量一阶组合） ===")
hit = False
for Khex, seq in list(golden.items())[:3]:
    K = bytes.fromhex(Khex)
    iv = K[::-1]
    rk = expand(K)
    C = d.calibrate(K, 2)[0]
    Cb = bytes(C)
    # 更全的 xor 常量集
    xor_ins = [("0", bytes(16)), ("iv", iv), ("K", K), ("C", Cb), ("CONST1", bytes.fromhex(seq[1]))]
    xor_outs = [("0", bytes(16)), ("iv", iv), ("K", K), ("C", Cb),
                ("prev", None), ("CONST1", bytes.fromhex(seq[1]))]  # prev 单独处理
    ciphers = cands_ciphers(K)
    for cname, fn in ciphers.items():
        # prev 形式：out = prev（依赖 b），单独展开
        for xi_name, xi in xor_ins:
            ok = True
            st = bytes.fromhex(seq[1])
            for b in range(2, min(12, len(seq))):
                prev = bytes.fromhex(seq[b - 1])
                y = xr(fn(xr(st, xi)), prev)
                if y != bytes.fromhex(seq[b]):
                    ok = False
                    break
                st = y
            if ok:
                print("  ✅ %s K=%s in_xor=%s out_xor=prev" % (cname, Khex[:8], xi_name))
                hit = True
        # 常量 out 形式
        for xi_name, xi in xor_ins:
            for xo_name, xo in xor_outs:
                if xo is None:
                    continue
                ok = True
                st = bytes.fromhex(seq[1])
                for b in range(2, min(12, len(seq))):
                    y = xr(fn(xr(st, xi)), xo)
                    if y != bytes.fromhex(seq[b]):
                        ok = False
                        break
                    st = y
                if ok:
                    print("  ✅ %s K=%s in_xor=%s out_xor=%s" % (cname, Khex[:8], xi_name, xo_name))
                    hit = True
if not hit:
    print("  ❌ 40+ 组合全不匹配 —— 链式假设（state_{b+1}=G(state_b)）排除或 G 非已知原语")

print("\n=== A2. 计数器型：CONST_b = Cipher(编码(b)) ⊕ 常量 ===")
hit2 = False
for Khex, seq in list(golden.items())[:3]:
    K = bytes.fromhex(Khex)
    iv = K[::-1]
    rk = expand(K)
    C = d.calibrate(K, 2)[0]
    Cb = bytes(C)
    ct1 = bytes.fromhex(seq[1])
    encs = {
        "be16+zeros": lambda b: b.to_bytes(2, "big") + bytes(14),
        "le16+zeros": lambda b: b.to_bytes(2, "little") + bytes(14),
        "be8": lambda b: bytes([b & 0xFF]) + bytes(15),
        "be64": lambda b: b.to_bytes(8, "big") + bytes(8),
    }
    ciphers = cands_ciphers(K)
    for cname, fn in ciphers.items():
        for ename, enc in encs.items():
            for xo_name, xo in [("0", bytes(16)), ("C", Cb), ("iv", iv), ("K", K), ("ct1", ct1)]:
                ok = True
                for b in range(2, min(10, len(seq))):
                    y = xr(fn(enc(b)), xo)
                    if y != bytes.fromhex(seq[b]):
                        ok = False
                        break
                if ok:
                    print("  ✅ %s K=%s enc=%s out_xor=%s" % (cname, Khex[:8], ename, xo_name))
                    hit2 = True
if not hit2:
    print("  ❌ 计数器型全不匹配")
