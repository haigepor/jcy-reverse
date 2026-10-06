# -*- coding: utf-8 -*-
"""tmp_g1_step1.py — CONST 序列结构测试（秒级主攻 STEP1）。

对多个 K 标定 CONST_b 序列（b=0..127），落盘金料后做四类一锤定音测试：
  T1 同 K 相邻差分恒定？        CONST_{b+1} ^ CONST_b == c ?
  T2 跨 K GF(2) 仿射线性递推？  CONST_{b+1} = M·CONST_b ^ c（M 与 K 无关）?
     —— 若成立，纯 Python 128bit 位矩阵迭代 ≈ 10µs/块，直接达成秒级
  T3 计数器可见性：CONST_b ^ CONST_1 的字节里是否露出 b 的编码？
  T4 跨 K 同位差分 vs b：CONST_b(K1)^CONST_b(K2) 是否有结构？
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import EDecryptor  # noqa: E402

GOLDEN = os.path.join(HERE, "reports", "const_golden.json")
NKEYS = 8
NBLK = 128


def build_golden(force=False):
    if os.path.exists(GOLDEN) and not force:
        return json.load(open(GOLDEN))
    d = EDecryptor()
    out = {}
    for i in range(NKEYS):
        K = bytes([(i * 37 + j * 11 + 5) % 256 for j in range(16)])  # 固定可复现
        t0 = time.time()
        C, rk, CONST, Cb = d.calibrate(K, NBLK)
        out[K.hex()] = [bytes(c).hex() for c in CONST]
        print("[golden] K=%s %d 块 %.1fs (%.3fs/块) 不变式=%s"
              % (K.hex()[:8], NBLK, time.time() - t0,
                 (time.time() - t0) / NBLK, d.invariant_ok), flush=True)
    os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
    json.dump(out, open(GOLDEN, "w"))
    return out


def x2i(h):
    return int.from_bytes(bytes.fromhex(h), "big")


def i2x(v):
    return v.to_bytes(16, "big")


def test_t1(seq):
    """同 K 相邻差分恒定？"""
    ds = {x2i(seq[b]) ^ x2i(seq[b + 1]) for b in range(1, len(seq) - 1)}
    return len(ds) == 1, (hex(ds.pop()) if len(ds) == 1 else "不恒定(%d 种)" % len(ds))


def test_t2(golden):
    """跨 K 仿射线性递推：y=F(x)=M·x ^ c，F 与 K 无关？
    用基规约法：收集全部 (x=CONST_b, y=CONST_{b+1}) 对（跳过 x=0），
    线性一致 ⇔ 任意差分 (d,e) 满足 e 是 d 的线性函数。"""
    pairs = []
    for K, seq in golden.items():
        for b in range(1, len(seq) - 1):
            x, y = x2i(seq[b]), x2i(seq[b + 1])
            if x:
                pairs.append((x, y))
    x0, y0 = pairs[0]
    basis = {}          # 最高位 bit -> (d_mask, e_vec)
    inconsistent = 0
    for x, y in pairs[1:]:
        d, e = x ^ x0, y ^ y0
        while d:
            hb = d.bit_length() - 1
            if hb not in basis:
                basis[hb] = (d, e)
                break
            bd, be = basis[hb]
            d ^= bd
            e ^= be
        else:
            if e:
                inconsistent += 1
    n_dep = len(basis)
    verdict = "线性一致" if inconsistent == 0 else "非线性(%d 个矛盾差分)" % inconsistent
    return n_dep, inconsistent, verdict, pairs


def test_t2_holdout(golden):
    """留出验证：用一半 K 建 M 的基，另一半 K 的对做外推测试。"""
    ks = sorted(golden.keys())
    train = {k: golden[k] for k in ks[: len(ks) // 2]}
    test = {k: golden[k] for k in ks[len(ks) // 2:]}
    n_dep, inconsistent, verdict, _ = test_t2(train)
    if inconsistent:
        return verdict + "（训练集已非线性，无需留出）"
    # 显式化 M：对每个单位向量 e_i 求映射（用基规约）
    x0, y0 = None, None
    for K, seq in train.items():
        for b in range(1, len(seq) - 1):
            if x2i(seq[b]):
                x0, y0 = x2i(seq[b]), x2i(seq[b + 1])
                break
        if x0 is not None:
            break
    basis = {}
    for K, seq in train.items():
        for b in range(1, len(seq) - 1):
            x, y = x2i(seq[b]), x2i(seq[b + 1])
            d, e = x ^ x0, y ^ y0
            while d:
                hb = d.bit_length() - 1
                if hb not in basis:
                    basis[hb] = (d, e)
                    break
                bd, be = basis[hb]
                d ^= bd
                e ^= be
    def predict(x):
        d, e = x ^ x0, 0
        while d:
            hb = d.bit_length() - 1
            if hb not in basis:
                return None
            bd, be = basis[hb]
            d ^= bd
            e ^= be
        return e ^ y0
    bad = ok = 0
    for K, seq in test.items():
        for b in range(1, len(seq) - 1):
            p = predict(x2i(seq[b]))
            if p is None or p != x2i(seq[b + 1]):
                bad += 1
            else:
                ok += 1
    return "训练集 %s；留出验证 ok=%d bad=%d → %s" % (
        verdict, ok, bad, "仿射线性递推成立！" if bad == 0 and ok else "非仿射线性")


def test_t3(seq):
    """计数器可见性：CONST_b ^ CONST_1 的 16 字节里找 b 的痕迹。"""
    base = x2i(seq[1])
    hits = []
    for b in range(2, min(len(seq), 64)):
        d = (x2i(seq[b]) ^ base).to_bytes(16, "big")
        for pos in range(16):
            if d[pos] == (b & 0xFF) or d[pos] == ((b >> 8) & 0xFF):
                hits.append((b, pos, d[pos]))
    return hits[:12], len(hits)


def test_t4(golden):
    """跨 K 同位差分：CONST_b(K1)^CONST_b(K2) 是否随 b 恒定/有规律。"""
    ks = sorted(golden.keys())[:3]
    a, bv = golden[ks[0]], golden[ks[1]]
    ds = [x2i(a[b]) ^ x2i(bv[b]) for b in range(1, len(a))]
    const_ratio = len(set(ds)) == 1
    # 差分序列自身是否线性递推（对差分再跑 T2 思路）
    dd = {ds[i] ^ ds[i + 1] for i in range(len(ds) - 1)}
    return const_ratio, len(set(ds)), len(dd)


def main():
    golden = build_golden()
    print("\n=== T1 同 K 相邻差分 ===")
    for K, seq in list(golden.items())[:3]:
        ok, info = test_t1(seq)
        print("  K=%s: %s" % (K[:8], info if not ok else "恒定! " + info))
    print("\n=== T2 跨 K 仿射线性递推（全部对） ===")
    n_dep, inc, verdict, npairs = test_t2(golden)
    print("  对数=%d 线性无关差分=%d/128 → %s" % (len(npairs), n_dep, verdict))
    print("  " + test_t2_holdout(golden))
    print("\n=== T3 计数器可见性 ===")
    K0 = sorted(golden.keys())[0]
    hits, total = test_t3(golden[K0])
    print("  命中 %d 处 %s" % (total, hits if hits else "（无 b 痕迹）"))
    print("\n=== T4 跨 K 同位差分 ===")
    cr, nu, ndd = test_t4(golden)
    print("  恒定=%s 差分值种类=%d/%d 二阶差分种类=%d" % (cr, nu, len(golden[K0]) - 1, ndd))
    json.dump(golden, open(GOLDEN, "w"))
    print("\n金料已存:", GOLDEN)


if __name__ == "__main__":
    main()
