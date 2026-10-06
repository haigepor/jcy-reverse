#!/usr/bin/env python3
"""scan_rsa_key.py - 在二进制数据(内存 dump / so 文件)中定位 RSA-2048 私钥素数 p、q.

覆盖的内存布局 (128 字节窗口, 4 字节/8 字节步进):
  be_bytes : 大端字节序连续 128 字节   (Java BigInteger.toByteArray / Rust / C 序列化)
  u32le    : 32-bit 小端 limb x32      (dart:core BigInt Uint32List / 常见 C bignum)
  u64le    : 64-bit 小端 limb x16      (GMP mp_limb_t / Rust BigUint Vec<u64>)
  smi32    : Dart AOT Smi 标记数组     (pointycastle BigInteger._digits, 每 digit 占 8B = digit<<1)

筛选管线: numpy 向量预筛(最高位字 bit31=1, 最低位奇, Horner mod 小素数) -> gmpy2.is_prime.

用法:
  python scan_rsa_key.py selftest
  python scan_rsa_key.py scan FILE [FILE...] [--out primes.json] [--layout be_bytes,u32le,u64le,smi32]
  python scan_rsa_key.py verify --sample FILE [--sample FILE2...] --primes primes.json [--out result.json]
"""
import argparse
import base64
import itertools
import json
import os
import random
import re
import sys

import numpy as np
import gmpy2

try:
    import numba as nb
    _HAVE_NUMBA = True
except ImportError:
    nb = None
    _HAVE_NUMBA = False

# ---------------------------------------------------------------- 筛选参数
P1_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
P2_PRIMES = [37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def _primes_below(n):
    out = []
    for x in range(3, n, 2):
        if all(x % p for p in out if p * p <= x):
            out.append(x)
    return out


KERNEL_PRIMES = np.array(_primes_below(1000), dtype=np.uint64)
KERNEL_FACTORS32 = np.array([(1 << 32) % int(p) for p in KERNEL_PRIMES], dtype=np.uint64)
KERNEL_FACTORS64 = np.array([(1 << 64) % int(p) for p in KERNEL_PRIMES], dtype=np.uint64)

if _HAVE_NUMBA:
    @nb.njit(cache=True, parallel=True)
    def _horner_nb(wwin, primes, factors, is_be):
        alive = np.ones(wwin.shape[0], dtype=np.uint8)
        for j in nb.prange(wwin.shape[0]):
            dead = False
            for pi in range(primes.shape[0]):
                if dead:
                    break
                v = np.uint64(0)
                p = primes[pi]
                f = factors[pi]
                if is_be:
                    for i in range(wwin.shape[1]):
                        v = (v * f + np.uint64(wwin[j, i]) % p) % p
                else:
                    for i in range(wwin.shape[1] - 1, -1, -1):
                        v = (v * f + np.uint64(wwin[j, i]) % p) % p
                if v == np.uint64(0):
                    alive[j] = 0
                    dead = True
        return alive
CHUNK_ROWS_32 = 2_000_000   # 每批候选窗口数 (32bit 布局)
CHUNK_ROWS_64 = 1_000_000   # 每批候选窗口数 (64bit 布局)

LAYOUTS = ("be_bytes", "u32le", "u64le", "smi32")


def _horner(wwin, idx, primes, word_bits, is_be):
    """对窗口矩阵逐素数求 value mod p; 返回 (存活窗口, 存活索引)."""
    for p in primes:
        pm = np.uint64(p)
        f = np.uint64((1 << word_bits) % p)
        wmod = wwin % pm
        v = np.zeros(wwin.shape[0], dtype=np.uint64)
        rng = range(wwin.shape[1]) if is_be else range(wwin.shape[1] - 1, -1, -1)
        for i in rng:
            v = (v * f + wmod[:, i]) % pm
        alive = v != 0
        if alive.all():
            continue
        wwin = wwin[alive]
        idx = idx[alive]
        if wwin.shape[0] == 0:
            break
    return wwin, idx


def _scan_layout(W, n_words, word_bits, is_be, out_recs, tag, file_idx=0,
                 run_ok=None, log=print, log_every=12, stride=None):
    """对一个字数组跑单布局扫描. W: uint32/uint64 小端读入的一维数组.
    stride: 每个窗口起始索引对应的原缓冲字节步长 (smi32=8, 其余=字宽)."""
    total = W.shape[0] - n_words
    if total <= 0:
        return
    if stride is None:
        stride = word_bits // 8
    shift_top = np.uint64(word_bits - 1) if word_bits == 64 else np.uint32(word_bits - 1)
    chunk = CHUNK_ROWS_64 if word_bits == 64 else CHUNK_ROWS_32
    swv = np.lib.stride_tricks.sliding_window_view(W, n_words)
    done = 0
    for lo in range(0, total, chunk):
        hi = min(lo + chunk, total)
        # ---- 字级廉价预筛: 最高位字 bit31=1, 最低位奇数
        if is_be:  # 窗口内第 0 个字是最高位字
            top = (W[lo:hi].astype(np.uint64) >> shift_top).astype(bool)
            lsb = (W[lo + n_words - 1: hi + n_words - 1] & 1).astype(bool)
        else:      # 窗口内最后一个是最高位字
            top = (W[lo + n_words - 1: hi + n_words - 1].astype(np.uint64) >> shift_top).astype(bool)
            lsb = (W[lo:hi] & 1).astype(bool)
        mask = top & lsb
        if run_ok is not None:
            mask &= run_ok[lo:hi]
        ks = np.nonzero(mask)[0] + lo
        if ks.size:
            wwin = np.ascontiguousarray(swv[ks])
            if wwin.dtype.byteorder == ">":
                wwin = wwin.astype(wwin.dtype.newbyteorder("="))
            if _HAVE_NUMBA:
                fac = KERNEL_FACTORS64 if word_bits == 64 else KERNEL_FACTORS32
                alive = _horner_nb(wwin, KERNEL_PRIMES, fac, bool(is_be))
                if not alive.all():
                    alive = alive.astype(bool)
                    wwin = wwin[alive]
                    ks = ks[alive]
            else:
                wwin, ks = _horner(wwin, ks, P1_PRIMES, word_bits, is_be)
                if wwin.shape[0]:
                    wwin, ks = _horner(wwin, ks, P2_PRIMES, word_bits, is_be)
            for off, row in zip(ks, wwin):
                if is_be:  # 行已转 native, 按字值大端拼装
                    v = 0
                    for w in row:
                        v = (v << 32) | int(w)
                else:
                    v = int.from_bytes(row.tobytes(), "little")
                if gmpy2.is_prime(v, 1):
                    out_recs.append((v, file_idx, int(off) * stride, tag))
        done = hi
        if (lo // chunk) % log_every == 0:
            log("      [%s] %3d%%" % (tag, 100 * done // total))


def scan_bytes(buf, layouts=LAYOUTS, log=print, file_idx=0):
    """扫描一段二进制, 返回素数候选记录列表 [(int 素数, file_idx, 字节偏移, 布局)]."""
    recs = []
    if len(buf) < 256:
        return recs
    if "be_bytes" in layouts or "u32le" in layouts:
        W32be = np.frombuffer(buf, ">u4")
        W32le = np.frombuffer(buf, "<u4")
        if "be_bytes" in layouts:
            _scan_layout(W32be, 32, 32, True, recs, "be_bytes", file_idx, log=log)
        if "u32le" in layouts:
            _scan_layout(W32le, 32, 32, False, recs, "u32le", file_idx, log=log)
    if "u64le" in layouts:
        W64 = np.frombuffer(buf, "<u8")
        _scan_layout(W64, 16, 64, False, recs, "u64le", file_idx, log=log)
    if "smi32" in layouts:
        A64 = np.frombuffer(buf, "<u8")
        # Dart Smi: qword = digit<<1, 载荷可占 33 bit (最高位字 digit bit31=1)
        valid = ((A64 & np.uint64(1)) == 0) & ((A64 >> np.uint64(33)) == 0)
        cs = np.concatenate((np.zeros(1, np.int64), np.cumsum(~valid, dtype=np.int64)))
        if len(A64) >= 32:
            run_ok = (cs[32:] - cs[:-32]) == 0
            Wd = (A64 >> np.uint64(1)).astype(np.uint32)
            _scan_layout(Wd, 32, 32, False, recs, "smi32", file_idx,
                         run_ok=run_ok, log=log, stride=8)
    # 终筛: 高轮次 Miller-Rabin, 误报率 < 4^-25
    recs = [r for r in recs if gmpy2.is_prime(r[0], 25)]
    return recs


# ---------------------------------------------------------------- 样本验证
def load_sample(path):
    raw = open(path, "rb").read()
    txt = raw.decode("ascii", "ignore").strip()
    p0s, _, p1s = txt.partition(".")
    c = int.from_bytes(base64.b64decode(re.sub(r"\s", "", p0s)), "big")
    p1 = base64.b64decode(re.sub(r"\s", "", p1s))
    return c, p1


def _looks_json(pt):
    try:
        t = pt.decode("utf-8")
    except UnicodeDecodeError:
        return False
    head = t.lstrip()[:4]
    return head[:1] in ("{", "[", '"') or '"code"' in t[:200]


def payload_candidates(mb):
    """从 256 字节 RSA 明文里穷举 (key, iv) 切法."""
    out = []
    # PKCS#1 v1.5 type 2 剥壳
    if mb[0] == 0 and mb[1] == 2:
        z = mb.find(0, 2)
        if z > 0:
            pl = mb[z + 1:]
            if len(pl) >= 48:
                out.append((pl[:32], pl[32:48], "v15: key32+iv16"))
                out.append((pl[:16], pl[16:32], "v15: key16+iv16"))
            if len(pl) >= 32:
                out.append((pl[:32], b"\0" * 16, "v15: key32/zeroiv"))
    # 裸窗口穷举
    for w in (32, 16, 24):
        if len(mb) >= w + 16:
            out.append((mb[:w], mb[w:w + 16], "head%d+next16" % w))
            out.append((mb[-w:], mb[-w - 16:-w], "tail%d+prev16" % w))
            out.append((mb[-w:], b"\0" * 16, "tail%d/zeroiv" % w))
        out.append((mb[:w], b"\0" * 16, "head%d/zeroiv" % w))
    if len(mb) >= 48:
        # iv||key 顺序: key=mb[16:48], iv=mb[0:16]；及 key=mb[16:48]/零iv
        out.append((mb[16:48], mb[:16], "iv16+key32"))
        out.append((mb[16:48], b"\0" * 16, "key32@16/zeroiv"))
    return out


def aes_try(key, iv, p1):
    if len(key) not in (16, 24, 32) or len(iv) != 16 or len(p1) < 32:
        return None
    from Crypto.Cipher import AES
    probe = AES.new(key, AES.MODE_CBC, iv).decrypt(p1[:48])
    if not _looks_json(probe[:32] + probe[16:48]):
        return None
    full = AES.new(key, AES.MODE_CBC, iv).decrypt(p1[: len(p1) // 16 * 16])
    # PKCS7 剥离(宽松)
    n = full[-1]
    if 1 <= n <= 16 and full.endswith(bytes([n]) * n):
        full = full[:-n]
    return full


def _ecb_try(cipher_new, key, p1):
    if len(p1) < 32:
        return None
    data = p1[: len(p1) // 16 * 16]
    dec = cipher_new(key).decrypt(data[:48])
    if not _looks_json(dec):
        return None
    full = cipher_new(key).decrypt(data)
    n = full[-1]
    if 1 <= n <= 16 and full.endswith(bytes([n]) * n):
        full = full[:-n]
    return full


def sm4_cbc_try(key, iv, p1):
    if len(key) != 16 or len(iv) != 16 or len(p1) < 32:
        return None
    from sm4 import SM4
    data = p1[: len(p1) // 16 * 16]
    prev, out = iv, []
    for i in range(0, min(len(data), 48), 16):
        blk = SM4(key).decrypt(data[i:i + 16])
        out.append(bytes(a ^ b for a, b in zip(blk, prev)))
        prev = data[i:i + 16]
    probe = b"".join(out)
    if not _looks_json(probe):
        return None
    prev, out = iv, []
    for i in range(0, len(data), 16):
        blk = SM4(key).decrypt(data[i:i + 16])
        out.append(bytes(a ^ b for a, b in zip(blk, prev)))
        prev = data[i:i + 16]
    full = b"".join(out)
    n = full[-1]
    if 1 <= n <= 16 and full.endswith(bytes([n]) * n):
        full = full[:-n]
    return full


def sym_try(key, iv, note, p1):
    """穷举对称层: AES-CBC / AES-ECB / SM4-CBC / SM4-ECB."""
    from Crypto.Cipher import AES
    pt = aes_try(key, iv, p1)
    if pt is not None:
        return pt, "AES-CBC " + note
    if len(key) in (16, 24, 32):
        pt = _ecb_try(lambda k: AES.new(k, AES.MODE_ECB), key, p1)
        if pt is not None:
            return pt, "AES-ECB " + note
    if len(key) == 16:
        pt = sm4_cbc_try(key, iv, p1)
        if pt is not None:
            return pt, "SM4-CBC " + note
        pt = _ecb_try(SM4_NEW, key, p1)
        if pt is not None:
            return pt, "SM4-ECB " + note
    return None, None


def SM4_NEW(key):
    from sm4 import SM4
    return SM4(key)


def try_pair(p, q, samples):
    n = p * q
    if n.bit_length() != 2048:
        return None
    phi = (p - 1) * (q - 1)
    for e in (65537, 3, 17, 5, 7, 257):
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)
        for c, p1 in samples:
            if c >= n:
                continue
            m = pow(c, d, n)
            mb = m.to_bytes(256, "big")
            for key, iv, note in payload_candidates(mb):
                pt, note2 = sym_try(key, iv, note, p1)
                if pt is not None:
                    return {"n": n, "e": e, "d": d, "p": p, "q": q,
                            "sample_note": note2, "plain": pt}
            # OAEP 兜底
            try:
                from Crypto.Cipher import PKCS1_OAEP
                from Crypto.Hash import SHA1, SHA256
                from Crypto.PublicKey import RSA
                rk = RSA.construct((n, e, d, p, q))
                for ha in (SHA1, SHA256):
                    try:
                        pl = PKCS1_OAEP.new(rk, hashAlgo=ha).decrypt(mb)
                        cands = [(pl[:32], pl[32:48], "OAEP key32+iv16"),
                                 (pl[:16], pl[16:32], "OAEP key16+iv16")]
                        cands += payload_candidates(b"\x00" * (256 - len(pl)) + pl)
                        for key, iv, note2 in cands:
                            pt, note3 = sym_try(key, iv, note2, p1)
                            if pt is not None:
                                return {"n": n, "e": e, "d": d, "p": p, "q": q,
                                        "sample_note": "OAEP/" + note3, "plain": pt}
                    except Exception:
                        pass
            except Exception:
                pass
    return None


# ---------------------------------------------------------------- CLI
def cmd_selftest(_):
    rnd = random.Random(20261001)
    base = (1 << 1023) | (rnd.getrandbits(1022) | 1)
    p = int(gmpy2.next_prime(base))
    q = int(gmpy2.next_prime(base + (1 << 700)))
    buf = bytearray(0x4000)
    buf[0x1000:0x1080] = p.to_bytes(128, "big")            # be_bytes
    buf[0x2000:0x2080] = q.to_bytes(128, "little")         # u32le/u64le 同形
    qb = q.to_bytes(128, "little")
    for i in range(32):                                     # smi32
        digit = int.from_bytes(qb[i * 4:i * 4 + 4], "little")
        buf[0x3000 + i * 8: 0x3008 + i * 8] = (digit * 2).to_bytes(8, "little")
    recs = scan_bytes(bytes(buf), log=lambda *_: None)
    vals = {r[0] for r in recs}
    offs = {r[2] for r in recs}
    ok = (p in vals) and (q in vals) and {0x1000, 0x2000, 0x3000} <= offs
    print("selftest: p found=%s q found=%s offsets_ok=%s recs=%d"
          % (p in vals, q in vals, {0x1000, 0x2000, 0x3000} <= offs, len(recs)))
    sys.exit(0 if ok else 1)


def _recs_dump(recs, path, files):
    json.dump({"files": files,
               "primes": [[str(v), fi, off, tag] for v, fi, off, tag in recs]},
              open(path, "w"))


def _recs_load(path):
    d = json.load(open(path))
    return d.get("files", []), [(int(v), fi, off, tag)
                                for v, fi, off, tag in d["primes"]]


def cmd_scan(a):
    recs = []
    files = []
    if a.out and os.path.exists(a.out):
        files, recs = _recs_load(a.out)
        print("[merge] 已有候选 %d 条" % len(recs))
    for f in a.files:
        if os.path.isdir(f):
            a.files.extend(sorted(
                os.path.join(f, x) for x in os.listdir(f) if x.endswith(".bin")))
            continue
        fi = len(files)
        files.append(f)
        buf = open(f, "rb").read()
        print("[scan] #%d %s (%.1f MB)" % (fi, f, len(buf) / 1048576))
        found = scan_bytes(buf, layouts=a.layout.split(","), file_idx=fi)
        print("   -> 素数候选 %d 个" % len(found))
        recs.extend(found)
        del buf
    if a.out:
        _recs_dump(recs, a.out, files)
        print("[out] %s: %d 条候选记录" % (a.out, len(recs)))


def cmd_verify(a):
    """邻近配对 + n=pq 字节命中预筛 + RSA oracle."""
    files, recs = _recs_load(a.primes)
    samples = [load_sample(s) for s in a.sample]
    bufs = [open(f, "rb").read() for f in files]
    print("候选 %d 条 / 文件 %d / 样本 %d, 邻域 %d KB" %
          (len(recs), len(files), len(samples), a.local // 1024))
    # 按文件分组, 按偏移排序
    byfile = {}
    for v, fi, off, tag in recs:
        if fi < len(bufs):
            byfile.setdefault(fi, []).append((off, v, tag))
    tried = 0
    for fi, lst in sorted(byfile.items()):
        lst.sort()
        buf = bufs[fi]
        for x in range(len(lst)):
            off_a, pa, _ = lst[x]
            for y in range(x + 1, len(lst)):
                off_b, pb, _ = lst[y]
                if off_b - off_a > a.local:
                    break
                tried += 1
                n = pa * pb
                if n.bit_length() != 2048:
                    continue
                # 邻域字节命中 n 才进入昂贵的 RSA oracle
                lo = max(0, min(off_a, off_b) - a.local)
                hi = min(len(buf), max(off_a, off_b) + 256 + a.local)
                seg = buf[lo:hi]
                nb = n.to_bytes(256, "big")
                nl = n.to_bytes(256, "little")
                if nb not in seg and nl not in seg:
                    continue
                print("  [n-hit] f%d %#x/%#x -> oracle ..." % (fi, off_a, off_b), flush=True)
                r = try_pair(pa, pb, samples)
                if r:
                    print("\n===== RSA 私钥命中 =====")
                    print("p = %s" % hex(r["p"]))
                    print("q = %s" % hex(r["q"]))
                    print("e = %d   note = %s" % (r["e"], r["sample_note"]))
                    print("plain[:120] = %r" % r["plain"][:120])
                    if a.out:
                        json.dump({"n": hex(r["n"]), "e": r["e"], "d": hex(r["d"]),
                                   "p": hex(r["p"]), "q": hex(r["q"]),
                                   "sample_note": r["sample_note"]},
                                  open(a.out, "w"), indent=1)
                        from Crypto.PublicKey import RSA
                        pem = RSA.construct((r["n"], r["e"], r["d"], r["p"], r["q"])).export_key()
                        open(os.path.splitext(a.out)[0] + ".pem", "wb").write(pem)
                        open(os.path.splitext(a.out)[0] + ".plain.txt", "wb").write(r["plain"])
                        print("[out] %s / .pem / .plain.txt" % a.out)
                    sys.exit(0)
    print("未命中 (尝试配对 %d 次): 无任何邻近素数对能解开样本" % tried)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    s = sub.add_parser("scan")
    s.add_argument("files", nargs="+")
    s.add_argument("--out", default=None)
    s.add_argument("--layout", default=",".join(LAYOUTS))
    v = sub.add_parser("verify")
    v.add_argument("--sample", action="append", required=True)
    v.add_argument("--primes", required=True)
    v.add_argument("--out", default=None)
    v.add_argument("--local", type=int, default=65536,
                   help="p/q 邻域字节距离阈值, 默认 64KB")
    a = ap.parse_args()
    {"selftest": cmd_selftest, "scan": cmd_scan, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    main()
