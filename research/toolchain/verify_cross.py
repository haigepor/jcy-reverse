#!/usr/bin/env python3
"""verify_cross.py - 跨区域全量配对: n=pq 与全 dump 256B 窗口索引求交.

不要求 p/q/n 相邻: 只要 p、q 在素数候选集里, 且 n=pq 以小端字节/limb 形式
出现在任意 dump 文件的 8 字节对齐位置, 即可命中并进入 RSA oracle.
查询键 = n mod 2^64 (窗口首 8 字节 LE), 批量向量化 searchsorted.
"""
import argparse
import glob
import itertools
import json
import mmap
import os
import sys
import time

import numpy as np
import gmpy2

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan_rsa_key as S

MASK64 = (1 << 64) - 1
CHUNK = 400_000


def build_index(dump_dir):
    """n 候选窗口过滤: 最低字节奇(n 为奇数) + 最高字节>=0x80(n 为 2048-bit)."""
    files = sorted(glob.glob(os.path.join(dump_dir, "*.bin")))
    keys, ids = [], []
    for fi, f in enumerate(files):
        raw = np.fromfile(f, dtype=np.uint8)
        w = raw.view("<u8")
        nwin = min(len(raw) // 8, len(raw[255::8]))
        if nwin == 0:
            continue
        m = ((raw[0::8][:nwin] & np.uint8(1)) == 1) & (raw[255::8][:nwin] >= np.uint8(0x80))
        k = w[:nwin][m]
        ids.append((np.flatnonzero(m).astype(np.uint64) << np.uint64(3))
                   | (np.uint64(fi) << np.uint64(40)))
        keys.append(k)
    keys = np.concatenate(keys)
    ids = np.concatenate(ids)
    print("索引窗口(过滤后) %d 个 (%.2f GB)" % (len(keys), keys.nbytes / (1 << 30)), flush=True)
    order = np.argsort(keys)
    return keys[order], ids[order], files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--primes", required=True)
    ap.add_argument("--dump", required=True)
    ap.add_argument("--sample", action="append", required=True)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    _, recs = S._recs_load(a.primes)
    primes = sorted({v for v, fi, off, tag in recs})
    pz = [gmpy2.mpz(x) for x in primes]   # GMP 乘法, CPython int mul 在此机器过慢
    np_pair = len(primes) * (len(primes) - 1) // 2
    print("去重素数 %d -> 配对 %d" % (len(primes), np_pair), flush=True)

    samples = [S.load_sample(s) for s in a.sample]
    keys, ids, files = build_index(a.dump)
    nkeys = len(keys)

    t0 = time.time()
    tried = 0
    hits = []
    mmaps = {}
    fsize = [os.path.getsize(f) for f in files]
    bk = np.empty(CHUNK, dtype=np.uint64)
    meta_i = np.empty(CHUNK, dtype=np.int32)
    meta_j = np.empty(CHUNK, dtype=np.int32)
    meta_n = []
    cnt = 0

    def flush():
        nonlocal cnt, tried, hits
        if cnt == 0:
            return
        tried += cnt
        top = np.empty(cnt, dtype=np.uint64)
        for k in range(cnt):
            top[k] = (int(meta_n[k]) >> 1984) & MASK64
        q2 = np.concatenate([bk[:cnt], top])  # 前半: LE 窗口键(n 低64), 后半: BE 存储(n 高64)
        pos = np.searchsorted(keys, q2)
        pos_c = np.minimum(pos, nkeys - 1)
        m = keys[pos_c] == q2
        n_raw = int(m.sum())
        if n_raw:
            print("  [chunk] 键碰撞 %d 个(LE+BE)" % n_raw, flush=True)
        for idx in np.nonzero(m)[0][:1000]:
            is_be = idx >= cnt
            src = idx - cnt if is_be else idx
            i, j, n = int(meta_i[src]), int(meta_j[src]), meta_n[src]
            key = int(q2[idx])
            nb = int(n).to_bytes(256, "big" if is_be else "little")
            lo = int(pos[idx])
            while lo < nkeys and int(keys[lo]) == key:
                idv = int(ids[lo]); lo += 1
                off = idv & ((1 << 40) - 1)
                fi = idv >> 40
                if off + 256 > fsize[fi]:
                    continue
                mm = mmaps.get(fi)
                if mm is None:
                    mm = mmap.mmap(os.open(files[fi], os.O_RDONLY | getattr(os, "O_BINARY", 0)),
                                   0, access=mmap.ACCESS_READ)
                    mmaps[fi] = mm
                seg = mm[off:off + 256]
                if seg != nb:
                    continue
                p, qq = primes[i], primes[j]
                print("[n-hit] file%s+%#x p=%s.. q=%s.. -> oracle" %
                      (fi, off, hex(p)[:18], hex(qq)[:18]), flush=True)
                hits.append((p, qq, fi, off))
                r = S.try_pair(p, qq, samples)
                if r:
                    print("\n===== RSA 私钥命中 =====")
                    print("p =", hex(r["p"]))
                    print("q =", hex(r["q"]))
                    print("e =", r["e"], " note =", r["sample_note"])
                    print("plain[:160] =", r["plain"][:160])
                    if a.out:
                        json.dump({"n": hex(r["n"]), "e": r["e"], "d": hex(r["d"]),
                                   "p": hex(r["p"]), "q": hex(r["q"]),
                                   "note": r["sample_note"]},
                                  open(a.out, "w"), indent=1)
                        from Crypto.PublicKey import RSA
                        pem = RSA.construct((r["n"], r["e"], r["d"], r["p"], r["q"])).export_key()
                        open(os.path.splitext(a.out)[0] + ".pem", "wb").write(pem)
                    sys.exit(0)
        meta_n.clear()
        cnt = 0

    for i, j in itertools.combinations(range(len(primes)), 2):
        n = pz[i] * pz[j]
        if n.bit_length() != 2048:
            continue
        bk[cnt] = int(n & MASK64)
        meta_i[cnt] = i
        meta_j[cnt] = j
        meta_n.append(n)
        cnt += 1
        if cnt == CHUNK:
            flush()
            print("  %.1fM 对, %.0fs, hits=%d" %
                  (tried / 1e6, time.time() - t0, len(hits)), flush=True)
    flush()
    print("跨区配对完成: %d 对, n 命中 %d, 全部 oracle 未解" % (tried, len(hits)))
    if a.out:
        json.dump([[hex(p), hex(q), fi, hex(off)] for p, q, fi, off in hits],
                  a.out.replace(".json", "_hits.json"), indent=1)
    sys.exit(1)


if __name__ == "__main__":
    main()
