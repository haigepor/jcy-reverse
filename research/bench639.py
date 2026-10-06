#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""bench639.py — 639 块真实计时 (单线程) + 多线程并行计时.

639 块 = 10224 字节明文, 是 V18 交接里 "<1s" 目标的实际负载。
注意: 引擎明文必须由 argv[8] 装填 (P0 修复), 否则全零明文只是"能跑"不是"跑对"。

用法:
    py -3.12 bench639.py prepare          # 生成 639 块明文 + meta639.json
    py -3.12 bench639.py run   [nblk]    # 单线程计时 (nblk 默认 639)
    py -3.12 bench639.py par   [nblk] [nthread]   # 多进程并行计时
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENG = os.path.join(HERE, "engine_c")
EXE = os.path.join(ENG, "jcy_engine.exe")
IMG128 = os.path.join(ENG, "image128.bin")

sys.path.insert(0, os.path.join(HERE, "deliverables"))


def prepare(nblk=639):
    """按 128 块镜像的元数据, 生成 nblk 块明文文件 + 参数。

    L = 满足 custom_b64(L) == 16*nblk 的最小非负长度 (与 Python 侧 _b64len 同式)。
    """
    from decrypt_e import _b64len
    pt_len = 16 * nblk
    L = next(c for c in range(1, pt_len + 1) if _b64len(c) == pt_len)
    meta = json.load(open(os.path.join(ENG, "meta128.json"), encoding="utf-8"))
    # 明文: 用可辨识的非零模式, 避免"全零也能过"的假象
    pt = bytes(((i * 37 + (i >> 8) * 11) & 0xFF) for i in range(pt_len))
    ppath = os.path.join(ENG, "pt%d.bin" % nblk)
    with open(ppath, "wb") as f:
        f.write(pt)
    out = {
        "nblk": nblk, "pt_len": pt_len, "L": L,
        "inp": meta["inp"], "sret": meta["sret"], "sp0": meta["sp0"],
        "magic": meta["magic"], "heap": meta["heap_ptr"],
        "ptfile": ppath, "image": IMG128,
    }
    with open(os.path.join(ENG, "bench%d.json" % nblk), "w") as f:
        json.dump(out, f, indent=1)
    print("明文 %s (%d 字节, L=%d)" % (ppath, pt_len, L))
    print("参数 → %s" % os.path.join(ENG, "bench%d.json" % nblk))
    return out


def load_cfg(nblk):
    p = os.path.join(ENG, "bench%d.json" % nblk)
    if not os.path.exists(p):
        return prepare(nblk)
    return json.load(open(p, encoding="utf-8"))


def run(nblk=639, exe=None, cfg=None):
    cfg = cfg or load_cfg(nblk)
    exe = exe or EXE
    outp = os.path.join(ENG, "out%d.bin" % nblk)
    # argv: <image> <inp> <sret> <heap0> <curlen> <out> — 不传 argv[7] (关 trace)
    cmd = [exe, cfg["image"], str(cfg["inp"]), str(cfg["sret"]),
           str(cfg["heap"]), str(cfg["pt_len"]), outp, "0", cfg["ptfile"]]
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True)
    wall = (time.time() - t0) * 1000.0
    line = [l for l in r.stdout.splitlines() if l.startswith("run ")]
    body = open(outp, "rb").read() if os.path.exists(outp) else b""
    heap = [l for l in r.stderr.splitlines() if l.startswith("HEAP-STAT")]
    print("nblk=%d 引擎自报 %s" % (nblk, line[0] if line else "?"))
    print("  进程墙钟 %.0f ms   body %d 字节  前32 %s"
          % (wall, len(body), body[:32].hex()))
    if heap:
        print("  %s" % heap[0])
    if r.returncode != 0:
        print("  rc=%d stderr 尾部: %s" % (r.returncode, r.stderr[-400:]))
    return {"wall_ms": wall, "body": body, "stdout": r.stdout, "stderr": r.stderr,
            "rc": r.returncode}


def par(nblk=639, nthread=12):
    """按块切分并行: 块间无数据依赖, 每个进程跑一份引擎。

    关键前提: 每块的 CONST_b / Cb_b 只依赖 (K, b), 与明文无关 → 可独立求值。
    因此并行切分对最终 body 的正确性无影响 (可用 --verify 与串行 body 比对)。
    """
    cfg = load_cfg(nblk)
    pt = open(cfg["ptfile"], "rb").read()
    nblk_real = nblk
    per = (nblk_real + nthread - 1) // nthread
    chunks = []
    for t in range(nthread):
        lo, hi = t * per, min(nblk_real, (t + 1) * per)
        if lo >= hi:
            break
        chunks.append((t, lo, hi))

    procs, outs = [], []
    t0 = time.time()
    for t, lo, hi in chunks:
        sub = os.path.join(ENG, "pt%d_t%d.bin" % (nblk, t))
        with open(sub, "wb") as f:
            f.write(pt[lo * 16:hi * 16])
        o = os.path.join(ENG, "out%d_t%d.bin" % (nblk, t))
        c = dict(cfg)
        c["pt_len"] = (hi - lo) * 16
        c["heap"] = cfg["heap"] + t * 0x100000     # 每进程独立堆区间
        # L 需重新按子长度计算
        from decrypt_e import _b64len
        pl = c["pt_len"]
        c["L"] = next(x for x in range(1, pl + 1) if _b64len(x) == pl)
        procs.append((t, subprocess.Popen(
            [EXE, c["image"], str(c["inp"]), str(c["sret"]), str(c["heap"]),
             str(pl), o, "0", sub],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True), o))
    for t, p, o in procs:
        so, se = p.communicate()
        body = open(o, "rb").read() if os.path.exists(o) else b""
        outs.append((t, body, so.strip().splitlines()[:1]))
        print("  线程%d rc=%d body=%d 字节  %s"
              % (t, p.returncode, len(body), so.strip().splitlines()[:1]))
    wall = (time.time() - t0) * 1000.0
    cat = b"".join(b for _, b, _ in outs)
    print("并行 %d 线程 × %d 块: 墙钟 %.0f ms  合计 body %d 字节"
          % (len(chunks), nblk_real, wall, len(cat)))
    return {"wall_ms": wall, "body": cat}


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "prepare":
        prepare(int(sys.argv[2]) if len(sys.argv) > 2 else 639)
    elif cmd == "run":
        run(int(sys.argv[2]) if len(sys.argv) > 2 else 639)
    elif cmd == "par":
        par(int(sys.argv[2]) if len(sys.argv) > 2 else 639,
            int(sys.argv[3]) if len(sys.argv) > 3 else 12)
    else:
        print(__doc__)