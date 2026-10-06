# -*- coding: utf-8 -*-
"""probe_c_state.py — 为 C 引擎准备预运行镜像 + 统计桩命中 + 全量 golden.

两个独立周期 (各自全新 boot):
  A: NBLK=1   → engine_c/image1.bin + meta1.json + golden1.json
  B: NBLK=128 → engine_c/image128.bin + meta128.json + golden128.json + reports/stubs_hit.json
"""
import os
import sys
import json
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from decrypt_e import EDecryptor, _b64len  # noqa: E402
from authgen import DEV_BASE, OFF_PIPE  # noqa: E402

STUBS = 0x60000000


def cycle(nblk, tag, log_stubs):
    d = EDecryptor()
    d._oracle()
    o = d._o
    s = o.s
    e = s.e
    uc = e.uc

    K = bytes(range(0x05, 0x15))
    iv = K[::-1]
    PT = bytes(16 * nblk)

    stub_hits = {}

    def on_stub(u_, a, sz, ud):
        nm = e.stub_syms.get(a)
        if nm:
            stub_hits[nm] = stub_hits.get(nm, 0) + 1

    hk = uc.hook_add(unicorn.UC_HOOK_CODE, on_stub, begin=STUBS, end=STUBS + 0x10000)

    # ---- 输入装配 (预运行态) ----
    e.fix_long_string(0x688130, K)
    e.fix_long_string(0x688148, iv)
    L = next(c for c in range(1, len(PT) + 1) if _b64len(c) == len(PT))
    s._cur[0] = PT
    s._out.clear()
    inp = e.mkstr(b"\x00" * L)
    sret = s.sret
    heap0 = e.heap_ptr

    # ---- 预运行镜像 dump ----
    outp = os.path.join(HERE, "engine_c", "image%s.bin" % tag)
    regions = [(r[0], r[1]) for r in uc.mem_regions()]
    with open(outp, "wb") as f:
        f.write(struct.pack("<I", len(regions)))
        for lo, hi in regions:
            size = hi - lo + 1
            f.write(struct.pack("<QQ", lo, size))
            f.write(uc.mem_read(lo, size))
    meta = {
        "inp": inp, "sret": sret, "L": L, "nblk": nblk,
        "heap_ptr": heap0, "K": K.hex(), "iv": iv.hex(),
        "OFF_PIPE": OFF_PIPE,
        "sp0": 0x70000000 + 0x200000 - 0x10000,
        "magic": 0x900000, "tls": 0x61000000, "canary": "0x5EED5EEDCAFEF00D",
    }
    json.dump(meta, open(os.path.join(HERE, "engine_c", "meta%s.json" % tag), "w"), indent=1)
    print("[%s] inp=0x%x sret=0x%x L=%d heap0=0x%x 镜像 %.1f MB → %s"
          % (tag, inp, sret, L, heap0,
             sum(h - l + 1 for l, h in regions) / 1048576, outp), flush=True)

    # ---- 运行 (与 _enc_big 相同的手工 call) ----
    body = s._out.get("body", b"")
    e.call(DEV_BASE + OFF_PIPE,
           (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
           sret=sret, timeout=600_000_000)
    body = s._out.get("body", b"")
    uc.hook_del(hk)
    heap1 = e.heap_ptr
    print("[%s] body %d B 前32: %s" % (tag, len(body), body[:32].hex()))
    print("[%s] heap: 0x%x → 0x%x (+%d B)" % (tag, heap0, heap1, heap1 - heap0))
    json.dump({"tag": tag, "nblk": nblk, "body_hex": body.hex(),
               "heap0": heap0, "heap1": heap1, "inp": inp, "sret": sret, "L": L},
              open(os.path.join(HERE, "reports", "golden%s.json" % tag), "w"), indent=1)
    return stub_hits, body


hits1, body1 = cycle(1, "1", True)
hits128, body128 = cycle(128, "128", True)

# 128 周期命中应是 1 周期的超集 (同代码路径更多迭代)
merged = dict(hits1)
for k, v in hits128.items():
    merged[k] = merged.get(k, 0) + v
print("桩命中 (%d 种):" % len(merged))
for nm, c in sorted(merged.items(), key=lambda kv: -kv[1]):
    print("  %-28s %d" % (nm, c))
miss = set(hits1) - set(hits128)
if miss:
    print("!! 1 周期独有桩: %s" % miss)
json.dump({nm: {"addr": hex(a), "n": 0} for nm, a in []},
          open(os.devnull, "w"))
# 存 命中桩的地址映射 (C 桩分发用 idx)
e_stub_addr = {}
json.dump({nm: c for nm, c in merged.items()},
          open(os.path.join(HERE, "reports", "stubs_hit.json"), "w"), indent=1)
print("→ reports/stubs_hit.json")
