#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""dump_image639.py — 为 N 块(默认 639)生成专用镜像 + golden.

为什么不能直接用image128.bin 跑 639 块:
  1) 管线输入串长度 L 与块数绑定( custom_b64(L) == 16*nblk ).
     128 块 L=1534, 639 块 L=7666 —— 读到的串长度不同。
  2) image128.bin 是在一次 128 块运行**之后** dump 的, 堆上 2.1MB 是那次运行
     留下的垃圾; 直接喂 639 块会把这些垃圾当成输入串的一部分。
  所以必须: 装配好输入 → dump 镜像 → 再跑 (顺序与 gen_ref_trace.py 一致)。

同时产出 golden(N 块 body) 供差分。

用法: py -3.12 dump_image639.py [nblk]
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import EDecryptor, _b64len   # noqa: E402
from authgen import DEV_BASE                 # noqa: E402

ENG = os.path.join(HERE, "engine_c")


def main():
    nblk = int(sys.argv[1]) if len(sys.argv) > 1 else 639
    K = bytes(range(0x05, 0x15))
    iv = K[::-1]
    # 可辨识的非零明文(全零会让"没装填"与"装填了零"无法区分)
    PT = bytes(((i * 37 + (i >> 8) * 11) & 0xFF) for i in range(16 * nblk))
    L = next(c for c in range(1, len(PT) + 1) if _b64len(c) == len(PT))

    d = EDecryptor()
    d._oracle()
    s = d._o.s
    e = s.e

    e.fix_long_string(0x688130, K)
    e.fix_long_string(0x688148, iv)
    s._cur[0] = PT
    s._out.clear()
    inp = e.mkstr(b"\x00" * L)
    sret = s.sret

    # 校验输入串确实是 L 个零 (L>22 → 长字符串 {cap,len,data}, data 在 +16)
    rec = e.rd(inp, 24)
    cap, ln, data = struct.unpack("<QQQ", rec)
    assert ln == L and cap == (L + 1) | 1, "string 头不符: cap=%d len=%d" % (cap, ln)
    chk = e.rd(data, L)
    assert chk == b"\x00" * L, "inp 串不是全零: %r" % chk[:16]

    # ---- dump 镜像(运行之前) ----
    regions = [(r[0], r[1]) for r in e.uc.mem_regions()]
    img = os.path.join(ENG, "image%d.bin" % nblk)
    with open(img, "wb") as f:
        f.write(struct.pack("<I", len(regions)))
        for lo, hi in regions:
            size = hi - lo + 1
            f.write(struct.pack("<QQ", lo, size))
            f.write(e.uc.mem_read(lo, size))
    print("镜像 %d 区 %.1f MB → %s" % (len(regions),
          sum(h - l + 1 for l, h in regions) / 1048576, img))

    # heap_ptr 必须从"输入装配完成后"的位置起算, 否则 C 侧会覆盖 inp
    heap_ptr = e.heap_ptr
    meta = {"nblk": nblk, "L": L, "inp": inp, "sret": sret, "heap_ptr": heap_ptr,
            "pt_len": len(PT), "K": K.hex(), "iv": iv.hex(),
            "sp0": 0x701F0000, "magic": 0x900000, "tls": 0x61000000,
            "canary": "0x5EED5EEDCAFEF00D", "image": img}
    with open(os.path.join(ENG, "meta%d.json" % nblk), "w") as f:
        json.dump(meta, f, indent=1)
    ptp = os.path.join(ENG, "pt%d.bin" % nblk)
    open(ptp, "wb").write(PT)
    print("meta → meta%d.json   明文 → %s (%d 字节)" % (nblk, ptp, len(PT)))
    print("inp=0x%x sret=0x%x heap=0x%x L=%d" % (inp, sret, heap_ptr, L))

    # ---- golden: Unicorn 跑一次, 记body ----
    d._cap.clear()
    body = d._enc_big(PT, K, iv, timeout=3_000_000_000)
    gp = os.path.join(HERE, "reports", "golden%d.json" % nblk)
    with open(gp, "w") as f:
        json.dump({"nblk": nblk, "body_hex": body.hex(), "L": L}, f)
    print("golden body %d 字节 前32 %s → %s" % (len(body), body[:32].hex(), gp))
    assert len(body) == 16 * nblk, "body 长度异常 %d" % len(body)


if __name__ == "__main__":
    main()