# -*- coding: utf-8 -*-
"""gen_ref_trace.py — 用 Unicorn 重跑 NBLK=1, 产出与 goldenN 同一次运行的
逐指令 trace (so 内偏移), 供 C 引擎逐条对拍.

背景: reports/trace_py_1blk.txt 是历史文件, 与当前 golden1.json 不是同一次
运行 (在 idx 252879 上走向就不同), 不能直接当对拍基准. 本脚本与
probe_c_state.py 的 cycle(1,"1") 走完全相同的装配路径, 保证基准一致.

用法: py -3.12 gen_ref_trace.py [nblk] [outfile]
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from decrypt_e import EDecryptor, _b64len  # noqa: E402
from authgen import DEV_BASE, OFF_PIPE  # noqa: E402

DB = DEV_BASE


def main():
    nblk = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    outp = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        HERE, "reports", "ref_trace_%dblk.txt" % nblk)

    d = EDecryptor()
    d._oracle()
    o = d._o
    s = o.s
    e = s.e
    uc = e.uc

    K = bytes(range(0x05, 0x15))
    iv = K[::-1]
    PT = bytes(16 * nblk)

    e.fix_long_string(0x688130, K)
    e.fix_long_string(0x688148, iv)
    L = next(c for c in range(1, len(PT) + 1) if _b64len(c) == len(PT))
    s._cur[0] = PT
    s._out.clear()
    inp = e.mkstr(b"\x00" * L)
    sret = s.sret

    # hook 范围必须与 C 引擎 cover 同域: so 段映射是 0x400024a00000 起 0x800000
    # (镜像 8 个区域里 so 段 size=0x800000). 用 0x800000 才是全量, 少一段会
    # 漏记 so 高段 PC, 导致对拍时基准与 C 侧错位 (曾因此误判 idx 1085 为发散点).
    lo = DB + 0x0
    hi = DB + 0x800000
    trc = []

    def on_code(u_, addr, sz, ud):
        if lo <= addr < hi:
            trc.append(addr - DB)

    hk = uc.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=lo, end=hi)
    e.call(DEV_BASE + OFF_PIPE,
           (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
           sret=sret, timeout=900_000_000)
    uc.hook_del(hk)

    body = s._out.get("body", b"")
    with open(outp, "w") as f:
        f.write("\n".join("0x%x" % t for t in trc))
    print("trace %d 条 → %s" % (len(trc), outp))
    print("body %d 字节 前32: %s" % (len(body), body[:32].hex()))

    # 与既有 golden 对拍, 确认这是同一次基线
    gp = os.path.join(HERE, "reports", "golden%d.json" % nblk)
    if os.path.exists(gp):
        import json
        g = json.load(open(gp, encoding="utf-8"))
        want = bytes.fromhex(g["body_hex"])
        print("与 golden%d 比: %s" % (nblk, "一致 ✓" if body == want else "不一致 ✗"))


if __name__ == "__main__":
    main()
