# -*- coding: utf-8 -*-
"""tmp_cover_lengths.py — 泛化采样：不同明文长度 L 的 PC 覆盖（Unicorn, 离线）。

只新建本文件；输出仅写 reports/pc_cover_multi.txt 与 reports/cover_lengths.json。
不修改 gen_engine.py / trace_py_1blk.py / engine_c / 其他 reports。

方法：每个 L 全新 EDecryptor+oracle（避免堆残留），UC_HOOK_CODE 采 PC 偏移集合
     （begin=DEV_BASE,end=DEV_BASE+0x800000），另加 STUBS 区独立 hook 记录命中桩；
     记录 body 长度/前16B、heap_ptr 变化；桩用 e.stub_syms 反查。
L 合法性：明文 pt 长度必须 = _b64len(L) 且为 16 的倍数（E 为 16B 分组密码）。
     任务原表 {1,5,26,100,511,2731} 非法（pt=4/8/36/136/684/3644，非 16 倍数），
     替换为相邻合法值 {11, 24, 34, 96, 514, 2734}；非法原值仍以 probe 模式短超时
     试跑观察管线实际行为；639 块=10224B=_b64len(7666..7668)，补跑 7667。
"""
import gc
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402

from decrypt_e import EDecryptor, _b64len  # noqa: E402
from authgen import DEV_BASE, OFF_PIPE  # noqa: E402
from emu_v11 import STUBS  # noqa: E402

REPORTS = os.path.join(HERE, "reports")
DEADLINE = time.time() + 9.5 * 60          # 预算闸门（仅约束 bonus 大长度）
KNOWN9_IDX = {2, 3, 44, 57, 66, 68, 79, 90, 113}   # C 引擎 main.c 已实现的 9 种桩 idx

# (tag, L)：orig=任务原表合法项；repl=非法项相邻合法替换；probe=非法原值行为探测；bonus=639 块
PLAN = [
    ("orig", 10), ("repl", 11), ("orig", 22), ("orig", 23), ("repl", 24), ("repl", 34),
    ("probe", 1), ("probe", 5), ("probe", 26), ("probe", 100),
    ("repl", 96), ("probe", 511), ("repl", 514),
    ("orig", 1534), ("probe", 2731), ("repl", 2734), ("bonus", 7667),
]
REPL_NOTE = {
    11: "5 非法(pt=8<16B) -> 相邻合法 11(pt=16,1块,SSO)",
    24: "26 非法(pt=36,2.25块) -> 最近合法 24(pt=32,2块)",
    34: "26 非法 -> 另补 34(pt=48,3块,首个新块数)",
    96: "100 非法(pt=136=8.5块) -> 最近合法 96(pt=128,8块)",
    514: "511 非法(pt=684=42.75块) -> 最近合法 514(pt=688,43块)",
    2734: "2731 非法(pt=3644=227.75块) -> 最近合法 2734(pt=3648,228块)",
    7667: "639 块=10224B=_b64len(7666..7668)，任务给的 2731 换算有误，按 639 块意图补 7667",
}


def load_base_union():
    base = set()
    n_all = 0
    with open(os.path.join(REPORTS, "pc_cover_all.txt")) as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                base.add(int(ln, 16))
                n_all += 1
    n1 = len(base)
    with open(os.path.join(REPORTS, "trace_py_1blk.txt")) as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                base.add(int(ln, 16))
    return base, n_all, n1


def load_stub_table():
    with open(os.path.join(REPORTS, "stub_table.json")) as f:
        raw = json.load(f)
    return {(int(a, 16) - STUBS) >> 3: nm for a, nm in raw.items()}


def pages_top10(pcs, topn=10):
    cnt = {}
    for p in pcs:
        pg = p >> 12
        cnt[pg] = cnt.get(pg, 0) + 1
    top = sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))[:topn]
    return [["0x%05x000-0x%05xfff" % (pg, pg), n] for pg, n in top]


def run_L(L, tag, stub_idx2name, t_blk, base):
    """跑单个 L，返回记录 dict。失败记录 error 继续。"""
    rec = {"L": L, "tag": tag, "error": None}
    pcs = set()
    stubs = set()
    d = None
    try:
        pt_len = _b64len(L)
        rec["pt_len"] = pt_len
        rec["blocks"] = pt_len // 16 if pt_len % 16 == 0 else None
        t0 = time.time()
        d = EDecryptor()
        d._oracle()
        o = d._o
        s = o.s
        e = s.e
        uc = e.uc
        rec["boot_s"] = round(time.time() - t0, 2)

        def cb(u_, a, sz, ud):
            pcs.add(a - DEV_BASE)

        def scb(u_, a, sz, ud):
            stubs.add(a)

        uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=DEV_BASE, end=DEV_BASE + 0x800000)
        uc.hook_add(unicorn.UC_HOOK_CODE, scb, begin=STUBS, end=STUBS + 0x10000)

        K = bytes(range(0x05, 0x15))
        iv = K[::-1]
        e.fix_long_string(0x688130, K)
        e.fix_long_string(0x688148, iv)
        hp0 = e.heap_ptr
        s._cur[0] = bytes(pt_len)              # 全零明文，长度必须 = _b64len(L)
        s._out.clear()
        inp = e.mkstr(b"\x00" * L)             # L<=22 libc++ SSO 内联, >22 堆
        timeout = 600_000_000 if pt_len % 16 == 0 else 90_000_000
        t1 = time.time()
        e.call(DEV_BASE + OFF_PIPE, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=s.sret, timeout=timeout)
        rec["run_s"] = round(time.time() - t1, 2)
        body = s._out.get("body", b"")
        rec["body_len"] = len(body)
        rec["body16"] = body[:16].hex()
        rec["heap_delta"] = e.heap_ptr - hp0
        rec["pc_count"] = len(pcs)
        names = ["%s@%d" % (stub_idx2name.get((a - STUBS) >> 3, "?"), (a - STUBS) >> 3)
                 for a in stubs]
        rec["stubs_hit"] = sorted(names)
        rec["stubs_beyond_known9"] = sorted(
            n for n in names if int(n.rsplit("@", 1)[1]) not in KNOWN9_IDX)
        if rec["blocks"]:
            t_blk[0] = max(t_blk[0] or 0.0, rec["run_s"] / rec["blocks"])
        rec["_pcs"] = pcs
        if L == 23:
            rec["_dis_new"] = pcs - base       # capstone 样本（首个堆串长度）
    except Exception as ex:  # noqa: BLE001 — 单 L 失败必须记录并继续
        rec["error"] = "%s: %s" % (type(ex).__name__, ex)
        rec["_pcs"] = pcs
    finally:
        d = None
        gc.collect()
    return rec


def build_summary(base, union_all, union_legal, recs):
    le22, gt22 = set(), set()
    for r in recs:
        if r.get("error") or not r.get("_pcs"):
            continue
        pt = r.get("pt_len", 0)
        if r["L"] <= 22:
            le22 |= r["_pcs"]
        elif pt % 16 == 0:
            gt22 |= r["_pcs"]
    sso = {}
    if le22 or gt22:
        le22_only = le22 - gt22
        gt22_only = gt22 - le22
        gt22_new = gt22 - base
        sso = {
            "le22_union": len(le22), "gt22_union": len(gt22),
            "le22_only_vs_gt22": len(le22_only), "gt22_only_vs_le22": len(gt22_only),
            "le22_only_pages_top10": pages_top10(le22_only),
            "gt22_only_pages_top10": pages_top10(gt22_only),
            "gt22_new_vs_base": len(gt22_new),
            "gt22_new_pages_top10": pages_top10(gt22_new),
        }
    linear = [{"L": r["L"], "blocks": r["blocks"], "new_vs_base": r["new_vs_base"]}
              for r in recs
              if not r.get("error") and r.get("blocks") and r["blocks"] >= 3]
    return {
        "base_union_size": len(base),
        "runs": [{k: v for k, v in r.items() if not k.startswith("_")} for r in recs],
        "sso": sso,
        "linear_new_vs_base": linear,
        "union_total": len(union_all),
        "union_legal_total": len(union_legal),
        "delta_vs_base_pct": round((len(union_all) - len(base)) / max(len(base), 1) * 100, 3),
        "delta_vs_24984_pct": round((len(union_all) - 24984) / 24984 * 100, 3),
        "stubs_beyond_known9_union": sorted(
            {n for r in recs for n in r.get("stubs_beyond_known9", [])}),
    }


def _so_offsets():
    so = os.path.join(HERE, "artifacts", "libcore.so")
    data = open(so, "rb").read()
    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from("<I", data, off)
        if p_type != 1:
            continue
        p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<QQQQ", data, off + 8)
        segs.append((p_vaddr, p_offset, p_filesz))
    return data, segs


def disasm_context(recs, n_ctx=6):
    try:
        import capstone
    except ImportError:
        print("capstone 不可用，跳过反汇编辅助")
        return
    tgt = None
    for r in recs:
        if r.get("_dis_new"):
            tgt = r["_dis_new"]
            break
    if not tgt:
        print("（无 L=23 新 PC 可反汇编）")
        return
    data, segs = _so_offsets()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    def rd(off, n=28):
        for vaddr, poff, filesz in segs:
            if vaddr <= off < vaddr + filesz:
                return data[poff + (off - vaddr):poff + (off - vaddr) + n]
        return b""

    by_pg = {}
    for p in tgt:
        by_pg.setdefault(p >> 12, []).append(p)
    print("---- capstone 反汇编（L=23 相对 base 新增 PC 样本, 最多 %d 页, 每页 1 个）----" % n_ctx)
    for pg in sorted(by_pg, key=lambda g: (-len(by_pg[g]), g))[:n_ctx]:
        p = sorted(by_pg[pg])[0]
        print("PC 0x%06x (页 0x%05x000, 该页新 PC %d 个):" % (p, pg, len(by_pg[pg])))
        for ins in md.disasm(rd(p & ~3), p & ~3):
            print("   +0x%02x  %-8s %s" % (ins.address - (p & ~3), ins.mnemonic, ins.op_str))
        print()


def main():
    t_start = time.time()
    base, n_all_lines, n_all_uniq = load_base_union()
    stub_idx2name = load_stub_table()
    print("base_union: pc_cover_all 行=%d 唯一=%d, +trace_py_1blk 去重后=%d"
          % (n_all_lines, n_all_uniq, len(base)), flush=True)
    t_blk = [None]
    union_all = set()
    union_legal = set()
    recs = []
    out_json = os.path.join(REPORTS, "cover_lengths.json")
    out_txt = os.path.join(REPORTS, "pc_cover_multi.txt")

    def flush_files():
        with open(out_txt, "w") as f:
            f.write("\n".join(hex(p) for p in sorted(union_all)))
            if union_all:
                f.write("\n")
        with open(out_json, "w") as f:
            json.dump(build_summary(base, union_all, union_legal, recs),
                      f, ensure_ascii=False, indent=1)

    for tag, L in PLAN:
        if tag == "bonus" and t_blk[0]:
            proj = t_blk[0] * (_b64len(L) / 16) + 15
            if time.time() + proj > DEADLINE:
                recs.append({"L": L, "tag": tag, "pt_len": _b64len(L), "blocks": _b64len(L) // 16,
                             "error": "SKIPPED_BUDGET 预计 %.0fs 超预算闸门" % proj,
                             "repl_note": REPL_NOTE.get(L)})
                print("[L=%5d %-5s] SKIP 预算 (预计 %.0fs)" % (L, tag, proj), flush=True)
                continue
        rec = run_L(L, tag, stub_idx2name, t_blk, base)
        pcs = rec.get("_pcs") or set()
        rec["new_vs_base"] = len(pcs - base)
        rec["new_pages_top10"] = pages_top10(pcs - base)
        rec["repl_note"] = REPL_NOTE.get(L)
        recs.append(rec)
        union_all |= pcs
        if rec.get("blocks"):
            union_legal |= pcs
        print("[L=%5d %-5s] pt=%-5d blk=%-4s pcs=%-6d new=%-5d body=%-5d hpD=%-7d run=%.1fs %s"
              % (L, tag, rec.get("pt_len", -1), rec.get("blocks"), rec.get("pc_count", 0),
                 rec.get("new_vs_base", 0), rec.get("body_len", -1), rec.get("heap_delta", -1),
                 rec.get("run_s", 0.0), ("ERR " + rec["error"]) if rec["error"] else ""), flush=True)
        flush_files()

    disasm_context(recs)
    summ = build_summary(base, union_all, union_legal, recs)
    summ["wall_s"] = round(time.time() - t_start, 1)
    with open(out_json, "w") as f:
        json.dump(summ, f, ensure_ascii=False, indent=1)
    print("DONE wall=%.1fs union=%d legal=%d → pc_cover_multi.txt / cover_lengths.json"
          % (summ["wall_s"], summ["union_total"], summ["union_legal_total"]), flush=True)


if __name__ == "__main__":
    main()
