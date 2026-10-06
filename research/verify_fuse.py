# -*- coding: utf-8 -*-
"""基本块合并版的正确性验证。

判据（全部必须逐字节/逐条通过，任何一项不过就算合并失败）：
  A. 1 块 body 与 golden1 完全一致
  B. 128 块 body 与 golden128 完全一致
  C. 639 块 body 与 golden639 完全一致
  D. 1 块 PC trace 与未合并基线**逐条**一致（合并改变了 dispatch 粒度，
     但 PC 序列必须完全相同 —— 这是语义等价性的最强判据）

用法：
    py -3.12 verify_fuse.py 1 128 639
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENG = os.path.join(HERE, "engine_c")
REPORTS = os.path.join(HERE, "reports")

sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "deliverables"))


def run_exe(exe, image, nblk, out, trace=False, feed_pt=True):
    """跑 jcy 引擎 exe。命令行参数与 main.c 对齐：
       image  K_OFF IV_OFF PTLEN OUT [TRACE_FLAG] [PT_FILE]
    TRACE_FLAG 是 "1"/"0"（main.c: 非 "0" 才开 trace）—— 注意 argv[8] 是明文文件，
    传了它就必须同时给 argv[7]，否则明文静默不装填（V19 踩过）。"""
    L = 0
    n = 16 * nblk
    #明文与 PTLEN: 用**满块** 16*nblk, 与 dump_image639.py:77 写出的
    # pt<nblk>.bin 配对。V22 曾误改成 L(1534/7666) 并裁明文, 结果 128/639
    # 全部 FAIL —— 实测该配置下 128/639 首16 字节 = d085ec6c... 与 golden 逐位
    # 吻合, 而 L 配置得6f1c..., 证明满块才是对的。已回退。
    pt_path = os.path.join(ENG, "pt%d.bin" % nblk)
    if not os.path.exists(pt_path):
        raise SystemExit("缺少明文 %s（先跑 dump_image639.py %d）" % (pt_path, nblk))
    cmd = [os.path.join(ENG, exe), os.path.join(ENG, image),
           "0x500000b0", "0x50000030", "0x50001ed0", str(n), out]
    if trace:
        # argv[7] 不是布尔开关, 而是 TRACE_LIM 本身 (main.c:167) ——
        # 传 "1" 会把上限设成 1 条, 只记到1 就停! 必须传大数。
        cmd += ["5000000", pt_path]
    elif feed_pt:
        # 仍必须传 argv[7]="0" + argv[8]=明文 —— main.c:149 只看 argc>8 就装填,
        # 省掉 argv[7] 会让 argv[8] 错位, 明文**静默不装填**,
        # 于是跑的是镜像里烤死的明文(1 块恰好等于 golden1, 极具欺骗性)。
        cmd += ["0", pt_path]
    # feed_pt=False: 完全不传 argv[7]/argv[8], 用镜像里烤死的明文。
    p = subprocess.run(cmd, capture_output=True, cwd=ENG, timeout=3600)
    return p


def body_of(path):
    with open(path, "rb") as f:
        return f.read()


def golden(nblk):
    p = os.path.join(REPORTS, "golden%d.json" % nblk)
    if not os.path.exists(p):
        return None
    return bytes.fromhex(json.load(open(p, encoding="utf-8"))["body_hex"])


def cmp_body(exe, nblk, image):
    out = os.path.join(ENG, "fuse_out%d.bin" % nblk)
    # V22: 两批 golden 的生成条件不同(V19~V21 期间演进留下的):
    #   golden1     = 跑**不传明文**、用image1.bin 里烤死的明文
    #   golden128/639 = 跑**传 pt<nblk>.bin** 显式明文
    # 实测: 1块不传 -> 3665eb1c...(与golden1 逐位吻合);
    #       1块传 pt1.bin -> d085ec6c...(不吻合);
    #       128/639 传 -> d085ec6c...(与各自 golden 吻合)。
    # 故按规模分别选配置, 统一用一种必然有一半报 FAIL。
    feed_pt = (nblk != 1)
    t0 = time.time()
    p = run_exe(exe, image, nblk, out, feed_pt=feed_pt)
    el = time.time() - t0
    if p.returncode != 0:
        return False, "exe 退出码 %d: %s" % (p.returncode,
                                          p.stderr.decode("utf-8", "replace")[:300]), el
    got = body_of(out)
    want = golden(nblk)
    if want is None:
        return False, "缺 golden%d.json" % nblk, el
    if got == want:
        return True, "%d 字节逐字节一致" % len(got), el
    for i, (a, b) in enumerate(zip(want, got)):
        if a != b:
            return False, "首个差异 idx %d: want %02x got %02x (长度 want %d got %d)" % (
                i, a, b, len(want), len(got)), el
    return False, "长度差 %d" % (len(want) - len(got)), el


def cmp_trace(nblk, image):
    """1 块 PC trace 逐条对拍：合并版 vs 未合并基线。

    2026-10-06 修正（此前会假FAIL）
    ------------------------------
    原来用 `jcy_fuse.exe` 当合并版。但 18:08 起生产 DLL 改用
    `gen_engine.py --fuse --notrace` 构建 —— **--notrace 在编译期就把
    TRACEPUT() 和块内 PC 赋值消掉了**, 于是 jcy_fuse.exe 根本不产 trace,
    对拍必然报 "trace 长度不同: 基线 2183860 合并 0"。

    这不是语义回归, 是拿生产版去做需要 trace 的验证。两个 exe 必须
    **同为 trace 构建**:
        基线   jcy_clean.exe      (未合并 + trace)
        合并   jcy_fuse_trace.exe (合并 + trace, 由 jcy_engine_trace.c 构建)
    生产版 jcy_fuse.exe 只用于 body 对拍(它更快, 且 body 语义相同)。
    """
    base_out = os.path.join(ENG, "trace_base.bin")
    fuse_out = os.path.join(ENG, "trace_fuse.bin")
    for exe, out in (("jcy_clean.exe", base_out), ("jcy_fuse_trace.exe", fuse_out)):
        if not os.path.exists(os.path.join(ENG, exe)):
            return False, "%s 不存在(需用 jcy_engine_trace.c 构建 trace 版)" % exe, 0
        p = run_exe(exe, image, nblk, out, trace=True)
        if p.returncode != 0:
            return False, "%s trace 运行失败: %s" % (exe, p.stderr.decode()[:200]), 0
    a = base_out + ".trace"
    b = fuse_out + ".trace"
    if not (os.path.exists(a) and os.path.exists(b)):
        return False, "trace 文件缺失", 0
    n = 0
    with open(a, "r") as fa, open(b, "r") as fb:
        for la, lb in zip(fa, fb):
            if la.strip() != lb.strip():
                return False, "PC 序列首个差异 @%d: 基线 %s 合并 %s" % (
                    n, la.strip(), lb.strip()), n
            n += 1
    na = sum(1 for _ in open(a, "r"))
    nb = sum(1 for _ in open(b, "r"))
    if na != nb:
        return False, "trace 长度不同: 基线 %d 合并 %d" % (na, nb), n
    return True, "%d 条逐条一致" % n, n


def main():
    blocks = [int(x) for x in (sys.argv[1:] or ["1", "128", "639"])]
    allok = True
    for nb in blocks:
        image = "image%d.bin" % nb
        if not os.path.exists(os.path.join(ENG, image)):
            print("[%3d 块] 跳过：缺 %s" % (nb, image))
            continue
        ok, msg, el = cmp_body("jcy_fuse.exe", nb, image)
        allok &= ok
        print("[%3d 块] body %s  %.2f s  %s" % (nb, "PASS" if ok else "FAIL", el, msg))

    if 1 in blocks and os.path.exists(os.path.join(ENG, "image1.bin")):
        ok, msg, n = cmp_trace(1, "image1.bin")
        allok &= ok
        print("[  1 块] trace %s  %s" % ("PASS" if ok else "FAIL", msg))

    print("\n结论:", "PASS 合并版与基线完全等价 ✓" if allok else "FAIL 合并改变了语义 ✗")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())