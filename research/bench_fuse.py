# -*- coding: utf-8 -*-
"""合并版 vs 基线 DLL 的标定对比 —— 测的是**真实瓶颈**。

背景（V21 实测）：
  解密 639 块本体 382 ms（已 <1s，纯 Python 算术，与引擎无关）
  标定 639 块      8930 ms（100% 成本集中在这里）
所以「639 块 <1s」能不能达成，**全看标定**。

## 为什么要一库一进程

引擎的 `REGP/RBASE/RSZ`（镜像映射）与 `JT`（跳转表）是**进程级全局**，
`c_engine.load()` 又有进程级单例。同一进程里换 DLL 加载第二份会与之冲突；
而且 `load(dll_path=DLL)` 的默认值在**函数定义时**就绑定了，
改模块变量根本换不掉库 —— V21 第一版 benchmark 因此两次都测了同一个 DLL，
得出「合并无提速」的**假结论**（0.99x）。

修法：父进程按「一库一进程」用 subprocess 隔离，每个子进程只加载一个 DLL。
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENG = os.path.join(HERE, "engine_c")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "deliverables"))

K = bytes(range(0x05, 0x15))


def child(dll_name, nblk, reps):
    """在子进程里跑：加载指定 DLL → 标定 nblk 块 → 打印结果行。"""
    import ctypes
    import c_engine

    c_engine.DLL = os.path.join(ENG, dll_name)
    path = os.path.abspath(c_engine.DLL)
    t0 = time.time()
    c_engine.init(os.path.join(ENG, "image%d.bin" % nblk))
    load_ms = (time.time() - t0) * 1000
    lib = c_engine.load()

    lib.jcy_capture_enable(nblk)
    cap = 16 * nblk + 80
    buf = ctypes.create_string_buffer(cap)
    best = None
    body_ref = None
    ncap = 0
    for _ in range(reps):
        t = time.time()
        rc = lib.jcy_encrypt_ex(K, bytes(16 * nblk), 16 * nblk, buf, cap, 1)
        el = (time.time() - t) * 1000
        if rc <= 0:
            print("RESULT\tERR\trc=%d %s" % (rc, lib.jcy_last_error().decode()))
            return
        ncap = lib.jcy_capture_count()
        body = buf.raw[:rc]
        if body_ref is None:
            body_ref = body
        elif body != body_ref:
            print("RESULT\tERR\t同一 DLL 两次输出不一致")
            return
        if best is None or el < best:
            best = el
    ver = lib.jcy_version().decode()
    print("RESULT\tOK\t%.0f\t%d\t%.0f\t%s\t%s" % (best, ncap, load_ms, ver, path))


def main():
    nblk = int(sys.argv[1]) if len(sys.argv) > 1 else 639
    reps = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    if len(sys.argv) > 3 and sys.argv[3] == "--child":
        return child(sys.argv[4], nblk, reps)

    print("目标: %d 块标定路径（含 x 捕获），每库独立进程，各跑 %d 次取最优\n"
          % (nblk, reps))
    res = {}
    for tag, dll in (("基线(未合并)", "jcy_engine.dll"), ("合并版(--fuse)", "jcy_fuse.dll")):
        if not os.path.exists(os.path.join(ENG, dll)):
            print("%-18s 缺 %s，跳过" % (tag, dll))
            continue
        p = subprocess.run([sys.executable, os.path.abspath(__file__),
                            str(nblk), str(reps), "--child", dll],
                           capture_output=True, cwd=HERE, timeout=3600)
        line = [l for l in p.stdout.decode("utf-8", "replace").splitlines()
                if l.startswith("RESULT")]
        if not line:
            err = p.stderr.decode("utf-8", "replace").strip()[-300:]
            print("%-18s 失败: %s" % (tag, err or "无输出"))
            continue
        f = line[0].split("\t")
        if f[1] != "OK":
            print("%-18s 失败: %s" % (tag, f[2]))
            continue
        ms = float(f[2])
        res[tag] = ms
        print("%-18s 标定 %9.0f ms   捕获 %s 条   镜像加载 %s ms   [%s]"
              % (tag, ms, f[3], f[4], os.path.basename(f[6])))

    if len(res) == 2:
        a = res["基线(未合并)"]
        b = res["合并版(--fuse)"]
        print("\n合并提速: **%.2fx**  (%.0f ms -> %.0f ms)" % (a / b, a, b))
        print("距离 1000 ms 目标: 基线差 %.1fx, 合并版差 %.2fx" % (a / 1000, b / 1000))


if __name__ == "__main__":
    main()