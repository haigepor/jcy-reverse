# -*- coding: utf-8 -*-
"""bench_o1.py — 对比 -O2 与 -O1-fno-gcse 融合引擎的 639 块耗时。

V22 背景: 之前 "-O1 编译 40 分钟超时" 是**编译错了文件**(jcy_engine.c,
103,828 行未融合版)。正确目标是 jcy_engine_fuse.c(4,401 基本块),
-O1 -fno-gcse 实测 8 分 16 秒编译成功, 产物体积 5.71MB -> 3.46MB(-39%)。
本脚本测它到底快不快, 并**逐位校验 body 没变**。
"""
import ctypes, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from c_engine import load, unload

ENG = os.path.join(HERE, "engine_c")
K = bytes(range(0x05, 0x15))

def run(dll, nblk=639, reps=3):
    load(dll)
    lib = load()
    assert os.path.abspath(lib._name) == os.path.abspath(dll), \
        "加载了错误的 DLL: %s != %s" % (lib._name, dll)
    img = os.path.abspath(os.path.join(ENG, "image639.bin"))
    if not getattr(run, "_inited", False):
        rc = lib.jcy_init(img.encode())
        assert rc == 0, lib.jcy_last_error().decode()
        run._inited = True
    pt = open(os.path.join(ENG, "pt639.bin"), "rb").read()
    best = None; body = None
    for _ in range(reps):
        rc = lib.jcy_capture_enable(nblk)
        assert rc == 0, lib.jcy_last_error().decode()
        outcap = len(pt) + 16 + 64
        buf = ctypes.create_string_buffer(outcap)
        t0 = time.time()
        n = lib.jcy_encrypt_ex(K, pt, len(pt), buf, outcap, 1)
        dt = (time.time() - t0) * 1000
        assert n > 0, lib.jcy_last_error().decode()
        if best is None or dt < best:
            best = dt; body = bytes(buf.raw[:n])
    return best, body

res = {}
for tag, dll in (("O2 (基线)", "jcy_fuse.dll"), ("O1 -fno-gcse", "jcy_fuse_o1.dll")):
    p = os.path.join(ENG, dll)
    if not os.path.exists(p):
        print("%-16s 缺 %s" % (tag, dll)); continue
    try:
        t, b = run(p)
    except AssertionError as e:
        print("%-16s 失败: %s" % (tag, e)); continue
    res[tag] = (t, b)
    print("%-16s 639 块: %8.1f ms   body %d 字节  首16=%s"
          % (tag, t, len(b), b[:16].hex()))
    run._inited = False
    unload()

if len(res) == 2:
    (t1,b1), (t2,b2) = res["O2 (基线)"], res["O1 -fno-gcse"]
    print()
    print("body 逐位一致: %s" % (b1 == b2))
    print("加速: %.3fx  (节省 %.1f ms)" % (t1/t2 if t2 else 0, t1-t2))
