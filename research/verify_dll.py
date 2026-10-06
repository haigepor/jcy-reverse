#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""verify_dll.py — DLL 后端与 golden 的全量差分 + 639 块真实计时 (含多线程).

三条验证线:
  1. 128 块: DLL encrypt() vs reports/golden128.json 逐字节
  2. 639 块: DLL encrypt() vs reports/golden639.json 逐字节 (单线程计时)
  3. 639 块多线程: ctypes 在不同线程里各算一块区间, 结果与单线程拼接比对
     (验证 __thread 隔离真的生效 —— 若heap_ptr 是全局的, 分块结果必然错)

用法:
    py -3.12 verify_dll.py 1blk        # 1 块
    py -3.12 verify_dll.py 128
    py -3.12 verify_dll.py 639
    py -3.12 verify_dll.py 639 par 12
"""
import json
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import c_engine  # noqa: E402
from decrypt_e import _b64len  # noqa: E402

ENG = os.path.join(HERE, "engine_c")


def pt_for(nblk):
    """与 dump_image639.py 一致的可辨识明文。

    ⚠ golden128.json 是**全零 dummy 明文**（早期基线），而 golden639.json 是
    可辨识明文 —— 两者明文不同，body 必然不同。必须按 nblk 选对明文口径，
    否则会误报 FAIL（128 块用可辨识明文时首个字节就不同）。
    """
    if nblk == 128:
        return bytes(16 * 128)
    return bytes(((i * 37 + (i >> 8) * 11) & 0xFF) for i in range(16 * nblk))


def golden(nblk):
    gp = os.path.join(HERE, "reports", "golden%d.json" % nblk)
    if not os.path.exists(gp):
        return None
    return bytes.fromhex(json.load(open(gp, encoding="utf-8"))["body_hex"])


def serial(nblk):
    img = os.path.join(ENG, "image%d.bin" % nblk)
    if not os.path.exists(img):
        img = os.path.join(ENG, "image128.bin")
    K = bytes(range(0x05, 0x15))
    pt = pt_for(nblk)
    c_engine.init(img)
    t0 = time.time()
    body = c_engine.encrypt(K, pt)
    ms = (time.time() - t0) * 1000
    want = golden(nblk)
    print("[%d 块] DLL %.0f ms  body %d 字节  heap=%s"
          % (nblk, ms, len(body), c_engine.heap_stat()))
    if want is None:
        print("         (无 golden%d.json, 跳过差分)" % nblk)
        return body, ms, None
    if body == want:
        print("         PASS 与 golden%d 逐字节完全一致 ✓" % nblk)
    else:
        n = min(len(body), len(want))
        fd = next((i for i in range(n) if body[i] != want[i]), n)
        print("         FAIL 首个差异 idx=%d  c=%s  golden=%s"
              % (fd, body[fd:fd + 8].hex(), want[fd:fd + 8].hex()))
    return body, ms, want


def parallel(nblk, nthread):
    """每线程算一段。分段结果必须与串行完全一致 —— 这是 __thread 隔离的证据。"""
    img = os.path.join(ENG, "image%d.bin" % nblk)
    if not os.path.exists(img):
        img = os.path.join(ENG, "image128.bin")
    K = bytes(range(0x05, 0x15))
    pt = pt_for(nblk)
    c_engine.init(img)
    per = (nblk + nthread - 1) // nthread
    res = [None] * nthread
    errs = [None] * nthread

    def work(t):
        lo, hi = t * per, min(nblk, (t + 1) * per)
        if lo >= hi:
            return
        try:
            res[t] = c_engine.encrypt(K, pt[lo * 16:hi * 16])
        except Exception as e:      # noqa: BLE001
            errs[t] = "%d: %s" % (lo, e)

    ths = [threading.Thread(target=work, args=(t,)) for t in range(nthread)]
    t0 = time.time()
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    ms = (time.time() - t0) * 1000
    if any(errs):
        print("线程错误: %s" % [e for e in errs if e])
        return None, ms
    cat = b"".join(b for b in res if b)
    print("[%d 块 × %d 线程] 墙钟 %.0f ms  合计 body %d 字节"
          % (nblk, nthread, ms, len(cat)))
    per_blk = ms / nblk
    print("   %.2f ms/块  单线程等效 %.0f ms  加速比 %.2fx"
          % (per_blk, per_blk * nblk, (per_blk * nblk) / ms))
    return cat, ms


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 128
    if len(sys.argv) > 3 and sys.argv[2] == "par":
        nt = int(sys.argv[3])
        cat, ms = parallel(n, nt)
        want = golden(n)
        if cat and want:
            print("   与 golden%d %s" % (n, "一致 ✓" if cat == want else "不一致 ✗"))
    else:
        serial(n)