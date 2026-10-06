# -*- coding: utf-8 -*-
"""并行扩展性诊断：确定加速比不足是CPU 核数不足、内存带宽，还是 spawn 开销。

方法：固定总工作量（1 个任务 vs N 个任务），测墙钟。
  - 若加速比 << N，说明并行效率受限于内存带宽（QEMU 访存密集）
  - 若 spawn 固定开销占比大，空任务往返能看出来
"""
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "deliverables"))


def bench(nproc, ntasks, nblk):
    import multiprocessing as mp
    from calib_pool import _worker
    ctx = mp.get_context("spawn")
    KS = [bytes([(0x05 + i * 13) & 0xFF]) * 16 for i in range(ntasks)]
    jobs = [(k, nblk, "unicorn") for k in KS]
    t0 = time.time()
    p = ctx.Pool(nproc)
    spawn_ms = (time.time() - t0) * 1000
    t1 = time.time()
    res = p.map(_worker, jobs, chunksize=1)
    el = time.time() - t1
    p.close()
    p.join()
    ok = all(len(r[0]) == nblk for r in res)
    return spawn_ms, el * 1000, ok


if __name__ == "__main__":
    NBLK = 320
    print("固定每任务 %d 块，改变并发度（观察扩展性）\n" % NBLK)
    print("进程数  任务数  spawn(ms)  计算(ms)  ms/任务  相对1进程")
    ref = None
    for ntasks in (1, 2, 4, 6, 8):
        sp, el, ok = bench(ntasks, ntasks, NBLK)
        per = el / ntasks
        if ref is None:
            ref = per
        print("%7d  %7d  %9.0f  %9.0f  %8.0f  %8.2fx%s"
              % (ntasks, ntasks, sp, el, per, ref / per,
                 "" if ok else "  ✗块数错误"))