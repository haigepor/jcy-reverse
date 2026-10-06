# -*- coding: utf-8 -*-
"""calib_pool 加速比实测。

注意：必须作为**真实文件**运行。multiprocessing 的 spawn 方式要 re-import
__main__，用 `python - <<EOF` 从stdin 喂脚本时子进程会卡死 —— 那不是性能问题。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "deliverables"))


def main():
    import decrypt_e as D
    from calib_pool import CalibPool

    NBLK = int(sys.argv[1]) if len(sys.argv) > 1 else 320
    NTASK = int(sys.argv[2]) if len(sys.argv) > 2 else 6

    K0 = bytes([0x11]) * 16
    d = D.EDecryptor(backend="unicorn")
    t0 = time.time()
    d.calibrate(K0, NBLK)
    base = time.time() - t0
    print("串行基线%d 块: %.0f ms" % (NBLK, base * 1000))
    del d

    KS = [bytes([(0x05 + i * 13) & 0xFF]) * 16 for i in range(NTASK)]
    jobs = [(k, NBLK) for k in KS]
    t0 = time.time()
    with CalibPool(nproc=NTASK) as pool:
        res = pool.calibrate_many(jobs)
    el = time.time() - t0
    print("%d 进程 × %d 任务 × %d 块: %.0f ms" % (NTASK, NTASK, NBLK, el * 1000))
    print("串行预计 %.0f ms  加速比 %.2fx" % (NTASK * base * 1000, NTASK * base / el))
    print("块数全部正确:", all(len(r[2]) == NBLK for r in res))
    print("CPU 逻辑核: %d" % os.cpu_count())


if __name__ == "__main__":
    main()