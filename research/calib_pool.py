# -*- coding: utf-8 -*-
"""多进程标定池 —— Unicorn 是 thread-safe by design，但**不是** process-safe 的问题：
每个子进程有独立地址空间，天然规避 V19 记录的「仿真地址空间未隔离」问题。

背景实测（见reports/V20_perf_options.md）：
    解密 639 块（标定已缓存）  :   382 ms   ← 已 <1s
    标定 639 块                :  8930 ms   ← 全部瓶颈
    K 在真实流量里 100% 不复用（10 样本 10 个不同 K）→ 缓存无收益
    CONST[b] 无代数结构（仿射检验全 False）→ 无法外推
结论：单请求 <1s 只能靠「把 639 块的标定并行化」。标定是串行链式推进
（续算实测失败：把 iv 换成 ctd[7] 重跑，密文链与一次跑 16 块不一致），
所以**不能把一条链切段并行** —— 只能并行「不同请求」。

本模块解决的是**并发吞吐**：N 个同时到来的请求分给 N 个进程，
每个进程独享一个 Unicorn 会话。单请求延迟不变（8930 ms），
但 N 个请求的总吞吐是 8930/N ms。

对「单请求 639 块 <1s」这个目标，本模块**无效**；
真正的达标路径是 engine_c 的基本块合并或把 x_b 生成式提取成 C。
"""
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_DELIV = os.path.join(_HERE, "deliverables")
if _DELIV not in sys.path:
    sys.path.insert(0, _DELIV)


def _worker(payload):
    """子进程入口：标定 (K, nblk) 并回传 (CONST, Cb, C, rk)。

    必须 pickle 安全的顶层函数；EDecryptor 不可跨进程传递，故在子进程内新建。
    """
    import decrypt_e as D
    K, nblk, backend = payload
    d = D.EDecryptor(backend=backend)
    C, rk, CONST, Cb = d.calibrate(K, nblk)
    return (list(CONST), list(Cb), C, rk)


class CalibPool:
    """进程池。每个 worker 持有一个 Unicorn 会话（懒加载），任务按需分配。"""

    def __init__(self, nproc=None, backend="unicorn"):
        import multiprocessing as mp
        self.nproc = nproc or min(12, os.cpu_count() or 4)
        self.backend = backend
        # spawn：避免 fork 继承 Unicorn 内部状态（QEMU 有大量全局/线程局部）
        ctx = mp.get_context("spawn")
        self._pool = ctx.Pool(self.nproc)

    def calibrate_many(self, jobs):
        """jobs = [(K, nblk), ...]，返回 [((C, rk, CONST, Cb), ...), ...]。

        jobs 会被均分到 nproc 个进程。**同一个进程内的任务必须按块号升序**，
        因为 CONST[b] 只依赖 (K, b)，与 nblk 无关 —— 这样小请求先标定不会浪费大请求。
        """
        payloads = [(K, nblk, self.backend) for (K, nblk) in jobs]
        raw = self._pool.map(_worker, payloads, chunksize=1)
        out = []
        for CONST, Cb, C, rk in raw:
            out.append((C, rk, CONST, Cb))
        return out

    def close(self):
        self._pool.close()
        self._pool.join()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


if __name__ == "__main__":
    import multiprocessing as mp

    KS = [bytes([(0x05 + i * 7) & 0xFF]) * 16 for i in range(12)]
    jobs = [(k, 128) for k in KS]

    with CalibPool() as pool:
        t0 = time.time()
        res = pool.calibrate_many(jobs)
        el = time.time() - t0

    ok = all(len(r[2]) == 128 for r in res)
    print("12 个不同 K × 128 块标定: %.0f ms  (串行单次 %.0f ms)"
          % (el * 1000, 858))
    print("全部块数正确:", ok)
    print("进程数: %d  加速比: %.2fx" % (min(12, os.cpu_count() or 4),
                                       858 * len(jobs) / (el * 1000)))