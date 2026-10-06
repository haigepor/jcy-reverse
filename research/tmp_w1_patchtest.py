# -*- coding: utf-8 -*-
"""tmp_w1_patchtest.py — 微测试：mem_write 补丁是否真正影响执行（TB 缓存问题定位）。"""
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, os.path.join(HERE, "captures", "rsa_scan"))

from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

RET = bytes.fromhex("c0035fd6")
D0 = DEV_BASE + 0x2DA498


def run_case(flush, label):
    d = EDecryptor()
    d.calibrate(os.urandom(16), 2)            # 预热（未补丁，TB 已翻译）
    o = d._oracle()
    uc = o.s.e.uc
    orig = o.s.e.rd(D0, 4)
    uc.mem_write(D0, RET)
    back = o.s.e.rd(D0, 4)
    if flush:
        try:
            uc.ctl_flush_tb()
        except Exception as e:
            print("  ctl_flush_tb 不可用:", e)

    import unicorn
    cnt = Counter()

    def prof(u, address, size, ud):
        cnt[address - DEV_BASE] += 1

    uc.hook_add(unicorn.UC_HOOK_CODE, prof, begin=D0, end=D0 + 0x10)
    d._cache.clear()
    d._cap.clear()
    t0 = time.time()
    ctd = d._enc_big(bytes(16 * 4), os.urandom(16), os.urandom(16)[::-1])
    dt = time.time() - t0
    hits_ret = cnt[0x2DA498]
    hits_2nd = cnt[0x2DA49C]
    print("[%s] 回读=%s  ret命中=%d  第二条命中=%d  %.3fs  捕获=%d"
          % (label, "OK" if back == RET else "FAIL:" + back.hex(),
             hits_ret, hits_2nd, dt, len(d._cap)))
    uc.mem_write(D0, orig)


def main():
    print("== 补丁执行有效性微测试 ==")
    run_case(False, "无flush ")
    run_case(True,  "有flush ")


if __name__ == "__main__":
    main()
