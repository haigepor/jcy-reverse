# -*- coding: utf-8 -*-
"""端到端验证：进程池标定的正确性 + 接入 authgen_server 后的行为。

正确性判据：池化标定的 CONST/Cb 必须与同进程 Unicorn 串行标定**逐字节一致**
（池是 spawn 出来的独立进程，若有状态泄漏/环境差异，这里会立刻暴露）。
"""
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "deliverables"))


def main():
    import decrypt_e as D
    import authgen_server as A

    NBLK = 64
    K = bytes([0x3B, 0x91, 0x0C, 0x77, 0xE2, 0x14, 0xA6, 0x5F,
               0xC8, 0x2D, 0x73, 0xB0, 0x49, 0xE6, 0x1A, 0x8D])

    print("=== 1. 串行基线 ===")
    d = D.EDecryptor(backend="unicorn")
    t0 = time.time()
    C0, rk0, CONST0, Cb0 = d.calibrate(K, NBLK)
    base = time.time() - t0
    print("   Unicorn 串行 %d 块: %.0f ms  CONST=%d 条" % (NBLK, base * 1000, len(CONST0)))

    print("=== 2. 进程池标定 ===")
    t0 = time.time()
    got = A._pool_calibrate(K, NBLK)
    el = time.time() - t0
    if got is None:
        print("   ✗ 池不可用")
        return 1
    C1, rk1, CONST1, Cb1 = got
    print("   池化 %d 块: %.0f ms（含首次 spawn）CONST=%d 条" % (NBLK, el * 1000, len(CONST1)))

    print("=== 3. 逐字节比对 ===")
    ok_c = C0 == C1
    ok_rk = rk0 == rk1
    ok_const = list(CONST0) == list(CONST1)
    ok_cb = list(Cb0) == list(Cb1)
    print("   C一致=%s  rk一致=%s  CONST全一致=%s  Cb全一致=%s"
          % (ok_c, ok_rk, ok_const, ok_cb))
    if not ok_const:
        for i, (a, b) in enumerate(zip(CONST0, CONST1)):
            if a != b:
                print("   首个差异 CONST[%d]:\n     串行 %s\n     池化 %s" % (i, a.hex(), b.hex()))
                break

    print("=== 4. 池复用（第2 次，同 K）===")
    t0 = time.time()
    got2 = A._pool_calibrate(K, NBLK)
    el2 = time.time() - t0
    print("   第 2 次: %.0f ms  一致=%s" % (el2 * 1000, list(got2[2]) == list(CONST0)))

    print("=== 5. decrypt_response 端到端（走池）===")
    # 构造一个可解的响应体：先用引擎加密反向不现实，改为只验证不崩溃 + 返回结构
    t0 = time.time()
    r = A.decrypt_response("not-a-valid-body")
    print("   非法输入返回: ok=%s (%.0f ms)" % (r.get("ok"), (time.time() - t0) * 1000))

    good = ok_c and ok_rk and ok_const and ok_cb and list(got2[2]) == list(CONST0)
    print("\n结论:", "PASS 池化标定与串行逐字节一致 ✓" if good else "FAIL")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())