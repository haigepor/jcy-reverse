# -*- coding: utf-8 -*-
"""tmp_e2e.py — 同一真实信封（video_list，P1=8624B/539 块）重解，对比提速。

基线：research/reports/last_plain.json 记录 elapsed = 450.53s
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(HERE, "deliverables"), os.path.join(HERE, "..", "src")):
    sys.path.insert(0, _p)
from jcy_protocol.auth import custom_b64d  # noqa: E402
from decrypt_e import decrypt  # noqa: E402

env = open(os.path.join(HERE, "reports", "video_list_demo.raw"), "r", encoding="utf-8").read().strip()
K16 = b"3H71U2TMJRXRQMKJ"
P1 = custom_b64d(env.split(".", 1)[1])
print("信封 %d 字符  P1=%d 字节 = %d 块" % (len(env), len(P1), len(P1) // 16))

t0 = time.time()
pt = decrypt(P1, K16)
dt = time.time() - t0
print("全解耗时: %.2fs   (%.4f s/块)  → 明文 %d 字节" % (dt, dt / (len(P1) // 16), len(pt)))
print("明文头:", pt[:80].decode("utf-8", "replace"))

ref = json.load(open(os.path.join(HERE, "reports", "last_plain.json")))
same = pt.decode("utf-8", "replace") == ref["plain"]
print("\n与基线明文一致:", same, " 基线耗时 %.2fs → 提速 %.1f×" % (ref["elapsed"], ref["elapsed"] / dt))
