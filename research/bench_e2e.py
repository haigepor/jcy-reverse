# -*- coding: utf-8 -*-
"""bench_e2e.py — 真实链路端到端计时(标定+解密), 按真实接口块数分组。

用户感受的是链路速度, 不是引擎裸跑。这测的是 EDecryptor.decrypt()
的完整路径: calibrate(含引擎执行+C后处理) + 逐块 xr 解密。
每组独立进程, 与 bench_iso 同样的理由。
"""
import os, subprocess, sys, statistics

HERE = os.path.dirname(os.path.abspath(__file__))

CHILD = r'''
import os, sys, time
sys.path.insert(0, %r)
sys.path.insert(0, os.path.join(%r, "deliverables"))
os.environ["JCY_DLL"] = os.path.join(%r, "engine_c", sys.argv[1])
from decrypt_e import EDecryptor
NB = int(sys.argv[2])
K = bytes(range(0x05, 0x15))
P1 = bytes(16 * NB)
d = EDecryptor(backend="c")
t0 = time.time()
pt = d.decrypt(P1, K)
dt = (time.time() - t0) * 1000
import hashlib
print("%%.2f %%s %%d" %% (dt, hashlib.sha256(pt).hexdigest()[:16], len(pt)))
''' % (HERE, HERE, HERE)

CHILD_PY = os.path.join(HERE, "_e2e_child.py")
open(CHILD_PY, "w", encoding="utf-8").write(CHILD)

# 真实接口块数(从 captures/live_data/INDEX.json 的明文长度推算)
CASES = [("device-base", 3), ("sign_rule", 30), ("video_detail", 84),
         ("app_config", 120), ("update_list", 143), ("app_channel", 166),
         ("banners_0", 259), ("video_list", 539), ("【639压力】", 639)]
ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 3
DLLS = [("V22", "jcy_fuse.dll"), ("V23", "jcy_fuse_fast.dll")]

print("真实链路端到端(冷标定+解密), 每组 %d 个独立进程\n" % ROUNDS)
print("%-14s %6s %10s %10s %8s %s" % ("接口", "块数", "V22ms", "V23ms", "加速", "明文一致"))
tot = {t: 0.0 for t, _ in DLLS}
for name, nb in CASES:
    row = {}
    hs = {}
    for tag, dll in DLLS:
        vals = []
        for _ in range(ROUNDS):
            p = subprocess.run([sys.executable, CHILD_PY, dll, str(nb)],
                               capture_output=True, text=True)
            if p.returncode != 0:
                vals = []
                print("  %s/%s 失败: %s" % (tag, name, p.stderr.strip()[-160:]))
                break
            parts = p.stdout.strip().split()
            vals.append(float(parts[0]))
            hs.setdefault(tag, set()).add((parts[1], parts[2]))
        row[tag] = statistics.median(vals) if vals else None
        tot[tag] += row[tag] if row[tag] else 0
    if row.get("V22") and row.get("V23"):
        same = hs["V22"] == hs["V23"]
        print("%-14s %6d %10.0f %10.0f %7.2fx %s"
              % (name, nb, row["V22"], row["V23"], row["V22"] / row["V23"],
                 "是" if same else "**否**"))
    else:
        print("%-14s %6d   (失败)" % (name, nb))

os.remove(CHILD_PY)
print()
print("V22 合计 %.0f ms   V23 合计 %.0f ms" % (tot["V22"], tot["V23"]))
