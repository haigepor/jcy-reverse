# -*- coding: utf-8 -*-
"""bench_now.py — 当前速度实测(引擎裸跑 + 端到端), 版本标签自动按 md5 识别。

为什么重写: bench_iso.py / bench_e2e.py 里的 V22/V23 是硬编码文件名,
而 jcy_fuse.dll 已被 V23 覆盖 -> 两个标签指向同一 DLL, 对比结果全是 1.00x。
本脚本按 md5 归类, 指纹不同的才算两个版本。

用法:
  python bench_now.py            # 引擎裸跑 639/128, 5 轮
  python bench_now.py e2e        # 端到端 9 组真实块数
"""
import os, subprocess, sys, statistics, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
ENG = os.path.join(HERE, "engine_c")

# ---- 被测 DLL: (标签, 文件名) ----
CANDIDATES = [
    ("V22-O1", "jcy_fuse_o1.dll"),
    ("V22-O2", "jcy_fuse_O2.dll.bak"),
    ("V23-cur", "jcy_fuse.dll"),
    ("V23-alt", "jcy_fuse_fast.dll"),
]


def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def resolve():
    """返回 [(标签, 路径, md5, 体积)], 同 md5 只保留第一个标签。"""
    seen, out = {}, []
    for tag, name in CANDIDATES:
        p = os.path.join(ENG, name)
        if not os.path.exists(p):
            continue
        m = md5(p)
        if m in seen:
            print("  (跳过 %s: 与 %s 同一 DLL)" % (name, seen[m]))
            continue
        seen[m] = name
        out.append((tag, p, m, os.path.getsize(p)))
    return out


# ---------------- 引擎裸跑 ----------------
BARE = r'''
import ctypes, os, sys, time
sys.path.insert(0, %r)
from c_engine import load
ENG = %r
NB = int(sys.argv[2])
dll = sys.argv[1]
load(dll)
lib = load()
img = os.path.abspath(os.path.join(ENG, "image%%d.bin" %% NB))
assert lib.jcy_init(img.encode()) == 0, lib.jcy_last_error().decode()
K = bytes(range(0x05, 0x15))
pt = open(os.path.join(ENG, "pt%%d.bin" %% NB), "rb").read()
cap = len(pt) + 80
buf = ctypes.create_string_buffer(cap)
#预热一次(不计时), 排除首次调用的一次性开销
assert lib.jcy_encrypt_ex(K, pt, len(pt), buf, cap, 1) > 0
t0 = time.time()
n = lib.jcy_encrypt_ex(K, pt, len(pt), buf, cap, 1)
dt = (time.time() - t0) * 1000
import hashlib
print("%%.2f %%s" %% (dt, hashlib.sha256(bytes(buf.raw[:n])).hexdigest()[:16]))
''' % (HERE, ENG)


# ---------------- 端到端 ----------------
E2E = r'''
import os, sys, time, hashlib
sys.path.insert(0, %r)
sys.path.insert(0, os.path.join(%r, "deliverables"))
os.environ["JCY_DLL"] = sys.argv[1]
from decrypt_e import EDecryptor
NB = int(sys.argv[2])
K = bytes(range(0x05, 0x15))
P1 = bytes(16 * NB)
d = EDecryptor(backend="c")
t0 = time.time()
pt = d.decrypt(P1, K)
dt = (time.time() - t0) * 1000
print("%%.2f %%s %%d" %% (dt, hashlib.sha256(pt).hexdigest()[:16], len(pt)))
''' % (HERE, HERE)


def run(child, path, nb):
    p = subprocess.run([sys.executable, child, path, str(nb)],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return None, None, p.stderr.strip()[-180:]
    a = p.stdout.strip().split()
    return float(a[0]), " ".join(a[1:]), None


def stats(v):
    return (min(v), statistics.median(v), statistics.mean(v),
            statistics.stdev(v) if len(v) > 1 else 0.0, max(v) - min(v))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "bare"
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    dlls = resolve()
    if not dlls:
        print("未找到任何 DLL")
        return

    print("=== 参与测量的 DLL (按 md5 去重) ===")
    for tag, p, m, sz in dlls:
        print("  %-8s %-24s %7.2f MB  %s" % (tag, os.path.basename(p), sz / 1048576.0, m[:12]))
    print()

    if mode == "bare":
        child = os.path.join(ENG, "_bn_bare.py")
        open(child, "w", encoding="utf-8").write(BARE)
        for nb in (639, 128):
            print("--- 引擎裸跑 %d 块, 每组 %d 个独立进程 ---" % (nb, rounds))
            res, hs = {}, {}
            for tag, p, m, sz in dlls:
                vals = []
                for r in range(rounds):
                    v, h, err = run(child, p, nb)
                    if v is None:
                        print("  %s 第%d轮失败: %s" % (tag, r + 1, err))
                        break
                    vals.append(v)
                    hs.setdefault(tag, set()).add(h)
                res[tag] = vals
                print("  %-8s %s" % (tag, "  ".join("%.0f" % x for x in vals)))
            print("  %-8s %8s %8s %8s %7s %7s" % ("版本", "min", "median", "mean", "stdev", "极差"))
            for tag, v in res.items():
                if not v:
                    continue
                mn, md, me, sd, rg = stats(v)
                print("  %-8s %8.1f %8.1f %8.1f %7.1f %7.1f" % (tag, mn, md, me, sd, rg))
            allh = set()
            for t in hs:
                allh |= hs[t]
            print("  输出指纹集合: %s -> %s" % (len(allh), "全部一致" if len(allh) == 1 else "**存在分叉**"))
            if len(allh) == 1:
                print("  sha=%s" % list(allh)[0])
            print()
        os.remove(child)
    else:
        child = os.path.join(ENG, "_bn_e2e.py")
        open(child, "w", encoding="utf-8").write(E2E)
        cases = [("device-base", 3), ("sign_rule", 30), ("video_detail", 84),
                 ("app_config", 120), ("update_list", 143), ("app_channel", 166),
                 ("banners_0", 259), ("video_list", 539), ("【639压力】", 639)]
        tags = [d[0] for d in dlls]
        print("--- 端到端(冷标定+解密), 每组 %d 个独立进程 ---" % rounds)
        print("%-14s %6s" % ("接口", "块数") + "".join("%12s" % t for t in tags) + "%10s" % "最快倍")
        tot = {t: 0.0 for t in tags}
        for name, nb in cases:
            row, hs = {}, {}
            for tag, p, m, sz in dlls:
                vals = []
                for _ in range(rounds):
                    v, h, err = run(child, p, nb)
                    if v is None:
                        vals = []
                        print("  %s/%s 失败: %s" % (tag, name, err))
                        break
                    vals.append(v)
                    hs.setdefault(tag, set()).add(h)
                row[tag] = statistics.median(vals) if vals else None
                if row[tag]:
                    tot[tag] += row[tag]
            if all(row.get(t) for t in tags):
                best = min(tags, key=lambda t: row[t])
                line = "%-14s %6d" % (name, nb)
                for t in tags:
                    line += "%12.0f" % row[t]
                line += "%9.2fx" % (max(row[t] for t in tags) / row[best])
                allh = set()
                for t in hs:
                    allh |= hs[t]
                line += "  %s" % ("一致" if len(allh) == 1 else "**分叉**")
                print(line)
            else:
                print("%-14s %6d   (失败)" % (name, nb))
        print()
        for t in tags:
            print("  %-8s 合计 %.0f ms" % (t, tot[t]))
        os.remove(child)


main()
