# -*- coding: utf-8 -*-
# verify_corpus.py — 用真实语料核验 authgen (O[0:32] 是服务端实际校验的部分)
#   注意: 语料抓取于 2026-09-29, 其设备指纹与当前 DEV 镜像不同, 故仅 O[0:32]
#   (只依赖 input[0:36] = "3.0.0.8-<ts>-Android-1.5.8.") 可完全对齐。
import os, sys, json, base64, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
TOOLCHAIN = os.path.abspath(os.path.join(HERE, "..", "toolchain"))
sys.path.insert(0, TOOLCHAIN)
import authgen as AG

CORPUS = os.path.abspath(os.path.join(HERE, "..", "corpus", "O_corpus.json"))
LIMIT = int(os.environ.get("LIMIT", "24"))


def main():
    C = json.load(open(CORPUS))
    seen, rows = set(), []
    for r in C:
        if r.get("family") != "norm":
            continue
        try:
            ts = int(r["ts"])
        except (TypeError, ValueError):
            continue
        if ts in seen:
            continue
        seen.add(ts)
        body = AG.custom_b64d(r["b64"])
        rows.append((ts, body))
        if len(rows) >= LIMIT:
            break
    print("核验条目: %d (唯一 ts)" % len(rows))
    ok32 = ok64 = 0
    t0 = time.time()
    for i, (ts, ref) in enumerate(rows, 1):
        auth = AG.gen(ts)
        mine = AG.custom_b64d(auth)
        m32 = mine[16:48] == ref[16:48]
        m64 = mine[16:80] == ref[16:80]
        ok32 += m32
        ok64 += m64
        print("  [%2d/%d] ts=%d  O[0:32] %s  O[0:64] %s   (%.1fs)" %
              (i, len(rows), ts, "MATCH" if m32 else "DIFF ", "MATCH" if m64 else "DIFF ", time.time() - t0))
        if not m32:
            print("        mine=%s" % mine[16:48].hex())
            print("        ref =%s" % ref[16:48].hex())
    print()
    print("O[0:32] 命中: %d/%d" % (ok32, len(rows)))
    print("O[0:64] 命中: %d/%d" % (ok64, len(rows)))
    print("前缀(ct0) 恒定校验: %s" % ("一致" if len({r[1][:16] for r in rows}) == 1 else "不一致"))


if __name__ == "__main__":
    main()
