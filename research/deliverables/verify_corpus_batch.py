# -*- coding: utf-8 -*-
"""verify_corpus_batch.py — 单模拟器批量核验全量语料 O[0:32]。

复用 :class:`authgen.UnicornESession`（一个模拟器实例跑完全部 ts），
比逐次新建实例快约 30%。
"""
import os, sys, json, base64, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import authgen as AG
from jcy_protocol.auth import custom_b64, custom_b64d, build_input, CT0

FP = AG.DEVICE_FP
CORPUS = os.path.abspath(os.path.join(HERE, "..", "corpus", "O_corpus.json"))
LOG = os.path.join(HERE, "corpus_batch.log")


class Gen:
    """薄封装：把 UnicornESession 暴露成 gen(ts) → body。"""

    def __init__(self):
        self.sess = AG.UnicornESession()

    def gen(self, ts):
        a1 = custom_b64(build_input(ts, FP).encode()).encode()
        return self.sess.encrypt(a1)


def main():
    C = json.load(open(CORPUS))
    refs = {}
    for r in C:
        if r.get("family") != "norm":
            continue
        try:
            ts = int(r["ts"])
        except (TypeError, ValueError):
            continue
        refs.setdefault(ts, custom_b64d(r["b64"]))
    tsl = list(refs)
    print("唯一 ts 数: %d  (语料 norm 条数 %d)" % (len(tsl), sum(1 for r in C if r.get("family") == "norm")))
    g = Gen()
    ok32 = ok_ct0 = 0
    bad = []
    t0 = time.time()
    for i, ts in enumerate(tsl, 1):
        body = g.gen(ts)
        m32 = body[16:48] == refs[ts][16:48]
        mc0 = body[0:16] == refs[ts][0:16]
        ok32 += m32; ok_ct0 += mc0
        if not m32:
            bad.append(ts)
        if i % 25 == 0 or i == len(tsl):
            print("  [%3d/%d] O[0:32] 命中 %d  失败 %d  已用 %.1fs" %
                  (i, len(tsl), ok32, len(bad), time.time() - t0), flush=True)
    print()
    print("=== 汇总 ===")
    print("样本 ts 总数     : %d" % len(tsl))
    print("ct0 恒定命中     : %d/%d" % (ok_ct0, len(tsl)))
    print("O[0:32] 命中     : %d/%d" % (ok32, len(tsl)))
    if bad:
        print("失败 ts (前20)   : %s" % bad[:20])
    print("总耗时           : %.1fs" % (time.time() - t0))
    print("模拟器重建次数   : %d" % g.sess.boots)
    json.dump({"total": len(tsl), "o32_match": ok32, "ct0_match": ok_ct0,
               "bad": bad, "seconds": time.time() - t0,
               "boots": g.sess.boots},
              open(os.path.join(HERE, "corpus_batch.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
