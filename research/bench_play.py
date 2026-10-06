# -*- coding: utf-8 -*-
"""bench_play.py — 实测「取一个视频播放链接」整条链路耗时。

播放链路的真实形态（来自 archive/versions/v6/apipost + auth_samples.json）:
    1) /app/video/detail?id=...        -> 拿到 parts[] (线路 mp4 / 第N集)
    2) /app/video/play-connect         -> 点立即播放, 建立连接
    3) /app/video/play?id=&play=mp4&part=第N集 -> 返回 raw_play_url

每个响应都是 <P0_b64>.<P1_b64>, P0 = RSA(K16resp), P1 = E(key=K16resp,
逐块tweak)。**K16resp 每个响应都不同**（服务端 RSA 私钥动态配对), 所以
每次请求都要标定 —— 这正是真实最坏情况。

本脚本测两种口径:
  A. 冷:每个响应一个新 K16resp(必须标定) —— 最坏情况
  B. 温:同一 K16resp 重复请求(标定可复用) —— 会话内稳态

对比 App:A 口径下 App 也必须每请求做 key schedule, 所以 A 是双方
可比的口径; B 是我们复用带来的额外收益。
"""
import os, sys, json, time, statistics, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import EDecryptor


def load_pairs():
    p = os.path.join(HERE, "tmp_pairs.json")
    out = []
    for e in json.load(open(p, encoding="utf-8")):
        if not e.get("k16"):
            continue
        p1 = e.get("p1_hex")
        if not p1 or len(p1) % 32:
            continue
        out.append((e["hit"], bytes.fromhex(p1), e["k16"].encode()))
    return out


def main():
    pairs = load_pairs()
    if not pairs:
        print("无可用样本")
        return
    print("真实响应样本 %d 个 (P1 已按真实长度排序)" % len(pairs))
    print()
    print("响应 P1 字节 -> 块数: " +
          ", ".join("%dB/%d块" % (len(p), len(p) // 16) for _, p, _ in pairs))
    print()

    # ---------------- A. 冷: 每个响应新 K16 (最坏情况) ----------------
    print("=" * 72)
    print("A. 冷口径: 每个响应一个新 K16resp (每次都必须标定)")
    print("=" * 72)
    print("%6s %6s %10s %10s %10s %12s" %
          ("hit", "块数", "标定ms", "解密ms", "合计ms", "us/块"))
    cold_tot = 0.0
    rows_cold = []
    for hit, p1, k in pairs:
        d = EDecryptor(backend="c")        # 新实例 -> 必然冷标定
        nb = len(p1) // 16
        t0 = time.time()
        C, rk, CONST, Cb = d.calibrate(k, nb)
        t_cal = (time.time() - t0) * 1000
        t0 = time.time()
        pt = d.decrypt(p1, k)
        t_dec = (time.time() - t0) * 1000
        tot = t_cal + t_dec
        cold_tot += tot
        rows_cold.append((hit, nb, t_cal, t_dec, tot))
        print("%6s %6d %10.1f %10.2f %10.1f %12.1f" %
              (hit, nb, t_cal, t_dec, tot, tot * 1000 / nb))
    print("  合计 %.0f ms  平均 %.1f ms" % (cold_tot, cold_tot / len(pairs)))

    # ---------------- B. 温: 同一 K16 复用 (会话内稳态) ----------------
    print()
    print("=" * 72)
    print("B. 温口径: 同一 K16resp 重复请求 (标定可复用, 会话内稳态)")
    print("=" * 72)
    print("%6s %6s %10s %10s %10s %12s %9s" %
          ("hit", "块数", "标定ms", "解密ms", "合计ms", "us/块", "vs冷"))
    warm_tot = 0.0
    for hit, p1, k in pairs:
        d = EDecryptor(backend="c")
        nb = len(p1) // 16
        d.calibrate(k, nb)                  # 首次标定(不计时)
        best = None
        for _ in range(3):
            t0 = time.time()
            d.calibrate(k, nb)
            t_cal = (time.time() - t0) * 1000
            t0 = time.time()
            pt = d.decrypt(p1, k)
            t_dec = (time.time() - t0) * 1000
            tot = t_cal + t_dec
            if best is None or tot < best[2]:
                best = (t_cal, t_dec, tot)
        t_cal, t_dec, tot = best
        warm_tot += tot
        cold = [r[4] for r in rows_cold if r[0] == hit][0]
        print("%6s %6d %10.4f %10.3f %10.4f %12.1f %8.0fx" %
              (hit, nb, t_cal, t_dec, tot, tot * 1000 / nb, cold / max(tot, 1e-9)))
    print("  合计 %.1f ms  平均 %.3f ms" % (warm_tot, warm_tot / len(pairs)))

    # ---------------- C. 真实播放链接内容确认 ----------------
    print()
    print("=" * 72)
    print("C. 解密结果确认 (证明拿到的是真实播放链接数据)")
    print("=" * 72)
    from decrypt_e import decrypt_envelope
    for hit, p1, k in pairs:
        if len(p1) < 400:
            continue
        d = EDecryptor(backend="c")
        pt = d.decrypt(p1, k)
        try:
            j = json.loads(pt)
        except Exception:
            continue
        data = j.get("data")
        s = json.dumps(data, ensure_ascii=False)
        has_url = "http" in s
        print("  hit=%s  %d 字节明文  含URL=%s" % (hit, len(pt), has_url))
        if has_url:
            # 抽取第一个 http URL
            import re
            m = re.findall(r'https?://[^"\']+', s)
            if m:
                print("    首个URL: %s" % m[0][:150])
                if "m3u8" in s or "mp4" in s:
                    print("     含 m3u8/mp4: %s" % ("m3u8" in s or "mp4" in s))
        break

    print()
    print("=" * 72)
    print("结论: 冷口径合计 %.0f ms / 温口径合计 %.1f ms (%.0f×)" %
          (cold_tot, warm_tot, cold_tot / max(warm_tot, 1e-9)))
    print("=" * 72)


main()
