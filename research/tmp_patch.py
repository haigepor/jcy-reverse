# -*- coding: utf-8 -*-
"""tmp_patch.py — 补跑修正后的端点并合并进 tmp_all_endpoints.json。

补跑项：
  * GET /app/channel/            （301，jcy_client 已加非信封回退）
  * GET /app/danmu?...&part=第1集 （补 part 参数 → 20000）
"""
import json
import os
import sys
import urllib.parse

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables"))
sys.path.insert(0, os.path.join(ROOT, "research", "captures", "rsa_scan"))
sys.path.insert(0, os.path.join(ROOT, "src"))
import jcy_client as J  # noqa: E402

OUT = os.path.join(ROOT, "research", "tmp_all_endpoints.json")
PART = urllib.parse.quote("第1集")
CASES = [
    ("GET", "/app/channel/", None),
    ("GET", "/app/danmu?vid=113354&play=mp4&part=" + PART
            + "&start_time_point=0&end_time_point=60000", None),
    # play: 参数必须在 query 上, body 用 {} 即可
    ("POST", "/app/video/play?id=113354&play=mp4&part=" + PART, {}),
]


def main():
    cli = J.JcyClient()
    res = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    # 删除旧的失败/缺失项
    for k in list(res):
        if k.startswith("/app/danmu") or k == "/app/channel/" or k == "/app/video/play":
            del res[k]
    for method, path, params in CASES:
        try:
            r = cli.request(method, path, params, timeout=25)
        except Exception as e:  # noqa: BLE001
            print("ERR ", path, repr(e)); continue
        if r.get("plain") is not None:
            txt = r["plain"].decode("utf-8", "replace")
            rec = {"method": method, "http": r["http"], "k16resp": r["k16resp"],
                   "raw_len": r["raw_len"], "plain_len": len(r["plain"]),
                   "json": r["json"], "plain": txt}
            print("OK  %-4s %-64s %5dB code=%s" % (method, path[:64], len(r["plain"]),
                                                   (r["json"] or {}).get("code")))
        else:
            rec = {"method": method, "http": r["http"], "raw": r["raw"],
                   "location": r.get("location"), "note": r.get("note")}
            print("RAW %-4s %-64s %r" % (method, path[:64], r["raw"][:60]))
        res[path] = rec
    json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("merged -> %d 条" % len(res))


if __name__ == "__main__":
    main()
