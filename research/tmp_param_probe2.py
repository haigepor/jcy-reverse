# -*- coding: utf-8 -*-
"""tmp_param_probe2.py — play/play-connect/device-base 参数组合探测（第二轮）。"""
import json
import os
import sys
import urllib.parse

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables"))
sys.path.insert(0, os.path.join(ROOT, "research", "captures", "rsa_scan"))
sys.path.insert(0, os.path.join(ROOT, "src"))
import jcy_client as J  # noqa: E402

PART = urllib.parse.quote("第1集")
CASES = [
    # play: query + 同字段 body
    ("POST", "/app/video/play?id=113354&play=mp4&part=" + PART,
     {"id": 113354, "play": "mp4", "part": "第1集"}),
    ("POST", "/app/video/play?id=113354&play=mp4&part=" + PART, {}),
    # play-connect
    ("POST", "/app/video/play-connect?id=113354&play=mp4&part=" + PART,
     {"id": 113354, "play": "mp4", "part": "第1集"}),
    ("POST", "/app/video/play-connect", {"id": 113354, "play": "mp4", "part": "第1集"}),
    # device-base: 短键候选（明文 ≤16B）
    ("POST", "/app/video/device-base", {"id": 1}),
    ("POST", "/app/video/device-base", {"nid": 1}),
    ("POST", "/app/video/device-base", {"did": "1"}),
    ("POST", "/app/video/device-base", {"uuid": "1"}),
    ("POST", "/app/video/device-base", {"oaid": "1"}),
    ("POST", "/app/video/device-base", {"appid": "1"}),
    ("POST", "/app/video/device-base", {"version": "1"}),
    ("POST", "/app/video/device-base", {"brand": "1"}),
]


def main():
    cli = J.JcyClient()
    out = []
    for method, path, params in CASES:
        try:
            r = cli.request(method, path, params, timeout=25)
        except Exception as e:  # noqa: BLE001
            print("ERR  %-4s %-72s %r" % (method, path, e)); continue
        if r.get("plain") is not None:
            j = r.get("json") if isinstance(r.get("json"), dict) else {}
            code, msg = j.get("code"), j.get("message")
            print("%-5s %-4s %-72s code=%s msg=%s" % ("OK" if code == 20000 else "..",
                                                      method, path[:72], code, msg))
            out.append({"path": path, "params": params, "code": code, "message": msg})
        else:
            print("RAW  %-4s %-72s %r" % (method, path, r.get("raw", "")[:90]))
            out.append({"path": path, "params": params, "raw": r.get("raw", "")[:200]})
    json.dump(out, open(os.path.join(ROOT, "research", "tmp_param_probe2.json"), "w",
                        encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
