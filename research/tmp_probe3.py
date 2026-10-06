# -*- coding: utf-8 -*-
"""tmp_probe3.py — device-base / play-connect 第三轮参数探测。"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables"))
sys.path.insert(0, os.path.join(ROOT, "research", "captures", "rsa_scan"))
sys.path.insert(0, os.path.join(ROOT, "src"))
import jcy_client as J  # noqa: E402

DEV = [
    {"id": "113354"}, {"id": 113354}, {"vid": "113354"}, {"vid": 113354},
    {"nid": "113354"}, {"did": "113354"}, {"uuid": "113354"}, {"oaid": "113354"},
    {"aid": "113354"}, {"nid": 113354},
]
CONN = [
    {"id": 113354, "play": "mp4", "part": "第1集"},
    {"vid": 113354, "play": "mp4", "part": "第1集"},
    {"id": "113354", "play": "mp4", "part": "第1集"},
    {"id": 113354, "play": "mp4", "part": "第1集", "position": 0, "duration": 1440},
]


def main():
    cli = J.JcyClient()
    out = []
    for path, cases in (("/app/video/device-base", DEV),
                        ("/app/video/play-connect", CONN)):
        for p in cases:
            try:
                r = cli.request("POST", path, p, timeout=25)
            except Exception as e:  # noqa: BLE001
                print("ERR %-26s %-46s %r" % (path, json.dumps(p, ensure_ascii=False), e)); continue
            j = r.get("json") if isinstance(r.get("json"), dict) else {}
            code, msg = j.get("code"), j.get("message")
            tag = "OK" if code == 20000 else ".."
            print("%-3s %-26s %-46s code=%s %s" % (tag, path, json.dumps(p, ensure_ascii=False)[:46],
                                                   code, msg))
            out.append({"path": path, "params": p, "code": code, "message": msg})
    json.dump(out, open(os.path.join(ROOT, "research", "tmp_probe3.json"), "w",
                        encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
