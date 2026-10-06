# -*- coding: utf-8 -*-
"""tmp_param_probe.py — 为返回 code=40000 的 POST/GET 端点探测正确业务参数。"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables"))
sys.path.insert(0, os.path.join(ROOT, "research", "captures", "rsa_scan"))
sys.path.insert(0, os.path.join(ROOT, "src"))
import jcy_client as J  # noqa: E402

DEV = "16613a7076284a15bc723d018bcd67e1"

CASES = [
    ("POST", "/app/video/device-base", {"device_id": DEV, "app_name": "囧次元",
                                        "version": "1.5.8.0", "code_version": "3.0.0.8"}),
    ("POST", "/app/video/device-base", {"deviceId": DEV, "app_name": "囧次元",
                                        "version": "1.5.8.0", "codeVersion": "3.0.0.8"}),
    ("POST", "/app/video/device-base", {"device_id": DEV}),
    ("POST", "/app/video/play", {"id": 113354, "play": "mp4", "part": "第1集"}),
    ("POST", "/app/video/play", {"vid": 113354, "play": "mp4", "part": "第1集"}),
    ("POST", "/app/video/play-connect", {"id": 113354, "play": "mp4", "part": "第1集"}),
    ("POST", "/app/video/record", {"id": 113354, "play": "mp4", "part": "第1集",
                                   "position": 10, "duration": 1440}),
    ("GET", "/app/danmu?vid=113354&play=mp4&part=%E7%AC%AC1%E9%9B%86&start_time_point=0&end_time_point=60000", None),
    ("GET", "/app/danmu?vid=113354&cid=2&start_time_point=0&end_time_point=60000", None),
    ("GET", "/app/danmu?vid=113354&play=mp4&start_time_point=0&end_time_point=60000&cid=2", None),
]


def main():
    cli = J.JcyClient()
    out = []
    for method, path, params in CASES:
        try:
            r = cli.request(method, path, params, timeout=25)
        except Exception as e:  # noqa: BLE001
            print("ERR  %-4s %-70s %r" % (method, path, e)); continue
        if r.get("plain") is not None:
            code = (r.get("json") or {}).get("code") if isinstance(r.get("json"), dict) else None
            msg = (r.get("json") or {}).get("message") if isinstance(r.get("json"), dict) else None
            print("%-5s %-4s %-70s code=%s msg=%s len=%dB" % (
                "OK" if code == 20000 else "..", method, path[:70], code, msg, r.get("plain_len", 0)))
            out.append({"method": method, "path": path, "params": params, "code": code,
                        "message": msg, "json": r.get("json")})
        else:
            print("RAW  %-4s %-70s %r" % (method, path, r.get("raw", "")[:80]))
            out.append({"method": method, "path": path, "params": params, "raw": r.get("raw", "")[:200]})
    json.dump(out, open(os.path.join(ROOT, "research", "tmp_param_probe.json"), "w",
                        encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
