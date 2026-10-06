# -*- coding: utf-8 -*-
"""tmp_verify_play.py — 验证 GET /app/video/play 的真实返回内容。"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables"))
sys.path.insert(0, os.path.join(ROOT, "research", "captures", "rsa_scan"))
sys.path.insert(0, os.path.join(ROOT, "src"))
import jcy_client as J  # noqa: E402

cli = J.JcyClient()
for path in [
    "/app/video/play?id=113354&play=mp4&part=%E7%AC%AC1%E9%9B%86",
    "/app/video/record",
]:
    r = cli.request("GET" if "play?" in path else "POST", path,
                    {} if "play?" not in path else None, timeout=25)
    if r.get("plain") is not None:
        j = r.get("json")
        print("OK  %-60s http=%s plain=%dB code=%s" % (path[:60], r["http"], len(r["plain"]),
                                                       (j or {}).get("code")))
        print("    json: %s" % json.dumps(j, ensure_ascii=False)[:600])
    else:
        print("RAW %-60s http=%s %r" % (path[:60], r["http"], (r.get("raw") or "")[:120]))
