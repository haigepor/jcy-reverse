#!/usr/bin/env python3
"""proto_test.py - Apipost 库 35 接口协议执行测试 + 密文归档.

产出: research/captures/rsa_scan/responses_batch1.jsonl (加密成功响应)
      research/captures/rsa_scan/proto_test_results.json (明细+统计)
"""
import http.client
import json
import os
import random
import re
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUTH = "http://127.0.0.1:8791/auth"
OUTDIR = os.path.join(ROOT, "research/captures/rsa_scan")

EPS = [
    ("GET",  "/app/config", None),
    ("GET",  "/app/channel?top-level=true", None),
    ("GET",  "/app/channel/", None),
    ("POST", "/app/config/channel", {}),
    ("POST", "/app/config/video", {}),
    ("GET",  "/app/banners/0", None),
    ("GET",  "/app/banners/1", None),
    ("GET",  "/app/banners/2", None),
    ("GET",  "/app/video/list?channel=1&sort=weight&limit=6&page=1", None),
    ("GET",  "/app/video/detail?id=103558", None),
    ("GET",  "/app/video/search?keyword=%E6%B5%B7%E8%B4%BC%E7%8E%8B", None),
    ("GET",  "/app/video/key?keyword=%E6%B5%B7", None),
    ("GET",  "/app/video_update_list/2026-10-01", None),
    ("POST", "/app/video/device-base", {}),
    ("POST", "/app/video/record", {}),
    ("POST", "/app/video/play-connect", {}),
    ("POST", "/app/video/play", {}),
    ("GET",  "/app/danmu", None),
    ("GET",  "/app/vod_comment/gettop", None),
    ("GET",  "/app/vod_comment/gethitstop", None),
    ("GET",  "/app/vod_comment/getlist", None),
    ("POST", "/app/users/clearimg", {}),
    ("POST", "/app/users/task", {}),
    ("POST", "/app/history", {}),
    ("POST", "/app/history/localcahce", {}),
    ("GET",  "/app/task/sign_rule", None),
    ("POST", "/app/messagebox/give_me", {}),
    ("POST", "/app/messagebox/dynamic", {}),
    ("POST", "/app/upgrade", {}),
    ("GET",  "/app/v2/config/host", None),
    ("GET",  "/app/users/info", None),
    ("GET",  "/app/vip_price/list", None),
    ("POST", "/app/task/task", {}),
    ("GET",  "/app/playaddr/v4/client", None),
    # /app/login/smscode 跳过: 会真实触发短信发送
]


def get_auth():
    return json.load(urllib.request.urlopen(AUTH, timeout=120))


def classify(body_text):
    t = body_text.strip()
    if re.fullmatch(r"[A-Za-z0-9+/=.\s]+", t) and t.count(".") == 1:
        p0, _, p1 = t.partition(".")
        if len(p0) > 100 and len(p1) > 16:
            return "encrypted", len(p0), len(p1)
    if t.startswith("{") or t.startswith("["):
        try:
            j = json.loads(t)
            return "plain-json", j.get("code"), (j.get("message") or j.get("msg") or "")
        except Exception:
            return "plain", None, ""
    return "error", None, t[:120]


def main():
    jsonl_path = os.path.join(OUTDIR, "responses_batch1.jsonl")
    results = []
    counts = {"encrypted": 0, "plain-json": 0, "plain": 0, "error": 0}
    conn = http.client.HTTPConnection("43.145.33.254", 27990, timeout=15)
    auth = get_auth()
    for method, path, body in EPS:
        row = {"method": method, "path": path}
        try:
            auth = get_auth()
            conn = http.client.HTTPConnection("43.145.33.254", 27990, timeout=15)
            hdrs = {"x-version": "2020-09-17", "user-agent": "Dart/3.6 (dart:io)",
                    "appid": "4150439554430529", "ts": str(auth["ts"]),
                    "accept-encoding": "identity", "authentication": auth["authentication"],
                    "tcs": "2", "content-type": "application/json; charset=utf-8",
                    "nonce": "%08d" % random.randint(0, 99999999)}
            payload = json.dumps(body) if body is not None else None
            conn.request(method, path, body=payload, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            row["http"] = resp.status
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("latin1")
            kind, extra, note = classify(text)
            row["kind"] = kind
            row["code_or_p0"] = extra
            row["note"] = note if isinstance(note, str) else str(note)
            counts[kind] = counts.get(kind, 0) + 1
            if kind == "encrypted":
                row["body_len"] = len(data)
                with open(jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"path": path, "method": method, "body": text},
                                       ensure_ascii=False) + "\n")
        except Exception as e:
            row["kind"] = "error"
            row["note"] = "%s: %s" % (type(e).__name__, e)
            counts["error"] += 1
        results.append(row)
        print("%-4s %-52s -> %s %s" % (method, path[:52], row.get("http"), row["kind"]),
              flush=True)
        time.sleep(0.4)
    summary = {"total": len(EPS), "counts": counts, "results": results,
               "skipped": ["/app/login/smscode (避免真实触发短信)"]}
    with open(os.path.join(OUTDIR, "proto_test_results.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print("SUMMARY", counts)


if __name__ == "__main__":
    main()
