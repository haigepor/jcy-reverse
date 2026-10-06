# -*- coding: utf-8 -*-
"""从历史抓包语料提取去重响应体 → replay_corpus/ (供 inject_mitm.py --inject-dir 批量重放).

来源: research/captures/proxy_bodies.jsonl + research/captures/live/proxy_bodies.jsonl
输出: replay_corpus/bNNN.txt (P0.P1 原文) + replay_corpus/index.jsonl
"""
import base64, json, os, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUTD = os.path.join(HERE, "replay_corpus")
SOURCES = [
    os.path.join(HERE, "..", "..", "captures", "proxy_bodies.jsonl"),
    os.path.join(HERE, "..", "..", "captures", "live", "proxy_bodies.jsonl"),
    os.path.join(HERE, "bodies_now.jsonl"),
]

os.makedirs(OUTD, exist_ok=True)
uniq = {}  # body -> {endpoints, src}


def add(body, endpoint):
    body = body.strip()
    if not body or "." not in body:
        return
    parts = body.split(".")
    if len(parts) != 2:
        return
    p0, p1 = parts
    if len(p0) != 344:          # RSA-2048 b64 恒 344
        return
    try:
        p1b = base64.b64decode(p1)
    except Exception:
        return
    if len(p1b) == 0 or len(p1b) % 16 != 0:
        return
    # endpoint = 请求行 → 取纯路径
    ep = endpoint.split()
    path = ep[1] if len(ep) >= 2 and ep[0] in ("GET", "POST") else endpoint
    path = path.split("?")[0]
    if body not in uniq:
        uniq[body] = {"endpoints": set(), "p1_bytes": len(p1b)}
    uniq[body]["endpoints"].add(path)


for src in SOURCES:
    if not os.path.exists(src):
        print("skip(缺):", src)
        continue
    n = 0
    for line in open(src, encoding="utf-8"):
        try:
            r = json.loads(line)
        except Exception:
            continue
        ep = r.get("req", "?")
        body = r.get("resp_body_ascii") or r.get("resp") or r.get("body") or ""
        if isinstance(body, str) and body:
            add(body, ep)
            n += 1
    print("read", src, n, "行")

idx = os.path.join(OUTD, "index.jsonl")
with open(idx, "w", encoding="utf-8") as f:
    for i, (body, meta) in enumerate(sorted(uniq.items(), key=lambda kv: -kv[1]["p1_bytes"])):
        fn = os.path.join(OUTD, "b%03d.txt" % i)
        with open(fn, "w", newline="") as f2:
            f2.write(body)
        rec = {"n": i, "file": os.path.basename(fn),
               "endpoints": sorted(meta["endpoints"]),
               "body_len": len(body), "p1_bytes": meta["p1_bytes"],
               "sha1": hashlib.sha1(body.encode()).hexdigest()[:12]}
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
print("unique bodies:", len(uniq), "->", OUTD)
