# -*- coding: utf-8 -*-
"""tmp_w1_e2e.py — /app/video/list 端到端实测：分段计时 + 明文验证。"""
import json
import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, os.path.join(HERE, "captures", "rsa_scan"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import http.client  # noqa: E402

PATH = "/app/video/list?channel=1&sort=weight&limit=6&page=1"
BODY_FILE = os.path.join(HERE, "tmp_w1_body.txt")
CLI = os.path.join(HERE, "deliverables", "decrypt_cli.py")
PY = sys.executable


def main():
    import authgen

    # ---- 1) 认证生成 ----
    ts = int(time.time() * 1000)
    t0 = time.time()
    auth = authgen.gen(ts)
    t_auth = time.time() - t0
    print("[1] 认证生成        %.2fs  auth=%s..." % (t_auth, auth[:24]), flush=True)

    # ---- 2) 真实请求 ----
    t0 = time.time()
    conn = http.client.HTTPConnection("43.145.33.254", 27990, timeout=20)
    conn.request("GET", PATH, headers={
        "x-version": "2020-09-17", "user-agent": "Dart/3.6 (dart:io)",
        "appid": "4150439554430529", "tcs": "2",
        "ts": str(ts), "nonce": "%08d" % random.randint(0, 99999999),
        "authentication": auth,
    })
    r = conn.getresponse()
    raw = r.read().decode("utf-8", "replace")
    conn.close()
    t_http = time.time() - t0
    est = int(len(raw.split(".", 1)[1]) * 3 / 4) // 16 if raw.count(".") == 1 else 0
    print("[2] 真实 HTTP 往返  %.2fs  status=%s  body=%dB  ~%d 块" % (t_http, r.status, len(raw), est), flush=True)
    with open(BODY_FILE, "w", encoding="utf-8") as f:
        f.write(raw)

    # ---- 3) 预览解密（前 10 块，独立子进程=真实 /decrypt 链路）----
    t0 = time.time()
    p = subprocess.run([PY, CLI, "-", "10"], input=raw.encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    t_prev = time.time() - t0
    prev = json.loads(p.stdout.decode("utf-8", "replace"))
    pj = prev.get("json") or {}
    head = json.dumps(pj, ensure_ascii=False)[:160]
    print("[3] 预览解密(10块)  %.2fs  ok=%s code=%s  %s" % (t_prev, prev.get("ok"), pj.get("code"), head), flush=True)
    if not pj:
        print("    !plain[:150]:", repr(prev.get("plain", ""))[:150])
        print("    !stderr:", p.stderr.decode("utf-8", "replace")[-200:])

    # ---- 4) 全量解密（独立子进程）----
    t0 = time.time()
    p2 = subprocess.run([PY, CLI], input=raw.encode(),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800)
    t_full = time.time() - t0
    full = json.loads(p2.stdout.decode("utf-8", "replace"))
    fj = full.get("json") or {}
    ok = isinstance(fj, dict) and "total" in fj and "items" in fj
    item0 = (fj.get("items") or [{}])[0]
    if not fj:
        print("    !plain[:150]:", repr(full.get("plain", ""))[:150])
        print("    !stderr:", p2.stderr.decode("utf-8", "replace")[-200:])
    print("[4] 全量解密        %.2fs  ok=%s  json=%s  total=%s  items=%d" %
          (t_full, full.get("ok"), ok, fj.get("total"), len(fj.get("items") or [])), flush=True)
    print("    首条: id=%s name=%r score=%s" % (item0.get("id"), item0.get("name"), item0.get("score")), flush=True)
    print("\n合计体验: 点发送→预览明文 ≈ %.1fs(服务在跑时) ；全量明文 ≈ %.1fs"
          % (t_auth + t_http + t_prev, t_auth + t_http + t_full), flush=True)


if __name__ == "__main__":
    main()
