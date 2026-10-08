# -*- coding: utf-8 -*-
"""live_check.py — 实测确认：请求链路是否可用、响应是否仍为 <P0>.<P1> 密文。

流程：authgen 现签 ts/authentication → 重放 bodies_now.jsonl 最近一条
device-base 请求体 → 落盘响应 → custom_b64 解 P0 → priv_from_go.pem
PKCS1-v1.5 解出 K16（验证 P0 解包链路在当日流量上仍然成立）。
"""
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
for p in (os.path.join(ROOT, "research", "deliverables"), os.path.join(ROOT, "src", "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import authgen  # noqa: E402  (Unicorn 后端，首次 gen 需数秒)
from jcy_protocol.auth import custom_b64d, split_body  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402
from Crypto.Cipher import PKCS1_v1_5  # noqa: E402

URL = "http://43.145.33.254:27990/app/video/device-base"


def latest_body():
    best = None
    with open(os.path.join(HERE, "bodies_now.jsonl"), encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if "device-base" in o.get("req", "") and o.get("req_body_ascii"):
                best = o  # 文件按时间追加，取最后一条
    return best


def main():
    cap = latest_body()
    assert cap, "bodies_now.jsonl 无 device-base 样本"
    body = cap["req_body_ascii"]
    print(f"[1] 重放请求体: len={len(body)} head={body[:48]}...")

    ts = int(time.time() * 1000)
    auth = authgen.gen(ts)
    print(f"[2] 现签完成: ts={ts} auth={auth[:32]}... (len={len(auth)})")

    headers = {
        "appid": "4150439554430529",
        "ts": str(ts),
        "nonce": "12345678",
        "tcs": "2",
        "x-version": "2020-09-17",
        "authentication": auth,
        "content-type": "application/json; charset=utf-8",
        "user-agent": "Dart/3.6 (dart:io)",
    }
    req = urllib.request.Request(URL, data=body.encode(), headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=25)
        status = resp.status
        rheaders = dict(resp.headers)
        rbody = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        rheaders = dict(e.headers)
        rbody = e.read().decode("utf-8", "replace")

    print(f"[3] HTTP {status}")
    interesting = {k: v for k, v in rheaders.items()
                   if k.lower() in ("new-token", "content-type", "content-length", "server", "date")}
    print(f"    响应头(关键): {interesting}")
    print(f"    响应体前 100 字符: {rbody[:100]}")

    out = os.path.join(HERE, "live_check_resp.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write(rbody)
    print(f"    已落盘: {out} (len={len(rbody)})")

    # ---- 响应形态判定 ----
    if rbody.lstrip().startswith("{"):
        print("[4] 响应 = 明文 JSON（鉴权失败/错误路径）")
        print("    " + rbody[:300])
        return 1
    if "." not in rbody:
        print("[4] 响应形态未知")
        return 1
    p0, p1 = split_body(rbody) if "split_body" in dir() else (None, None)
    if p0 is None:
        p0, p1 = rbody.split(".", 1)
    print(f"[4] 响应 = <P0>.<P1> 密文: P0={len(p0)}ch P1={len(p1)}ch (P1%16b={len(custom_b64d(p1)) % 16})")

    # ---- 现场 P0 解包验证 ----
    raw = custom_b64d(p0)
    print(f"[5] P0 解码: {len(raw)}B, head={raw[:8].hex()}")
    priv = RSA.import_key(open(os.path.join(HERE, "priv_from_go.pem"), "rb").read())
    k16 = PKCS1_v1_5.new(priv).decrypt(raw, None)
    if k16 is None:
        print("    PKCS1-v1.5 解密失败（私钥不匹配当日流量？）")
        return 1
    print(f"[6] K16 解出: hex={k16.hex()} ascii={k16!r} len={len(k16)}")
    print("=> 请求链路 OK；响应 P1 需 K16→(AES key,IV) 派生公式（当前卡点）才能解")
    return 0


if __name__ == "__main__":
    sys.exit(main())
