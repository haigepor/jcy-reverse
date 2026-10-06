# -*- coding: utf-8 -*-
"""tmp_upgrade_probe.py — 探测 /app/upgrade 特例端点（大写 Authentication / 非 P0.P1）。"""
import os
import sys
import json
import time
import http.client

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables"))
sys.path.insert(0, os.path.join(ROOT, "src"))

from jcy_protocol.auth import ALPHABET, STD_B64, custom_b64d  # noqa
import authgen_server as AS  # noqa
import jcy_client as J  # noqa

HOST, PORT = J.HOST, J.PORT
PATH = "/app/upgrade"


def send(headers, body, method="POST"):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=20)
    try:
        conn.request(method, PATH, body=body, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        return r.status, dict(r.getheaders()), raw
    finally:
        conn.close()


def main():
    ts, auth = J.JcyClient()._auth_header()
    base = dict(J.STATIC_HEADERS)
    base.update({"ts": str(ts), "nonce": "12345678"})
    results = {}

    # 1) 小写 authentication（主方案头），空体
    h1 = dict(base); h1["authentication"] = auth
    st, hd, raw = send(h1, b"")
    results["lower_empty"] = {"status": st, "len": len(raw), "head": raw[:120].hex(),
                              "text": raw[:200].decode("utf-8", "replace")}
    print("lower+empty   -> HTTP %s len=%d %r" % (st, len(raw), raw[:120]))

    # 2) 大写 Authentication
    h2 = dict(base); h2["Authentication"] = auth
    st, hd, raw = send(h2, b"")
    results["upper_empty"] = {"status": st, "len": len(raw), "head": raw[:120].hex(),
                              "text": raw[:200].decode("utf-8", "replace")}
    print("upper+empty   -> HTTP %s len=%d %r" % (st, len(raw), raw[:120]))

    # 3) 大写 + 216B 裸二进制 body（全零探测）
    h3 = dict(base); h3["Authentication"] = auth
    st, hd, raw = send(h3, b"\x00" * 216)
    results["upper_216"] = {"status": st, "len": len(raw), "head": raw[:200].hex(),
                            "text": raw[:300].decode("utf-8", "replace")}
    print("upper+216B    -> HTTP %s len=%d" % (st, len(raw)))
    print("   head hex:", raw[:160].hex())
    print("   text:", raw[:300].decode("utf-8", "replace"))

    # 4) 尝试把响应当 base64（标准 + 自定义）解码，看长度结构
    for name, txt in (("upper_216", results["upper_216"]["text"]),
                      ("upper_empty", results["upper_empty"]["text"])):
        s = txt.strip()
        if not s:
            continue
        import base64
        for label, trans in (("std", None), ("custom", str.maketrans(ALPHABET, STD_B64))):
            t = s if trans is None else s.translate(trans)
            t += "=" * (-len(t) % 4)
            try:
                b = base64.b64decode(t)
                results["%s_%s" % (name, label)] = {"len": len(b), "mod16": len(b) % 16,
                                                    "hex": b[:64].hex()}
                print("  [%s/%s] b64->%dB mod16=%d %s" % (name, label, len(b), len(b) % 16, b[:32].hex()))
            except Exception as e:  # noqa: BLE001
                print("  [%s/%s] 非 base64: %r" % (name, label, e))

    json.dump(results, open(os.path.join(HERE, "tmp_upgrade_probe.json"), "w",
                            encoding="utf-8"), ensure_ascii=False, indent=1)
    print("saved -> research/tmp_upgrade_probe.json")


if __name__ == "__main__":
    main()
