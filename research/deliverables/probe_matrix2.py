# -*- coding: utf-8 -*-
# probe_matrix2.py — 按真机抓包的真实方法横扫端点
import os, sys, time, json, random, http.client
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import authgen as AG

CASES = [
    ("GET", "/app/config", None),
    ("GET", "/app/banners/0", None),
    ("GET", "/app/channel?top-level=true", None),
    ("GET", "/app/video/list?channel=1&sort=weight&limit=6&page=1", None),
    ("GET", "/app/video/detail?id=103558&cid=2", None),
    ("GET", "/app/video/search?keyword=%E5%99%AC%E5%99%AC", None),
    ("GET", "/app/vod_comment/getlist?vid=103558&cid=2&page=1", None),
    ("GET", "/app/video_update_list/2026-09-29", None),
    ("GET", "/app/task/sign_rule", None),
    ("GET", "/app/video/key", None),
    ("POST", "/app/config/channel", b""),
    ("POST", "/app/config/video", b""),
    ("POST", "/app/users/task", b""),
    ("POST", "/app/users/clearimg", b""),
    ("POST", "/app/messagebox/dynamic", b""),
    ("POST", "/app/messagebox/give_me", b""),
    ("POST", "/app/history/localcahce", b""),
    ("POST", "/app/history", b""),
    ("POST", "/app/video/device-base", b""),
    ("POST", "/app/video/record", b""),
    ("POST", "/app/video/play-connect", b""),
    ("POST", "/app/video/play", b""),
]


def classify(d):
    if not d:
        return "空"
    if d.lstrip().startswith(b"{"):
        try:
            return "明文JSON code=%s" % json.loads(d.decode("utf-8", "replace")).get("code")
        except Exception:
            return "明文JSON(截断)"
    a, _, b = d[:400].partition(b".")
    if len(a) > 200 and len(b) > 8:
        return "加密 P0.P1"
    return "其它(%d B)" % len(d)


def req(method, path, auth, ts, nonce, body=None):
    c = http.client.HTTPConnection("43.145.33.254", 27990, timeout=15)
    h = {"x-version": "2020-09-17", "user-agent": "Dart/3.6 (dart:io)",
         "appid": AG.APPID_HEADER, "ts": str(ts), "accept-encoding": "identity",
         "authentication": auth, "tcs": "2",
         "content-type": "application/json; charset=utf-8", "nonce": nonce}
    if body is not None:
        h["content-length"] = str(len(body))
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    d = r.read()
    c.close()
    return r.status, d


def main():
    ts = int(time.time() * 1000)
    auth = AG.gen(ts)
    print("同一 auth (ts=%d, 152 字符) 横扫 %d 个端点\n" % (ts, len(CASES)))
    print("%-5s %-52s %-5s %-9s %s" % ("方法", "路径", "HTTP", "大小", "响应形态"))
    print("-" * 108)
    ok = bad = 0
    for m, p, b in CASES:
        n = "%08d" % random.randint(0, 99999999)
        try:
            st, d = req(m, p, auth, ts, n, b)
        except Exception as ex:
            print("%-5s %-52s 异常 %r" % (m, p[:52], ex)); bad += 1; continue
        enc = st == 200 and not d.lstrip().startswith(b"{") and len(d) > 8
        print("%-5s %-52s %-5s %-9d %s" % (m, p[:52], st, len(d), classify(d)))
        if enc:
            ok += 1
        else:
            bad += 1
    print()
    print("可用(200 + 加密业务数据): %d/%d    不可用: %d" % (ok, len(CASES), bad))
    print()
    print("--- 对照 ---")
    st, d = req("GET", "/app/config", "", ts, "%08d" % random.randint(0, 99999999))
    print("%-5s %-52s %-5s %-9d %s" % ("GET", "/app/config (空 auth)", st, len(d), classify(d)))
    st, d = req("GET", "/app/config", auth, ts - 3600_000, "%08d" % random.randint(0, 99999999))
    print("%-5s %-52s %-5s %-9d %s" % ("GET", "/app/config (ts-1h)", st, len(d), classify(d)))


if __name__ == "__main__":
    main()
