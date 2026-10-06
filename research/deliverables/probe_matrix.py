# -*- coding: utf-8 -*-
# probe_matrix.py — 用 authgen 生成的 auth 横扫多端点, 给出当前可请求能力矩阵
import os, sys, time, json, random
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import authgen as AG

GETS = [
    "/app/config",
    "/app/banners/0",
    "/app/channel?top-level=true",
    "/app/video/list?channel=1&sort=weight&limit=6&page=1",
    "/app/messagebox/dynamic",
    "/app/task/sign_rule",
    "/app/config/channel",
    "/app/config/video",
    "/app/users/task",
    "/app/history/localcahce",
]

POSTS = [
    ("/app/users/clearimg", b""),
    ("/app/upgrade", b""),
]


def classify(data: bytes):
    if not data:
        return "空"
    s = data[:200]
    if s.lstrip().startswith(b"{"):
        try:
            j = json.loads(data.decode("utf-8", "replace"))
            return "明文JSON code=%s" % j.get("code")
        except Exception:
            return "明文JSON(截断)"
    if b"." in data[:400]:
        a, _, b = data.partition(b".")
        if len(a) > 200 and len(b) > 8:
            return "加密 P0.P1 (P0=%dB, P1=%dB)" % (len(a), len(b))
    return "其它(%d B)" % len(data)


def req(method, path, auth, ts, nonce, body=None):
    import http.client
    c = http.client.HTTPConnection("43.145.33.254", 27990, timeout=15)
    h = {"x-version": "2020-09-17", "user-agent": "Dart/3.6 (dart:io)",
         "appid": AG.APPID_HEADER, "ts": str(ts), "accept-encoding": "identity",
         "authentication": auth, "tcs": "2",
         "content-type": "application/json; charset=utf-8", "nonce": nonce}
    if body:
        h["content-length"] = str(len(body))
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    d = r.read()
    c.close()
    return r.status, d


def main():
    ts = int(time.time() * 1000)
    auth = AG.gen(ts)
    print("auth ts=%d len=%d" % (ts, len(auth)))
    print("前20字符: %s" % auth[:20])
    print()
    print("%-58s %-6s %-9s %s" % ("端点", "HTTP", "大小", "响应形态"))
    print("-" * 100)
    same_auth_ok = 0
    for p in GETS:
        n = "%08d" % random.randint(0, 99999999)
        try:
            st, d = req("GET", p, auth, ts, n)
            print("%-58s %-6s %-9d %s" % (p[:58], st, len(d), classify(d)))
            if st == 200 and not d.lstrip().startswith(b"{"):
                same_auth_ok += 1
        except Exception as ex:
            print("%-58s 异常 %r" % (p[:58], ex))
    print()
    print("同一 auth 跨端点可用: %d/%d" % (same_auth_ok, len(GETS)))
    print()
    print("--- POST 类 (无 body) ---")
    for p, b in POSTS:
        n = "%08d" % random.randint(0, 99999999)
        try:
            st, d = req("POST", p, auth, ts, n, b)
            print("%-58s %-6s %-9d %s" % (p[:58], st, len(d), classify(d)))
        except Exception as ex:
            print("%-58s 异常 %r" % (p[:58], ex))
    print()
    print("--- 无 auth 对照 ---")
    st, d = req("GET", "/app/config", "", ts, "%08d" % random.randint(0, 99999999))
    print("%-58s %-6s %-9d %s" % ("/app/config (空 auth)", st, len(d), classify(d)))


if __name__ == "__main__":
    main()
