"""快速探测：只看响应形态（是否 <P0>.<P1> 信封 / 明文错误码），不解密，避免长耗时。"""
import http.client
import json
import urllib.parse

LOCAL = ("127.0.0.1", 8791)
REMOTE = ("43.145.33.254", 27990)


def forge(path, params="{}"):
    c = http.client.HTTPConnection(*LOCAL, timeout=180)
    q = "/forge?path=" + urllib.parse.quote(path) + "&params=" + urllib.parse.quote(params)
    c.request("GET", q)
    d = json.loads(c.getresponse().read().decode())
    c.close()
    return d


def send(method, path, params="{}", with_body=False, nonce="12345678"):
    f = forge(path, params)
    h = {
        "x-version": "2020-09-17",
        "user-agent": "Dart/3.6 (dart:io)",
        "appid": "4150439554430529",
        "tcs": "2",
        "host": "43.145.33.254:27990",
        "ts": str(f["ts"]),
        "nonce": nonce,
        "authentication": f["authentication"],
    }
    body = None
    if with_body:
        h["content-type"] = "application/json; charset=utf-8"
        body = f["body"].encode()
    c = http.client.HTTPConnection(*REMOTE, timeout=20)
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    raw = r.read().decode("utf-8", "replace")
    st = r.status
    c.close()
    tag = "WITHBODY" if with_body else "NOBODY  "
    if raw.startswith("{"):
        shape = "PLAIN " + raw[:90]
    elif raw.count(".") == 1 and len(raw) > 400:
        shape = "ENVELOPE(len=%d) -> 认证+参数均通过" % len(raw)
    else:
        shape = "OTHER " + raw[:90]
    print("%s %-4s %-46s status=%s %s" % (tag, method, path[:46], st, shape), flush=True)


if __name__ == "__main__":
    send("GET", "/app/vod_comment/gettop?vid=113354", nonce="13572468")
    send("GET", "/app/video/list?channel=1&sort=weight&limit=6&page=1")
    send("GET", "/app/video/list?channel=1&sort=weight&limit=6&page=1", with_body=True)
    send("GET", "/app/video/list?channel=1&sort=weight&limit=6&page=1", nonce="13572468")
