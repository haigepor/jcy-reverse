# -*- coding: utf-8 -*-
"""tmp_w1_playtest.py — 直链可播性实测（按 lua custom_head 规则构造请求头）。

读取 tmp_w1_playchain_out.json 的 playAddr，对每条直链发 Range 请求，
校验 HTTP 206 / 内容类型 / 文件魔数（mp4 ftyp / m3u8 #EXTM3U）。
"""
import json
import os
import ssl
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def custom_head(url):
    # 与 lua custom_head() 逐条对应
    h = {"User-Agent": "", "Referer": url}
    if "aliyuncs.com" in url:
        h["Referer"] = "https://www.piccopilot.com"
    elif "toutiaovod.com" in url:
        h["Referer"] = ""
    elif "kwimgs.com" in url:
        h["Referer"] = "https://www.kuaishou.com"
    elif "dcarvod.com" in url:
        h["Referer"] = "https://www.dongchedi.com"
    elif "douyinvod.com" in url:
        h["Referer"] = "https://www.douyin.com"
    return h


def probe(url, tag):
    h = custom_head(url)
    t0 = time.time()
    req = urllib.request.Request(url, headers=dict(h, **{"Range": "bytes=0-4095"}))
    try:
        r = urllib.request.urlopen(req, timeout=25, context=ssl_ctx)
    except Exception as e:
        print("[%s] FAIL %r" % (tag, e))
        return None
    body = r.read(4096)
    dt = time.time() - t0
    cr = r.headers.get("Content-Range") or ""
    out = {
        "tag": tag, "status": r.status, "content_type": r.headers.get("Content-Type"),
        "content_range": cr, "got": len(body), "latency_s": round(dt, 2),
        "magic": body[:16].hex(), "ascii_head": repr(body[:48]),
    }
    kind = "?"
    if body[:4] == b"\x00\x00\x00 ftyp"[4:8] or b"ftyp" in body[:32]:
        kind = "MP4(ftyp)"
    if body.lstrip()[:7] == b"#EXTM3U":
        kind = "M3U8"
    if body[:3] == b"FLV":
        kind = "FLV"
    if body[:4] == b"\x1aE\xdf\xa3":
        kind = "MKV/EBML"
    out["kind"] = kind
    print("[%s] HTTP %s %s  ct=%s  cr=%s  %.2fs" % (
        tag, r.status, kind, out["content_type"], cr[:60], dt))
    print("     head=%r" % body[:40])
    return out


def main():
    d = json.load(open(os.path.join(HERE, "tmp_w1_playchain_out.json"), encoding="utf-8"))
    pa = d.get("playAddr") or []
    print("playAddr 条数:", len(pa), flush=True)
    results = []
    for i, item in enumerate(pa):
        url = (item.get("m3u8FileDomain") or "") + (item.get("addr") or "")
        tag = "%s/%s" % (item.get("desc"), item.get("title"))
        print("\n[%d] %s  format=%s vcodec=%s" % (i, tag, item.get("format"), item.get("vcodec")))
        print("    %s" % url)
        res = probe(url, tag)
        if res:
            res["url"] = url
            results.append(res)
    json.dump(results, open(os.path.join(HERE, "tmp_w1_playtest_out.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\n结果落盘 tmp_w1_playtest_out.json；可播: %d/%d" % (len(results), len(pa)))


if __name__ == "__main__":
    main()
