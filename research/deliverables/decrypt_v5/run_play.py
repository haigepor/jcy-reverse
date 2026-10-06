# -*- coding: utf-8 -*-
"""端到端: 解析囧次元播放地址 (m3u8 / mp4 直链)。

链路 (全链已验证, 2026-09-29):
  1) app: GET/POST /app/video/play?id=<vid>&play=mp4&part=<集>   → 响应 <P0>.<P1> 密文
  2) app 解密得到: {"url":"http://yh.jx.xajtl.com/vo1v03.php?url=...&t=...",
                    "header":{"x-time":..,"x-sign1":..,"x-sign2":..,"x-form":"Android"}}
  3) 带 header 请求该 url → {"data":{"playAddr":[{"addr":"/xxx/","m3u8FileDomain":"https://v9.douyinvod.com","format":"MP4",...}]}}
  4) 最终直链 = m3u8FileDomain + addr  → 实测 200 / video/mp4 / 146,763,786 bytes

本脚本:
  * --extract        从运行中 app 内存取回步骤 2 的 JSON (已验证)
  * --from-sample    用 samples/play_url.json 演示步骤 3+4 (离线, 会真实发起请求)
  * --resolve        对给定 url/header 执行步骤 3+4

用法:
    python run_play.py --extract
    python run_play.py --from-sample
"""
import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mem_plaintext import extract  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "samples", "play_url.json")
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"


def extract_play_url(max_hits=3):
    """从进程内存取回播放地址 JSON (步骤 2 的产物)。"""
    res = extract('"url":"http', back=4096, fwd=8192, max_hits=max_hits)
    for r in sorted(res, key=lambda x: -x["len"]):
        try:
            obj = json.loads(r["text"])
        except Exception:
            continue
        if "url" in obj and "header" in obj:
            return obj
    return None


def http_get(url, headers=None, timeout=25):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read()


def resolve(play_obj):
    """执行步骤 3+4: 换取 playAddr 并拼出最终直链。

    注意: url 中的 url= 参数是**一次性令牌** —— 首次请求返回明文 JSON,
    重放同一 url 会被服务端拒绝 (返回 144 字节密文/挑战体)。
    因此 --extract 路径必须"新提取 → 立即解析"。
    """
    url = play_obj["url"]
    hdr = dict(play_obj.get("header") or {})
    status, _, body = http_get(url, hdr)
    print("[3] GET %s" % url[:110])
    print("    status=%s  bytes=%d" % (status, len(body)))
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception:
        print("    [!] 响应不是明文 JSON (%d 字节): %s" % (len(body), body[:80]))
        print("    [!] 判定为令牌已失效/重放拒绝 —— 请用 --extract 重新取一份新 url 后立即解析。")
        return []
    print("    code=%s msg=%s" % (data.get("code"), data.get("msg")))
    out = []
    for it in data.get("data", {}).get("playAddr", []):
        final = (it.get("m3u8FileDomain") or "").rstrip("/") + it.get("addr", "")
        out.append({
            "title": it.get("title"), "desc": it.get("desc"),
            "vcodec": it.get("vcodec"), "format": it.get("format"),
            "final_url": final,
        })
    print("[4] 最终直链:")
    for o in out:
        print("    %-4s %-6s %-5s %s" % (o["title"], o["desc"], o["vcodec"], o["final_url"]))
    return out


def verify(url, timeout=20):
    """HEAD/GET 校验直链可用性 (只读前 64 字节, 不下载整文件)。"""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Range": "bytes=0-63"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            head = r.read(64)
            return r.status, r.headers.get("Content-Type"), r.headers.get("Content-Range"), head[:16]
    except Exception as e:
        return None, type(e).__name__, str(e)[:80], b""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--extract", action="store_true", help="从 app 内存取回播放地址")
    ap.add_argument("--from-sample", action="store_true", help="用 samples/play_url.json 演示")
    ap.add_argument("--verify", action="store_true", help="校验最终直链 (Range 0-63)")
    a = ap.parse_args()

    if a.from_sample:
        play_obj = json.load(open(SAMPLE, encoding="utf-8"))
        print("[2] 样本 play_url.json 载入")
    elif a.extract:
        play_obj = extract_play_url()
        if not play_obj:
            print("未取到播放地址。请先在 app 里点开一个视频并开始播放。", file=sys.stderr)
            sys.exit(2)
        print("[2] 内存取回: %s" % json.dumps(play_obj, ensure_ascii=False)[:200])
    else:
        ap.print_help()
        return

    addrs = resolve(play_obj)
    if a.verify and addrs:
        print("[5] 直链校验 (Range 0-63):")
        for o in addrs:
            st, ct, cr, head = verify(o["final_url"])
            print("    status=%s type=%s range=%s head=%s" % (st, ct, cr, head.hex()))


if __name__ == "__main__":
    main()
