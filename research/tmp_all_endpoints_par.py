# -*- coding: utf-8 -*-
"""tmp_all_endpoints_par.py — 多进程并行遍历全部 35 个接口（真实请求 + 离线解密）。

单进程逐块标定约 1.2s/块，35 个接口串行需数小时；本脚本用 N 进程并行，
每完成一个接口立即落盘（可中断续跑）。
"""
import os
import sys
import json
import time
import multiprocessing as mp

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
OUT = os.path.join(HERE, "tmp_all_endpoints.json")
RAW_DIR = os.path.join(HERE, "captures", "live_data_v2")

VID = "113354"
DATE = "2026-10-04"
EPS = [
    ("GET", "/app/config", None),
    ("GET", "/app/channel?top-level=true", None),
    ("GET", "/app/channel/", None),
    ("POST", "/app/config/channel", {}),
    ("POST", "/app/config/video", {}),
    ("GET", "/app/banners/0", None),
    ("GET", "/app/banners/1", None),
    ("GET", "/app/banners/2", None),
    ("GET", "/app/video/list?channel=1&sort=weight&limit=6&page=1", None),
    ("GET", "/app/video/detail?id=" + VID, None),
    ("GET", "/app/video/search?key=ai&limit=25&page=1", None),
    ("GET", "/app/video/key?key=ai&limit=10&page=1", None),
    ("GET", "/app/video_update_list/" + DATE, None),
    ("POST", "/app/video/record", {}),
    ("POST", "/app/video/play-connect", {}),
    ("POST", "/app/video/play", {}),
    ("POST", "/app/video/device-base", {}),
    ("GET", "/app/danmu?vid=" + VID + "&play=mp4&start_time_point=0&end_time_point=60000", None),
    ("GET", "/app/vod_comment/gettop?vid=" + VID, None),
    ("GET", "/app/vod_comment/gethitstop?vid=" + VID, None),
    ("GET", "/app/vod_comment/getlist?vid=" + VID + "&page=1", None),
    ("POST", "/app/users/clearimg", {}),
    ("POST", "/app/users/task", {}),
    ("POST", "/app/history", {}),
    ("POST", "/app/history/localcahce", {}),
    ("GET", "/app/task/sign_rule", None),
    ("POST", "/app/messagebox/give_me", {}),
    ("POST", "/app/messagebox/dynamic", {}),
    ("POST", "/app/upgrade", {}),
    ("GET", "/app/v2/config/host", None),
    ("GET", "/app/users/info", None),
    ("GET", "/app/vip_price/list", None),
    ("POST", "/app/task/task", {}),
    ("GET", "/app/playaddr/v4/client?vid=" + VID, None),
    ("POST", "/app/login/smscode", {}),
]


def _worker(item):
    method, path, params = item
    sys.path.insert(0, os.path.join(ROOT, "research", "deliverables"))
    sys.path.insert(0, os.path.join(ROOT, "research", "captures", "rsa_scan"))
    sys.path.insert(0, os.path.join(ROOT, "src", "tools"))
    import jcy_client as J
    cli = J.JcyClient()
    t0 = time.time()
    try:
        r = cli.request(method, path, params, timeout=25)
    except Exception as e:  # noqa: BLE001
        return path, {"method": method, "error": repr(e), "secs": round(time.time() - t0, 1)}
    dt = time.time() - t0
    if r["encrypted"]:
        txt = r["plain"].decode("utf-8", "replace")
        rec = {"method": method, "http": r["http"], "k16resp": r["k16resp"],
               "raw_len": r["raw_len"], "plain_len": len(r["plain"]),
               "json": r["json"], "plain": txt, "secs": round(dt, 1)}
    else:
        rec = {"method": method, "http": r["http"], "raw": r["raw"], "secs": round(dt, 1)}
    return path, rec


def main():
    n = int(os.environ.get("JCY_WORKERS", "6"))
    os.makedirs(RAW_DIR, exist_ok=True)
    res = {}
    if os.path.exists(OUT):
        try:
            res = json.load(open(OUT, encoding="utf-8"))
        except Exception:
            res = {}
    todo = [e for e in EPS if e[1] not in res]
    print("workers=%d  total=%d  todo=%d" % (n, len(EPS), len(todo)), flush=True)
    if not todo:
        print("全部已完成"); return 0
    done = len(res)
    with mp.Pool(n) as pool:
        for path, rec in pool.imap_unordered(_worker, todo):
            res[path] = rec
            done += 1
            if rec.get("error"):
                tag = "ERR " + rec["error"][:70]
            elif rec.get("raw") is not None:
                tag = "RAW %r" % rec["raw"][:70]
            else:
                code = (rec.get("json") or {}).get("code") if isinstance(rec.get("json"), dict) else None
                tag = "OK  %5dB code=%s" % (rec.get("plain_len", 0), code)
            print("[%2d/%d] %-4s %-52s %6.1fs %s" % (done, len(EPS), rec["method"], path, rec["secs"], tag), flush=True)
            json.dump(res, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("DONE %d/%d" % (len(res), len(EPS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
