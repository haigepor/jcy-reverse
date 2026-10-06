# -*- coding: utf-8 -*-
"""jcy_fetch.py — 终端一键取数：本地伪造签名 → 直发真实服务端 → 离线解密 → 打印业务数据。

完全独立：不依赖「启动本地取签服务.bat」，自己在进程内完成取签 + 加解密。

用法（在项目根目录）::

    # 默认：视频列表
    ./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py

    # 指定接口（GET，query 参数直接写在路径里）
    ./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py "/app/video/list?channel=1&sort=weight&limit=6&page=1"

    # POST（参数走加密 body）
    ./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py /app/video/record --method POST --params '{}'

    # 只看响应形态，不解密（大响应秒回）
    ./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py "/app/video/list?channel=1&sort=weight&limit=6&page=1" --no-decrypt

    # 打印一份可粘进 Apipost 的 ts / authentication（2 分钟内有效）
    ./.venv/Scripts/python.exe research/deliverables/jcy_fetch.py --emit-auth

约定：
  * GET 端点**不能带 body**（带了服务端会把 body 当参数 → 40000）；POST 才带加密 body。
  * 成功码是 **20000**（不是 HTTP 200）；服务端错误也返回 HTTP 200，业务码在 JSON body。
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

try:  # Windows 控制台中文
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    pass

import authgen_server as S  # noqa: E402

HOST = "43.145.33.254"
PORT = 27990
DEFAULT_PATH = "/app/video/list?channel=1&sort=weight&limit=6&page=1"


def forge(params: str, path: str) -> dict:
    """本地伪造一次可直接发送的 (ts, authentication, body)。"""
    return S.forge(params, path)


def send(method: str, path: str, f: dict, timeout: float = 20.0):
    """把伪造结果发到真实服务端，返回 (status, raw_text)。"""
    h = {
        "x-version": "2020-09-17",
        "user-agent": "Dart/3.6 (dart:io)",
        "appid": "4150439554430529",
        "tcs": "2",
        "host": "%s:%d" % (HOST, PORT),
        "ts": str(f["ts"]),
        "nonce": str(int(time.time() * 1000) % 90000000 + 10000000),
        "authentication": f["authentication"],
    }
    body = None
    if method.upper() == "POST":
        h["content-type"] = "application/json; charset=utf-8"
        body = f["body"].encode()
    conn = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    conn.request(method.upper(), path, body=body, headers=h)
    r = conn.getresponse()
    raw = r.read().decode("utf-8", "replace")
    st = r.status
    conn.close()
    return st, raw


def summarize(j, limit: int = 3) -> str:
    """把解密后的 JSON 摘要成几行。"""
    if not isinstance(j, dict):
        return "  (非 JSON)"
    lines = ["  code = %s   message = %s" % (j.get("code"), j.get("message"))]
    data = j.get("data")
    if isinstance(data, list):
        lines.append("  data = list[%d]" % len(data))
        for it in data[:limit]:
            if isinstance(it, dict):
                name = it.get("name") or it.get("title") or it.get("id")
                lines.append("    - %s" % str(name)[:80])
    elif isinstance(data, dict):
        lines.append("  data.keys = %s" % list(data.keys())[:12])
        items = data.get("items")
        if isinstance(items, list):
            lines.append("  data.total = %s   items = %d" % (data.get("total"), len(items)))
            for it in items[:limit]:
                if isinstance(it, dict):
                    nm = it.get("name") or it.get("title") or it.get("id")
                    lines.append("    - %s" % str(nm)[:80])
    elif data is not None:
        lines.append("  data = %s" % str(data)[:200])
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="囧次元 终端一键取数（伪造签名 + 直发 + 离线解密）")
    ap.add_argument("path", nargs="?", default=DEFAULT_PATH,
                    help="接口路径（含 query），默认视频列表")
    ap.add_argument("--method", default=None, help="GET / POST，默认按路径自动判断（含 query→GET）")
    ap.add_argument("--params", default="{}", help="加密业务参数 JSON（POST 用）")
    ap.add_argument("--no-decrypt", action="store_true", help="只回原始信封，不解密（快）")
    ap.add_argument("--blocks", type=int, default=None,
                    help="只解前 N 块（秒级，明文截断，用于快速看 code / 前几条数据）")
    ap.add_argument("--emit-auth", action="store_true",
                    help="只打印可粘进 Apipost 的 ts / authentication，不发请求")
    ap.add_argument("--save", default=None, help="把原始响应与明文写到该前缀（.raw / .json）")
    a = ap.parse_args()

    path = a.path
    method = a.method or ("POST" if "?" not in path else "GET")

    t0 = time.time()
    print("=" * 64)
    print("[1/3] 本地伪造签名 (ts + authentication + 加密 body) …", flush=True)
    f = forge(a.params, path)
    print("      ts            = %s" % f["ts"])
    print("      authentication= %s… (%d 字符)" % (f["authentication"][:32], len(f["authentication"])))
    print("      body(P0.P1)   = %d 字符   k16=%s" % (len(f["body"]), f["k16"]))
    print("      path          = %s   method=%s" % (path, method.upper()))
    print("      耗时 %.2fs" % f["elapsed"], flush=True)

    if a.emit_auth:
        print("-" * 64)
        print("粘进 Apipost（2 分钟内有效）:")
        print("  ts             = %s" % f["ts"])
        print("  authentication = %s" % f["authentication"])
        print("  body (POST)    = %s" % f["body"])
        print("=" * 64)
        return 0

    print("[2/3] 发往真实服务端 http://%s:%d%s …" % (HOST, PORT, path), flush=True)
    try:
        st, raw = send(method, path, f)
    except Exception as exc:  # noqa: BLE001
        print("      ✗ 发送失败: %r" % (exc,))
        print("      排查：网络是否通 / 是否需要代理（本机 HTTP_PROXY 会劫持，脚本用直连）")
        return 2
    kind = S.classify(raw)
    print("      HTTP status = %s" % st)
    print("      响应形态    = %s  %s" % (kind.get("kind"), kind.get("note", "")))
    print("      响应长度    = %d 字符" % len(raw), flush=True)

    if a.save:
        with open(a.save + ".raw", "w", encoding="utf-8") as fp:
            fp.write(raw)
        print("      原始响应已写 %s.raw" % a.save)

    if kind.get("kind") != "encrypted":
        print("-" * 64)
        print("✗ 没拿到加密业务数据。响应原文：")
        print("  " + raw[:600])
        print("-" * 64)
        print("对照：")
        print("  authentication is empty → 签名头没带上")
        print("  authentication is error → 签名头值不对（Apipost 里 {{jcy_auth}} 没被替换）")
        print("  403501 / 403502         → ts 与 auth 不配对 / ts 太旧")
        print("  40000                   → 业务参数不对（GET 别带 body；danmu 要 part）")
        return 3

    if a.no_decrypt:
        print("      (--no-decrypt：跳过解密)")
        print("=" * 64)
        print("✅ 认证 + 参数均通过，服务端返回加密业务数据 %d 字符" % len(raw))
        return 0

    print("[3/3] 离线解密响应（逐块 tweak，≈0.02s/块）…", flush=True)
    t1 = time.time()
    d = S.decrypt_response(raw, a.blocks)
    if not d.get("ok"):
        print("      ✗ 解密失败: %s" % d.get("error"))
        return 4
    j = d.get("json")
    print("      k16resp=%s  p1_len=%d  nblk=%s  明文 %dB  解密耗时 %.1fs" % (
        d.get("k16resp"), d.get("p1_len"), d.get("nblk_total"),
        d.get("plain_len"), time.time() - t1))
    if d.get("partial"):
        print("      ⚠ 截断模式（只解了前 %s 块）——明文不完整，json 解析可能失败" % a.blocks)
    print("-" * 64)
    if j is None and d.get("partial"):
        print("  (截断明文，原样输出前 800 字符)")
        print("  " + (d.get("plain") or "")[:800])
    else:
        print(summarize(j))
    if a.save:
        with open(a.save + ".json", "w", encoding="utf-8") as fp:
            fp.write(d.get("plain") or "")
        print("      明文已写 %s.json" % a.save)
    code = (j or {}).get("code") if isinstance(j, dict) else None
    print("-" * 64)
    print("总耗时 %.1fs" % (time.time() - t0))
    print("=" * 64)
    if code == 20000:
        print("✅ 成功（业务码 20000）")
        return 0
    print("⚠ 认证层通过，但业务码 = %s（参数/权限问题，不是签名问题）" % code)
    return 5


if __name__ == "__main__":
    sys.exit(main())
