# -*- coding: utf-8 -*-
"""tmp_w1_playchain.py — 播放全链路实测：config→列表→详情→play 凭证→解析器→直链。

全程离线签名/伪造/解密（authgen_server.forge + decrypt_response），不依赖设备。
产物落盘 research/tmp_w1_playchain_out.json。
"""
import hashlib
import http.client
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, os.path.join(HERE, "captures", "rsa_scan"))
sys.path.insert(0, os.path.join(HERE, "..", "src", "tools"))

import authgen_server as S  # noqa: E402

OUT = {}


def call_jcy(method, path, params_json="{}", label=""):
    """打囧次元真实服务端并离线解密。GET 无 body；POST body=伪造信封。"""
    p0 = path.split("?")[0]
    f = S.forge(params_json, p0)
    h = {
        "x-version": "2020-09-17", "user-agent": "Dart/3.6 (dart:io)",
        "appid": "4150439554430529", "tcs": "2",
        "content-type": "application/json; charset=utf-8",
        "host": "43.145.33.254:27990",
        "ts": str(f["ts"]), "nonce": "%08d" % random.randint(0, 99999999),
        "authentication": f["authentication"],
    }
    conn = http.client.HTTPConnection("43.145.33.254", 27990, timeout=20)
    body = f["body"].encode() if method.upper() == "POST" else None
    if body is None:
        h.pop("content-type", None)
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    raw = r.read().decode("utf-8", "replace")
    conn.close()
    t0 = time.time()
    dec = S.decrypt_response(raw)
    dec["decrypt_s"] = round(time.time() - t0, 2)
    j = dec.get("json")
    print("[%s] %s %s -> HTTP %s, code=%s, 解密%.1fs" %
          (label, method, path[:70], r.status,
           (j or {}).get("code") if isinstance(j, dict) else "?", dec["decrypt_s"]), flush=True)
    if not isinstance(j, dict):
        print("    !plain:", repr(dec.get("plain", ""))[:200], flush=True)
    return dec


def main():
    # ---- 1) 全局配置（platform / version 供解析器签名用）----
    dec = call_jcy("GET", "/app/config", label="1 配置")
    cfg = dec.get("json") or {}
    OUT["config"] = cfg
    # 递归找 platform / version / appVersion 字段
    found = {}

    def _walk(o, path=""):
        if isinstance(o, dict):
            for k, v in o.items():
                kl = str(k).lower()
                if kl in ("platform", "version", "appversion", "app_version", "ver") and not isinstance(v, (dict, list)):
                    found[path + k] = v
                _walk(v, path + k + ".")
        elif isinstance(o, list):
            for i, v in enumerate(o[:3]):
                _walk(v, path + "%d." % i)
    _walk(cfg)
    print("    版本/平台候选字段:", json.dumps(found, ensure_ascii=False)[:400], flush=True)
    data = cfg.get("data") if isinstance(cfg.get("data"), dict) else cfg

    # ---- 2) 视频列表 ----
    dec = call_jcy("GET", "/app/video/list?channel=1&sort=weight&limit=6&page=1", label="2 列表")
    lst = (dec.get("json") or {}).get("data") or {}
    items = lst.get("items") or []
    vid = items[0].get("id") if items else None
    vname = items[0].get("name") if items else None
    print("    total=%s 选定 id=%s name=%r" % (lst.get("total"), vid, vname), flush=True)
    OUT["list_first"] = items[0] if items else None

    if not vid:
        print("!! 无视频 id，终止", flush=True)
        return

    # ---- 3) 视频详情 ----
    dec = call_jcy("GET", "/app/video/detail?id=%s" % vid, label="3 详情")
    det = dec.get("json") or {}
    OUT["detail"] = det
    dd = det.get("data") if isinstance(det.get("data"), dict) else det
    # 找集数/播放格式线索
    for k in ("play", "part", "parts", "episode", "episodes", "urls", "url", "source", "quality", "line"):
        if k in dd:
            v = dd[k]
            print("    detail.%s = %s" % (k, json.dumps(v, ensure_ascii=False)[:220]), flush=True)

    # ---- 4) 播放凭证（参数走 query，body={}，V14 配方）----
    part = None
    play_fmt = "mp4"
    for ln in (dd.get("parts") or []):
        if isinstance(ln, dict) and ln.get("part"):
            part = ln["part"][0]
            play_fmt = ln.get("play") or play_fmt
            break
    part = part or "第1集"
    from urllib.parse import quote
    q = "/app/video/play?id=%s&play=%s&part=%s" % (vid, quote(str(play_fmt)), quote(str(part)))
    dec = call_jcy("POST", q, "{}", label="4 播放凭证")
    play = dec.get("json") or {}
    OUT["play"] = play
    pd = play.get("data") if isinstance(play.get("data"), dict) else play
    print("    play.data keys:", list(pd.keys())[:15] if isinstance(pd, dict) else type(pd), flush=True)
    print("    play.data =", json.dumps(pd, ensure_ascii=False)[:500], flush=True)

    # ---- 5) 解析器（签名算法取自 play 响应下发的现役 lua：盐=pzizhsqjjt）----
    entry = pd.get("data")[0] if isinstance(pd.get("data"), list) and pd.get("data") else {}
    source = entry.get("url")
    lua = entry.get("parse") or ""
    import re as _re
    m_k = _re.search(r'aes_key\s*=\s*"([^"]+)"', lua)
    m_i = _re.search(r'aes_iv\s*=\s*"([^"]+)"', lua)
    aes_key, aes_iv = (m_k.group(1) if m_k else "rdcibneoapyspqlt"), (m_i.group(1) if m_i else "fyoofrebaxjwioxn")
    if not source:
        print("!! play 响应中未找到 source(url) 字段", flush=True)
        json.dump(OUT, open(os.path.join(HERE, "tmp_w1_playchain_out.json"), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        return
    ts = int(time.time() * 1000)
    ver = "1.5.8.0"          # device_info["app_version"]（auth S 串同源）
    plat = "Android"         # device_info["platform"]
    SALT = "pzizhsqjjt"      # 现役盐（lua 实证，非 go-jocy 旧情报的 v50gjcy）
    s1 = hashlib.md5((ver + SALT + str(ts)).encode()).hexdigest()
    s2 = hashlib.md5((source + SALT + str(ts)).encode()).hexdigest()
    purl = "/vo1v03.php?url=" + source + "&t=" + str(ts)
    print("[5 解析器] GET http://yh.jx.xajtl.com%s" % purl[:100], flush=True)
    print("    version=%s x-sign1=%s x-sign2=%s aes=%s/%s" % (ver, s1, s2, aes_key, aes_iv), flush=True)
    conn = http.client.HTTPConnection("yh.jx.xajtl.com", 80, timeout=20)
    conn.request("GET", purl, headers={
        "x-time": str(ts), "x-form": plat, "x-sign1": s1, "x-sign2": s2,
        "user-agent": "Dart/3.6 (dart:io)",
    })
    r = conn.getresponse()
    praw = r.read()
    conn.close()
    print("    -> HTTP %s  %dB  ct=%s" % (r.status, len(praw), r.getheader("content-type")), flush=True)
    ptxt = praw.decode("utf-8", "replace")
    OUT["parser"] = {"url": "http://yh.jx.xajtl.com" + purl, "status": r.status,
                     "body_head": ptxt[:300], "aes_key": aes_key, "aes_iv": aes_iv}
    pobj = None
    try:
        pobj = json.loads(ptxt)
        print("    响应形态: 明文 JSON", flush=True)
    except Exception:
        # lua parse_response 兜底：AES128-CBC 解密再解析
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            raw = bytes.fromhex(ptxt.strip()) if _re.fullmatch(r"[0-9a-fA-F]+", ptxt.strip() or "x") else None
            if raw is None:
                from jcy_protocol.auth import custom_b64d
                try:
                    raw = custom_b64d(ptxt.strip())
                except Exception:
                    import base64
                    raw = base64.b64decode(ptxt.strip() + "=" * (-len(ptxt.strip()) % 4))
            dec = unpad(AES.new(aes_key.encode(), AES.MODE_CBC, aes_iv.encode()).decrypt(raw), 16)
            ptxt2 = dec.decode("utf-8", "replace")
            pobj = json.loads(ptxt2)
            OUT["parser"]["body"] = ptxt2
            print("    响应形态: AES128-CBC 解密成功 -> JSON", flush=True)
        except Exception as e:
            print("    !! 明文与 AES 解密均失败: %r" % e, flush=True)
            print("    body[:400]:", ptxt[:400], flush=True)
    OUT["parser_obj"] = pobj
    if pobj and isinstance(pobj.get("data"), dict):
        pa = pobj["data"].get("playAddr")
        print("    code=%s playAddr 类型: %s" % (pobj.get("code"), type(pa).__name__), flush=True)
        OUT["playAddr"] = pa
        if isinstance(pa, list):
            for i, item in enumerate(pa[:8]):
                du = (item.get("m3u8FileDomain") or "") + (item.get("addr") or "")
                print("    [%d] %s" % (i, json.dumps(item, ensure_ascii=False)[:220]), flush=True)

    json.dump(OUT, open(os.path.join(HERE, "tmp_w1_playchain_out.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("已落盘 tmp_w1_playchain_out.json", flush=True)


if __name__ == "__main__":
    main()
