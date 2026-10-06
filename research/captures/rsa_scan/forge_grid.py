# -*- coding: utf-8 -*-
"""forge_grid.py — 请求 P0 构造参数网格搜索（live server 探测）。

维度: padding {v1.5, oaep, raw} × 载荷 {key+iv, iv+key, key} × 字母表 {custom, std}
      × params {full, empty}
"""
import base64
import json
import random
import re
import subprocess
import sys
import time

import requests
from Crypto.Cipher import AES, PKCS1_v1_5, PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ALPHA = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"
HERE = "research/captures/rsa_scan"

PUB = RSA.import_key(open(HERE + "/server_pub_2048_live.pem", "rb").read())
KEY16 = bytes(range(0x61, 0x71))
IV16 = bytes(range(0x41, 0x51))

PARAMS_FULL = ('{"app_id":"4150439554430529","device_id":"16613a7076284a15bc723d018bcd67e1",'
               '"code_version":"3.0.0.8","app_version":"1.5.8.0","files_path":'
               '"/data/user/0/com.tudou.tool/files","tcp":"43.145.33.254:8191"}')
PARAMS_MIN = "{}"


def cb64(b, custom):
    s = base64.b64encode(b).decode()
    return s.translate(str.maketrans(STD, ALPHA)) if custom else s


def rsa_enc(mode, payload):
    m = payload
    if mode == "v15":
        return PKCS1_v1_5.new(PUB).encrypt(m)
    if mode == "oaep":
        return PKCS1_OAEP.new(PUB, hashAlgo=SHA1).encrypt(m)
    # raw
    c = pow(int.from_bytes(m, "big"), PUB.e, PUB.n)
    return c.to_bytes(256, "big")


def gen_auth(ts):
    out = subprocess.run(
        [sys.executable, "research/deliverables/authgen.py", "--ts", str(ts)],
        capture_output=True, text=True, timeout=300)
    for line in (out.stdout + out.stderr).splitlines():
        if "auth" in line and "=" in line:
            v = line.split("=", 1)[1].strip()
            if len(v) >= 100:
                return v
    raise RuntimeError("authgen fail")


def try_one(mode, layout, custom, params):
    if layout == "kiv":
        payload = KEY16 + IV16
    elif layout == "ivk":
        payload = IV16 + KEY16
    else:
        payload = KEY16
    p0 = rsa_enc(mode, payload)
    p1 = AES.new(KEY16, AES.MODE_CBC, IV16).encrypt(pad(params.encode(), 16))
    body = cb64(p0, custom) + "." + cb64(p1, custom)
    ts = int(time.time() * 1000)
    auth = gen_auth(ts)
    h = {"user-agent": "Dart/3.6 (dart:io)", "accept-encoding": "gzip",
         "x-version": "2020-09-17", "appid": "4150439554430529", "ts": str(ts),
         "tcs": "2", "nonce": "%08d" % random.randint(0, 99999999),
         "authentication": auth, "content-type": "application/json; charset=utf-8"}
    r = requests.post("http://43.145.33.254:27990/app/video/device-base",
                      data=body.encode(), headers=h, timeout=20)
    txt = r.text.strip()
    note = ""
    if "." in txt:
        try:
            raw1 = base64.b64decode(txt.split(".", 1)[1].translate(
                str.maketrans(ALPHA, STD)) + "=" * (-len(txt.split(".", 1)[1]) % 4))
            pt = AES.new(KEY16, AES.MODE_CBC, IV16).decrypt(raw1)
            pt = pt[:-pt[-1]]
            if pt[:1] == b"{":
                note = " ★★★响应可用我方key解密: " + pt[:200].decode("utf-8", "replace")
        except Exception as e:
            note = " (P1解密失败 %s)" % e
    return "HTTP %s len=%d %s%s" % (r.status_code, len(txt), txt[:120], note)


def main():
    seen = {}
    for mode in ("v15", "oaep", "raw"):
        for layout in ("kiv", "ivk", "k"):
            for custom in (True, False):
                for pname, params in (("full", PARAMS_FULL), ("min", PARAMS_MIN)):
                    tag = "%s/%s/%s/%s" % (mode, layout, "custom" if custom else "std", pname)
                    try:
                        res = try_one(mode, layout, custom, params)
                    except Exception as e:
                        res = "EXC %s" % e
                    key = res[:80]
                    seen.setdefault(key, []).append(tag)
                    print("%-32s → %s" % (tag, res[:150]), flush=True)
    print("\n=== 错误分组:")
    for k, v in seen.items():
        print("%d× %s" % (len(v), k))


if __name__ == "__main__":
    main()
