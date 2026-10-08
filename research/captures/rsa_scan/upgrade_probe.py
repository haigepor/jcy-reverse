# -*- coding: utf-8 -*-
"""upgrade_probe.py — 主动探测 /app/upgrade 旧式信封。

假设（请求 P0=256B 反推）：upgrade 通道用 libapp.so 0x540b2 的 RSA-1024 公钥
包裹 key16||iv16，随后 AES-CBC(key16, iv16, params JSON)。
请求体 = STD_B64(rsa_ct) + STD_B64(aes_ct)（无分隔符, 172+44=216 字符, 与捕获一致）。

用法:
    ./.venv/Scripts/python.exe research/captures/rsa_scan/upgrade_probe.py
"""
import base64
import json
import os
import subprocess
import sys
import time

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
RESEARCH = os.path.dirname(os.path.dirname(HERE))
ROOT = os.path.dirname(RESEARCH)
AUTHGEN = os.path.join(RESEARCH, "deliverables", "authgen.py")
sys.path.insert(0, os.path.join(ROOT, "src", "tools"))

PUB_PATH = os.path.join(HERE, "server_pub_from_libapp.pem")
HOST = "http://43.145.33.254:27990"
APPID = "4150439554430529"
DEVICE_FP = "16613a7076284a15bc723d018bcd67e1"


def std_b64(b):
    return base64.b64encode(b).decode()


def gen_auth(ts):
    out = subprocess.run(
        [sys.executable, AUTHGEN, "--ts", str(ts)],
        capture_output=True, text=True, timeout=300)
    txt = (out.stdout + out.stderr).strip()
    for line in txt.splitlines():
        line = line.strip()
        if "auth" in line and "=" in line:
            val = line.split("=", 1)[1].strip()
            if len(val) >= 100:
                return val
    raise RuntimeError("authgen 无输出: %s | %s" % (out.stdout[:200], out.stderr[:200]))


def build_body(pub, key16, iv16, params_json, alphabet="std", custom_b64=None,
               rsa_mode="raw"):
    m = int.from_bytes(key16 + iv16, "big")
    n, e = pub.n, pub.e
    if rsa_mode == "raw":
        c = pow(m, e, n)
        rsa_ct = c.to_bytes(128, "big")
    elif rsa_mode == "pkcs1":
        rsa_ct = PKCS1_v1_5.new(pub).encrypt(key16 + iv16)
    else:
        from Crypto.Cipher import PKCS1_OAEP
        rsa_ct = PKCS1_OAEP.new(pub).encrypt(key16 + iv16)
    aes_ct = AES.new(key16, AES.MODE_CBC, iv16).encrypt(pad(params_json, 16))
    b = std_b64(rsa_ct) + std_b64(aes_ct)
    if alphabet == "custom":
        STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        b = b.translate(str.maketrans(STD, custom_b64))
    return b


def main():
    pub = RSA.import_key(open(PUB_PATH, "rb").read())
    from jcy_protocol.auth import ALPHABET
    ts = int(time.time() * 1000)
    auth = gen_auth(ts)
    print("ts=%d auth=%s..." % (ts, auth[:40]))

    key16 = bytes(range(0x41, 0x51))   # 固定以便复现
    iv16 = bytes(range(0x61, 0x71))

    params_candidates = [
        b'{"code_version":"3.0.0.8"}',
        b'{"version":"1.5.8.0"}',
    ]
    for rsa_mode in ("raw", "pkcs1", "oaep"):
        for alphabet, alpha_src in (("std", None), ("custom", ALPHABET)):
            for params in params_candidates:
                body = build_body(pub, key16, iv16, params, alphabet, alpha_src,
                                  rsa_mode)
                headers = {
                    "Host": "43.145.33.254:27990",
                    "Accept": "*/*",
                    "Content-Type": "application/json",
                    "APPID": APPID,
                    "ts": str(ts),
                    "Authentication": auth,
                }
                url = HOST + "/app/upgrade"
                try:
                    r = requests.post(url, data=body.encode(), headers=headers, timeout=15)
                except Exception as e:
                    print("[%s %s %s] 请求失败: %s" % (rsa_mode, alphabet, params.decode(), e))
                    continue
                print("[%s %s %s] HTTP %s len=%d" % (rsa_mode, alphabet, params.decode(), r.status_code, len(r.content)))
                if r.status_code != 200 or not r.content:
                    continue
                raw = r.content
                txt = raw.decode("utf-8", "replace")
                is_b64 = all(c.isalnum() or c in "+/=" for c in txt[:64])
                print("  head=%r" % txt[:60])
                if is_b64 and len(txt) > 32:
                    STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    s = txt.strip()
                    s2 = s.translate(str.maketrans(ALPHABET, STD)) if alphabet == "custom" else s
                    try:
                        raw = base64.b64decode(s2 + "=" * (-len(s2) % 4))
                    except Exception as e:
                        print("  b64 解码失败 %s" % e)
                        continue
                # 用我们自己的 key/iv 尝试解密
                for name, data in (("full", raw), ("skip128", raw[128:]), ("skip256", raw[256:])):
                    if len(data) < 16 or len(data) % 16:
                        continue
                    pt = AES.new(key16, AES.MODE_CBC, iv16).decrypt(data)
                    if b"{" in pt[:16]:
                        print("  [%s] CBC 命中: %r" % (name, pt[:200]))
                        open(os.path.join(HERE, "upgrade_resp_plain.bin"), "wb").write(pt)
                    pt2 = AES.new(key16, AES.MODE_ECB).decrypt(data)
                    if b"{" in pt2[:16]:
                        print("  [%s] ECB 命中: %r" % (name, pt2[:200]))
                        open(os.path.join(HERE, "upgrade_resp_plain.bin"), "wb").write(pt2)
                if b"{" in raw[:8]:
                    print("  明文 JSON: %r" % raw[:200])
                    open(os.path.join(HERE, "upgrade_resp_plain.bin"), "wb").write(raw)
    print("done")


if __name__ == "__main__":
    main()
