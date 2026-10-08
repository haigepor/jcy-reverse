"""forge_v3.py — P0 只载 K16(16B 可打印), IV 派生假说网格
依据:
  - 响应 P0 = RSA(pub_from_go, K16) 仅 16B 可打印载荷 (134/134) → 镜像: 请求 P0 同构
  - emu api_encrypt 每请求仅一次 RAND_bytes(16) → key=rand16, iv=派生
  - 抓包: P1 恒 16B 单块 → pad('') 或 pad('{}')
变体: iv ∈ {K, md5(K), sha256(K)[:16], 0, Krev, MON前16, SIG前16} × K16 字符集 {大写数字, 小写}
      × P1 明文 {b'', b'{}'} × 字母表 custom(已证)
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
sys.path.insert(0, os.path.join(ROOT, "src", "tools"))
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


def iv_cands(k):
    return {
        "k": k,
        "md5(k)": hashlib.md5(k).digest(),
        "sha256(k)[:16]": hashlib.sha256(k).digest()[:16],
        "zero": bytes(16),
        "krev": k[::-1],
        "mon": MON_K,
        "sig": SIG_K,
    }


def main():
    upper_alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    lower_alnum = "abcdefghijklmnopqrstuvwxyz0123456789"
    hits = 0
    for cs_name, cs in (("upper", upper_alnum), ("lower", lower_alnum)):
        for plain in (b"", b"{}"):
            k = ("".join(random.choice(cs) for _ in range(16))).encode()
            p0 = PKCS1_v1_5.new(PUB).encrypt(k)
            for ivn, iv in iv_cands(k).items():
                p1 = AES.new(k, AES.MODE_CBC, iv).encrypt(pad(plain, 16))
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
                    print("  [%s/%s/%s] EXC %s" % (cs_name, plain, ivn, e))
                    continue
                hit = "." in rbody and len(rbody) > 100
                print("  [%s|%s|%s] http=%d len=%d %s" % (
                    cs_name, "empty" if plain == b"" else "{}", ivn, code, len(rbody),
                    "HIT" if hit else rbody[:60]))
                if hit:
                    hits += 1
                    open(os.path.join(HERE, "forge_v3_hit.jsonl"), "a").write(
                        json.dumps({"k": k.decode(), "iv": iv.hex(), "plain": plain.decode(),
                                    "body": body, "resp": rbody}) + "\n")
    print("done, hits =", hits)


if __name__ == "__main__":
    main()
