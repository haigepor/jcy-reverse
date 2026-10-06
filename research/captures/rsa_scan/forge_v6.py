# -*- coding: utf-8 -*-
"""forge_v6.py — 用真实自研密码 E (非 AES!) 伪造请求, 以服务端为判据找 f(K16)

关键修正: forge v5 用标准 AES 加密 P1 -> 密码选错, 负结果无效。
本版 P1 = CBC-E(key=f(K16), iv=g(K16), PKCS7(params)) —— E 由 Unicorn 管线提供。

判据: 响应 {"code":800131,"message":"通讯失败"} = P1 解不开;
      其它任何响应 (尤其 HTTP 200 + 加密 P0.P1 body) = f 命中。

用法:
  python forge_v6.py [--path /app/video/device-base] [--pt '{}'] [--only NAME]
"""
import argparse
import base64
import hashlib
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)

from jcy_protocol.auth import ALPHABET, STD_B64, AES_KEY, AES_IV  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402
from Crypto.Cipher import PKCS1_v1_5  # noqa: E402

_TO_CUSTOM = str.maketrans(STD_B64, ALPHABET)
URL_BASE = "http://43.145.33.254:27990"
PUB = RSA.import_key(open(os.path.join(HERE, "server_pub_2048_live.pem"), "rb").read())
MON_K = b"qPwClBj7j7ZQraSm"
SIG_K = b"p3JdVQl3q7WQJIgG"
Z16 = b"\x00" * 16

HEADERS_BASE = {
    "x-version": "2020-09-17",
    "user-agent": "Dart/3.6 (dart:io)",
    "appid": "4150439554430529",
    "tcs": "2",
    "content-type": "application/json; charset=utf-8",
    "host": "43.145.33.254:27990",
}


def cb64(b):
    return base64.b64encode(b).decode().translate(_TO_CUSTOM)


def gen_auth(ts):
    import subprocess
    out = subprocess.run(
        [sys.executable, "research/deliverables/authgen.py", "--ts", str(ts)],
        capture_output=True, text=True, timeout=300, cwd=ROOT)
    for line in (out.stdout + out.stderr).splitlines():
        if "auth" in line and "=" in line:
            v = line.split("=", 1)[1].strip()
            if len(v) >= 100:
                return v
    raise RuntimeError("authgen fail: " + (out.stdout + out.stderr)[-300:])


def md5(b):
    return hashlib.md5(b).digest()


def sha256(b):
    return hashlib.sha256(b).digest()


def candidates(K16):
    """key × iv 交叉积 (16 字节 K16 的常见派生)。"""
    hx = K16.hex().encode()
    keys = [
        ("authK", AES_KEY), ("K16", K16), ("K16x2", K16 * 2),
        ("md5", md5(K16)), ("md5x2", md5(K16) * 2),
        ("sha256", sha256(K16)), ("sha256_16", sha256(K16)[:16]),
        ("K16md5", K16 + md5(K16)), ("hex32", hx[:32]), ("hex16", hx[:16]),
        ("mon", MON_K), ("sig", SIG_K), ("monSig", MON_K + SIG_K),
        ("K16rev", K16[::-1]),
    ]
    ivs = [
        ("authIV", AES_IV), ("K16", K16), ("zero", Z16),
        ("md5_16", md5(K16)[:16]), ("sha256_16", sha256(K16)[:16]),
        ("K16rev", K16[::-1]), ("mon", MON_K), ("sig", SIG_K),
        ("K16x2_16", (K16 * 2)[:16]),
    ]
    return [("%s|%s" % (kn, ivn), kv, ivv)
            for kn, kv in keys for ivn, ivv in ivs]


def post(path, body, ts, nonce, auth, timeout=15):
    """直连 (不经宿主机 HTTP_PROXY 沙箱代理)。"""
    import http.client
    headers = dict(HEADERS_BASE)
    headers["ts"] = str(ts)
    headers["nonce"] = str(nonce)
    headers["authentication"] = auth
    try:
        conn = http.client.HTTPConnection("43.145.33.254", 27990, timeout=timeout)
        conn.request("POST", path, body=body.encode(), headers=headers)
        r = conn.getresponse()
        if os.environ.get("FORGE_DEBUG"):
            print("  [dbg] %s %s hdrs=%s" % (r.status, path, dict(r.getheaders())), flush=True)
        data = r.read().decode("utf-8", "replace")
        conn.close()
        return r.status, data
    except Exception as e:
        return -1, repr(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="/app/video/device-base")
    ap.add_argument("--pt", default="{}")
    ap.add_argument("--only", default=None)
    ap.add_argument("--ts", type=int, default=None)
    a = ap.parse_args()

    from e_oracle import EOracle
    print("[*] boot E oracle ...", flush=True)
    o = EOracle()
    print("[*] oracle ready", flush=True)

    pt = a.pt.encode()
    if len(pt) % 4:                       # E 预言机要求明文长度为 4 的倍数
        pt = pt + b" " * (-len(pt) % 4)   # JSON 允许尾随空白
    ts = a.ts or int(time.time() * 1000)
    nonce = str(random.randint(10_000_000, 99_999_999))
    print("[*] ts=%d nonce=%s pt=%r -> 生成 auth ..." % (ts, nonce, pt), flush=True)
    auth = gen_auth(ts)
    print("[*] auth 就绪 (%d 字符)" % len(auth), flush=True)

    results = []
    t_auth = time.time()
    for name, _k, _iv in candidates(b"\x00" * 16):
        if a.only and name != a.only:
            continue
        if time.time() - t_auth > 90:          # auth 有 ~120s 时效, 到期重签
            ts = int(time.time() * 1000)
            auth = gen_auth(ts)
            t_auth = time.time()
        K16 = os.urandom(16)
        # 重新按真实 K16 计算候选
        cand = dict((n, (kk, ii)) for n, kk, ii in candidates(K16))
        key, iv = cand[name]
        if len(key) not in (16, 32):
            key = (key + b"\x00" * 32)[:32]
        if len(iv) != 16:
            iv = (iv + b"\x00" * 16)[:16]
        try:
            p1 = o.enc(pt, key, iv)
        except Exception as e:
            print("[%s] E 加密失败: %r" % (name, e), flush=True)
            continue
        p0 = PKCS1_v1_5.new(PUB).encrypt(K16)
        body = cb64(p0) + "." + cb64(p1)
        st, rb = post(a.path, body, ts, nonce, auth)
        # 命中判定: 排除 800131(P1解不开) 与 auth 类错误(403501/403502/30000)
        bad = ("800131", "403501", "403502", "30000", "authentication")
        ok = st == 200 and not any(b in rb for b in bad)
        print("[%s] K16=%s key=%s iv=%s P1=%dB -> HTTP %s %s%s"
              % (name, K16.hex(), key.hex(), iv.hex(), len(p1), st, rb[:90],
                 "   <<< 命中候选!" if ok else ""), flush=True)
        results.append({"name": name, "k16": K16.hex(), "key": key.hex(),
                        "iv": iv.hex(), "status": st, "body": rb})
        if ok:
            print("[!] 候选 %s 通过 (非 800131), 详情见结果文件" % name, flush=True)
            break
        time.sleep(0.4)

    out = os.path.join(HERE, "forge_v6_results.json")
    json.dump(results, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[*] 结果 -> %s" % out, flush=True)


if __name__ == "__main__":
    main()
