# -*- coding: utf-8 -*-
"""forge_v7.py — 囧次元请求伪造 (V12 收官版)

== 已确认的协议模型 ==
  请求体 = <CUSTOM_B64(P0)>.<CUSTOM_B64(P1)>
  P0 = RSA-2048-PKCS1v1.5(server_pub, K16)         K16 = 客户端 16 字节原生随机
  P1 = CBC-E( key = K16 , iv = reverse(K16) , PKCS7(params) )
       E = libcore 自研分组密码 (与 authentication 头同一算法, 非 AES!)
  响应体同构: P0 = RSA(pub_from_go, K16resp)  -> priv_from_go.pem 可解
             P1 = CBC-E( key = K16, iv = reverse(K16), ... )  (会话同密钥)

== 判定 ==
  服务端返回 {"code":800131,"message":"通讯失败"} = P1 解不开;
  返回 CUSTOM_B64(P0).CUSTOM_B64(P1) 形态 = 请求被接受 (本版已达成)

用法:
  python forge_v7.py --path /app/video/device-base --pt '{}'
  python forge_v7.py --k16 <32hex> --pt '{"a":1}' --save out.txt
"""
import argparse
import base64
import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
for _p in (os.path.join(ROOT, "src", "tools"), HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jcy_protocol.auth import ALPHABET, STD_B64  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402
from Crypto.Cipher import PKCS1_v1_5  # noqa: E402
from e_oracle import EOracle  # noqa: E402

URL_HOST, URL_PORT = "43.145.33.254", 27990
PUB = RSA.import_key(open(os.path.join(HERE, "server_pub_2048_live.pem"), "rb").read())
PRIV_GO = RSA.import_key(open(os.path.join(HERE, "priv_from_go.pem"), "rb").read())
_TO_CUSTOM = str.maketrans(STD_B64, ALPHABET)

HEADERS = {
    "x-version": "2020-09-17",
    "user-agent": "Dart/3.6 (dart:io)",
    "appid": "4150439554430529",
    "tcs": "2",
    "content-type": "application/json; charset=utf-8",
    "host": "43.145.33.254:27990",
}


def cb64(b):
    return base64.b64encode(b).decode().translate(_TO_CUSTOM)


def cb64d(s):
    s = s.strip().translate(str.maketrans(ALPHABET, STD_B64))
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


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


def post(path, body, ts, nonce, auth, timeout=15):
    import http.client
    h = dict(HEADERS)
    h.update({"ts": str(ts), "nonce": str(nonce), "authentication": auth})
    conn = http.client.HTTPConnection(URL_HOST, URL_PORT, timeout=timeout)
    conn.request("POST", path, body=body.encode(), headers=h)
    r = conn.getresponse()
    data = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="/app/video/device-base")
    ap.add_argument("--pt", default="{}")
    ap.add_argument("--k16", default=None, help="32 hex, 默认随机")
    ap.add_argument("--save", default=None)
    a = ap.parse_args()

    K16 = bytes.fromhex(a.k16) if a.k16 else os.urandom(16)
    pt = a.pt.encode()
    if len(pt) % 4:
        pt += b" " * (-len(pt) % 4)          # E 预言机要求明文长度为 4 的倍数
    key, iv = K16, K16[::-1]

    print("[*] K16=%s" % K16.hex())
    print("[*] key=K16, iv=reverse(K16)=%s" % iv.hex())
    o = EOracle()
    p1 = o.enc(pt, key, iv)
    p0 = PKCS1_v1_5.new(PUB).encrypt(K16)
    body = cb64(p0) + "." + cb64(p1)
    print("[*] P0=%dB P1=%dB body=%d chars" % (len(p0), len(p1), len(body)))

    ts = int(time.time() * 1000)
    nonce = str(random.randint(10_000_000, 99_999_999))
    auth = gen_auth(ts)
    st, rb = post(a.path, body, ts, nonce, auth)
    print("[*] HTTP %s" % st)
    print("[*] resp[:120] = %s" % rb[:120])

    rec = {"path": a.path, "k16": K16.hex(), "pt": pt.decode("latin1"),
           "status": st, "resp": rb}
    ok = st == 200 and rb.count(".") == 1 and len(rb) > 400
    print("[%s] 服务端已接受请求 (非 800131)" % ("OK" if ok else "FAIL"))
    if ok:
        p0r, p1r = cb64d(rb.split(".", 1)[0]), cb64d(rb.split(".", 1)[1])
        k16resp = PKCS1_v1_5.new(PRIV_GO).decrypt(p0r[:256], None)
        print("[+] 响应 P0=%dB -> K16resp=%r" % (len(p0r), k16resp))
        rec["k16resp"] = k16resp.decode("latin1") if k16resp else None
        rec["resp_p1"] = p1r.hex()
        if a.save:
            open(a.save, "w", encoding="utf-8").write(rb)
            print("[*] 原始响应已保存 -> %s" % a.save)
    json.dump(rec, open(os.path.join(HERE, "forge_v7_last.json"), "w",
                        encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
