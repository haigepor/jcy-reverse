# -*- coding: utf-8 -*-
"""forge_v5.py — keystore 静态对假设验证 + 响应闭环解密

结构真值 (静态分析+emu 实证):
  P0 = RSA-PKCS1(server_pub, K16 raw 16B)          ← emu flen=16
  P1 = AES-CBC(keystore.key, keystore.iv, params)  ← builder(0x374870) x1/x2 = keystore 全局拷贝
  keystore 快照真值: key=qPwClBj7j7ZQraSm iv=p3JdVQl3q7WQJIgG (@0x689528/0x689540)

变体网格: keystore 对的 4 种排布; 每请求新 K16; 响应 P1 用已知 K16req 网格解密。
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
PRIV_GO = RSA.import_key(open(HERE + "/priv_from_go.pem", "rb").read())
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

MON_K = b"qPwClBj7j7ZQraSm"   # keystore.key @0x689528
SIG_K = b"p3JdVQl3q7WQJIgG"   # keystore.iv  @0x689540


def cb64(b):
    return base64.b64encode(b).decode().translate(_TO_CUSTOM)


def cb64d(s):
    _f = str.maketrans(ALPHABET, STD_B64)
    return base64.b64decode(s.strip().translate(_f) + "=" * (-len(s.strip()) % 4))


def gen_auth(ts):
    out = subprocess.run(
        [sys.executable, "research/deliverables/authgen.py", "--ts", str(ts)],
        capture_output=True, text=True, timeout=300, cwd=ROOT)
    for line in (out.stdout + out.stderr).splitlines():
        if "auth" in line and "=" in line:
            v = line.split("=", 1)[1].strip()
            if len(v) >= 100:
                return v
    raise RuntimeError("authgen fail: " + (out.stdout + out.stderr)[-200:])


def try_decrypt(p1, k16req, k16resp):
    """响应 P1 解密网格: 已知 K16req(raw)/K16resp(ascii) × 派生"""
    keys = {
        "K16req": k16req,
        "md5(K16req)": hashlib.md5(k16req).digest(),
        "sha256(K16req)[:16]": hashlib.sha256(k16req).digest()[:16],
        "hex(K16req)[:32]": k16req.hex().encode()[:32],
        "hex(K16req)[:16]": k16req.hex().encode()[:16],
        "K16resp": k16resp,
        "md5(K16resp)": hashlib.md5(k16resp).digest(),
        "MON_K": MON_K,
        "SIG_K": SIG_K,
    }
    ivs = {
        "zero": b"\x00" * 16,
        "K16req": k16req,
        "K16resp": k16resp,
        "md5(K16req)": hashlib.md5(k16req).digest(),
        "md5(K16resp)": hashlib.md5(k16resp).digest(),
        "sha256(K16req)[:16]": hashlib.sha256(k16req).digest()[:16],
        "sha256(K16resp)[:16]": hashlib.sha256(k16resp).digest()[:16],
        "MON_K": MON_K,
        "SIG_K": SIG_K,
        "K16req.rev": k16req[::-1],
        "K16resp.rev": k16resp[::-1],
    }
    hits = []
    for kn, k in keys.items():
        if len(k) not in (16, 24, 32):
            continue
        for ivn, iv in ivs.items():
            try:
                pt = AES.new(k, AES.MODE_CBC, iv).decrypt(p1)
            except Exception:
                continue
            n = pt[-1] if pt else 0
            valid_pad = 1 <= n <= 16 and pt[-n:] == bytes([n]) * n
            printable = sum(1 for c in pt[:32] if 32 <= c < 127) / min(32, len(pt) or 1)
            if pt[:1] in (b"{", b"[") or (valid_pad and printable > 0.9):
                body = pt[:-n] if valid_pad else pt
                hits.append((kn, ivn, valid_pad, body[:150]))
    return hits


def main():
    variants = [
        ("A key=MON iv=SIG", MON_K, SIG_K),
        ("B key=SIG iv=MON", SIG_K, MON_K),
        ("C key=MON iv=MON", MON_K, MON_K),
        ("D key=SIG iv=SIG", SIG_K, SIG_K),
    ]
    results = []
    for tag, k, iv in variants:
        k16 = os.urandom(16)
        p0 = PKCS1_v1_5.new(PUB).encrypt(k16)
        p1 = AES.new(k, AES.MODE_CBC, iv).encrypt(pad(b"{}", 16))
        body = cb64(p0) + "." + cb64(p1)
        ts = int(time.time() * 1000)
        headers = dict(HEADERS_BASE)
        headers["ts"] = str(ts)
        headers["nonce"] = str(random.randint(10_000_000, 99_999_999))
        headers["authentication"] = gen_auth(ts)
        req = urllib.request.Request(URL, data=body.encode(), headers=headers, method="POST")
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            status, rbody = resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, rbody = e.code, e.read().decode("utf-8", "replace")
        except Exception as e:
            status, rbody = -1, repr(e)
        print(f"[{tag}] K16={k16.hex()} HTTP {status} body[:80]={rbody[:80]!r}")
        rec = {"tag": tag, "k16": k16.hex(), "status": status, "body": rbody}
        # 解析响应
        rbody = rbody.strip()
        if rbody.startswith("{"):
            print(f"    明文 JSON: {rbody[:200]}")
        elif "." in rbody:
            try:
                p0s, p1s = rbody.split(".", 1)
                p0r, p1r = cb64d(p0s), cb64d(p1s)
                k16resp = PKCS1_v1_5.new(PRIV_GO).decrypt(p0r, None)
                print(f"    P0={len(p0r)}B P1={len(p1r)}B K16resp={k16resp!r}")
                rec["k16resp"] = k16resp.decode("latin1") if k16resp else None
                if p1r and len(p1r) % 16 == 0 and k16resp:
                    hits = try_decrypt(p1r, k16, k16resp)
                    for kn, ivn, vp, body_preview in hits[:6]:
                        print(f"    [P1-HIT] key={kn} iv={ivn} pad={vp}: {body_preview!r}")
                    if not hits:
                        print("    P1 网格无命中")
                    rec["hits"] = [(kn, ivn) for kn, ivn, _, _ in hits]
            except Exception as e:
                print(f"    解析失败: {e!r}")
        results.append(rec)
        time.sleep(1.5)
    with open(os.path.join(HERE, "forge_v5_results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    print("结果已落盘 forge_v5_results.json")


if __name__ == "__main__":
    main()
