# -*- coding: utf-8 -*-
"""jcy_client.py — 囧次元 API 端到端客户端（真实请求 + 离线解密）。

链路（全部离线可复现，无需设备/App）：
  请求头 : appid / ts / nonce / tcs=2 / x-version / authentication(=authgen 离线生成)
  GET    : 无 body；响应体 <P0>.<P1>
  POST   : body = CUSTOM_B64(P0) . CUSTOM_B64(P1)
             P0 = RSA-2048-PKCS1v1.5(server_pub, K16)      K16 = 16B 随机
             P1 = E( key=K16, iv=reverse(K16), PKCS7(params) )
  响应   : P0 = RSA(pub_from_go, K16resp)  -> priv_from_go.pem 解出 K16resp
           P1 = E( key=K16resp, iv=reverse(K16resp), ... ) -> decrypt_e 离线解明文

用法：
  python jcy_client.py GET  /app/config
  python jcy_client.py GET  /app/video/list?channel=1&sort=weight&limit=6&page=1
  python jcy_client.py POST /app/video/device-base '{}'
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import random
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_HERE, os.path.join(_ROOT, "src"),
           os.path.join(_ROOT, "research", "captures", "rsa_scan")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jcy_protocol.auth import ALPHABET, STD_B64  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402
from Crypto.Cipher import PKCS1_v1_5  # noqa: E402
import decrypt_e as D  # noqa: E402

HOST, PORT = "43.145.33.254", 27990
_RSA = os.path.join(_ROOT, "research", "captures", "rsa_scan")
PUB = RSA.import_key(open(os.path.join(_RSA, "server_pub_2048_live.pem"), "rb").read())
PRIV_GO = RSA.import_key(open(os.path.join(_RSA, "priv_from_go.pem"), "rb").read())
_TO_CUSTOM = str.maketrans(STD_B64, ALPHABET)

STATIC_HEADERS = {
    "x-version": "2020-09-17",
    "user-agent": "Dart/3.6 (dart:io)",
    "appid": "4150439554430529",
    "tcs": "2",
    "content-type": "application/json; charset=utf-8",
}


def cb64(b: bytes) -> str:
    return base64.b64encode(b).decode().translate(_TO_CUSTOM)


def cb64d(s: str) -> bytes:
    s = s.strip().translate(str.maketrans(ALPHABET, STD_B64))
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


class JcyClient:
    """囧次元 API 客户端。auth 与 E 预言机均复用。"""

    AUTH_TTL_MS = 90_000

    def __init__(self):
        self._auth = None
        self._auth_ts = 0
        self._enc = None          # EOracle（请求 P1 加密）
        self._dec = None          # EDecryptor（响应 P1 解密）

    # ---- authentication 头（本地离线生成，只与 ts 绑定）----
    def _auth_header(self):
        now = int(time.time() * 1000)
        if self._auth and now - self._auth_ts < self.AUTH_TTL_MS:
            return self._auth_ts, self._auth
        ts = now
        out = subprocess.run([sys.executable, "research/deliverables/authgen.py", "--ts", str(ts)],
                             capture_output=True, text=True, timeout=300, cwd=_ROOT)
        auth = None
        for line in (out.stdout + out.stderr).splitlines():
            if "auth" in line and "=" in line:
                v = line.split("=", 1)[1].strip()
                if len(v) >= 100:
                    auth = v
                    break
        if auth is None:
            raise RuntimeError("authgen 失败: " + (out.stdout + out.stderr)[-300:])
        self._auth, self._auth_ts = auth, ts
        return ts, auth

    def _encrypt_p1(self, pt: bytes, K16: bytes) -> bytes:
        if self._enc is None:
            from e_oracle import EOracle
            self._enc = EOracle()
        return self._enc.enc(pt, K16, K16[::-1])

    def _decrypt_p1(self, p1: bytes, K16: bytes) -> bytes:
        if self._dec is None:
            self._dec = D.EDecryptor()
        return self._dec.decrypt(p1, K16)

    # ---- 核心请求 ----
    def request(self, method: str, path: str, params: dict | None = None,
                timeout: int = 20, verbose: bool = False):
        method = method.upper()
        ts, auth = self._auth_header()
        headers = dict(STATIC_HEADERS)
        headers.update({"ts": str(ts), "nonce": str(random.randint(10 ** 7, 10 ** 8 - 1)),
                        "authentication": auth})
        K16 = None
        body = None
        if method == "POST":
            K16 = os.urandom(16)
            pt = json.dumps(params or {}, ensure_ascii=False, separators=(",", ":")).encode()
            if len(pt) % 4:
                pt += b" " * (-len(pt) % 4)
            p1 = self._encrypt_p1(pt, K16)
            p0 = PKCS1_v1_5.new(PUB).encrypt(K16)
            body = (cb64(p0) + "." + cb64(p1)).encode()
        if verbose:
            print("[*] %s %s  K16=%s" % (method, path, K16.hex() if K16 else "-"))

        conn = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers)
            r = conn.getresponse()
            raw = r.read().decode("utf-8", "replace")
            status = r.status
        finally:
            conn.close()

        # 明文错误（未加密）
        if "." not in raw:
            return {"http": status, "encrypted": False, "raw": raw,
                    "json": self._try_json(raw)}
        try:
            p0b, p1b = raw.split(".", 1)
            p0, p1 = cb64d(p0b), cb64d(p1b)
            if len(p0) < 256:
                raise ValueError("P0 长度 %d < 256，非 RSA 信封" % len(p0))
            k16resp = PKCS1_v1_5.new(PRIV_GO).decrypt(p0[:256], None)
            plain = self._decrypt_p1(p1, k16resp)
        except Exception as exc:  # noqa: BLE001
            # 301 跳转 / 非信封体（如 /app/channel/ 的 Location 响应）
            return {"http": status, "encrypted": False, "raw": raw,
                    "location": r.getheader("Location") if hasattr(r, "getheader") else None,
                    "note": "非 <P0>.<P1> 信封: %r" % exc,
                    "json": self._try_json(raw)}
        return {"http": status, "encrypted": True, "raw_len": len(raw),
                "k16resp": k16resp.decode("latin1") if k16resp else None,
                "plain": plain, "json": self._try_json(plain)}

    @staticmethod
    def _try_json(b):
        try:
            if isinstance(b, bytes):
                b = b.decode("utf-8")
            return json.loads(b)
        except Exception:
            return None

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, params=None, **kw):
        return self.request("POST", path, params, **kw)


if __name__ == "__main__":
    method = sys.argv[1] if len(sys.argv) > 1 else "GET"
    path = sys.argv[2] if len(sys.argv) > 2 else "/app/config"
    params = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    cli = JcyClient()
    res = cli.request(method, path, params, verbose=True)
    print("[*] HTTP %s encrypted=%s" % (res["http"], res["encrypted"]))
    if res["encrypted"]:
        print("[*] K16resp=%s  plain=%dB" % (res["k16resp"], len(res["plain"])))
    print(json.dumps(res["json"], ensure_ascii=False, indent=1)[:1500] if res["json"] else res["raw"][:400])
