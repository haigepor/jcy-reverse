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
for _p in (_HERE, os.path.join(_ROOT, "src", "tools"), os.path.join(_ROOT, "research"),
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
        self._enc = None          # EOracle（请求 P1 加密，C 引擎不可用时的兜底）
        self._dec = None          # EDecryptor（响应 P1 解密）
        self._ce = None           # c_engine 模块（C 转译引擎）
        self._conn = None         # 主 API 持久连接（keep-alive）
        self._conn_key = None

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
        """P1 = E(key=K16, iv=reverse(K16), PKCS7(pt))。

        后端优先级：C 转译引擎（jcy_fuse24.dll，稳态 ~6ms）→ EOracle/Unicorn（~105ms，兜底）。
        2026-10-07 实测两者逐位等价（同 K 同明文 nblk=1/2/4/8/16），故可安全替换。
        """
        try:
            return self._encrypt_p1_c(pt, K16)
        except Exception:                       # noqa: BLE001
            if self._enc is None:
                from e_oracle import EOracle
                self._enc = EOracle()
            return self._enc.enc(pt, K16, K16[::-1])

    def _encrypt_p1_c(self, pt: bytes, K16: bytes) -> bytes:
        """C 引擎加密。

        DLL 的 jcy_encrypt 有两条约束：(a) 明文长度必须是 16 的倍数；
        (b) 它内部会**再补一个整块** PKCS#7。真实请求的明文（JSON 补空格到 4 的倍数）
        一般不是 16 的倍数，所以这里先在 Python 侧补标准 PKCS#7 到整块，
        再把密文截断回 padded 长度 —— CBC 下多出来的那一整块只追加在尾部，
        不影响前面的块，故 ct[:len(padded)] 就是服务端期望的 P1。
        """
        if self._ce is None:
            import c_engine
            img = os.environ.get("JCY_IMAGE") or os.path.join(
                _ROOT, "research", "engine_c", "image639.bin")
            if not os.path.exists(img):
                img = os.path.join(_ROOT, "research", "engine_c", "image128.bin")
            c_engine.init(img)
            self._ce = c_engine
        n = 16 - (len(pt) % 16)                 # 1..16（len%16==0 时补整块）
        padded = pt + bytes([n]) * n
        ct = self._ce.encrypt(K16, padded)      # 长度 = len(padded) + 16
        if len(ct) < len(padded):
            raise RuntimeError("c_engine 密文过短 %d < %d" % (len(ct), len(padded)))
        return ct[:len(padded)]

    def _decrypt_p1(self, p1: bytes, K16: bytes, blocks: int | None = None) -> bytes:
        if self._dec is None:
            self._dec = D.EDecryptor()
        return self._dec.decrypt(p1, K16, blocks)

    # ---- 上游 HTTP（keep-alive 持久连接）----
    def _http_conn(self, timeout: int) -> http.client.HTTPConnection:
        """实例内复用的主 API 连接。

        2026-10-07 实测：同连接第 2 请求 ~99ms vs 新连接 ~174-195ms（省 ~75-90ms/请求）。
        实例本身是线程局部的（桥层 _TLS.api），故无需额外加锁。
        """
        key = (HOST, PORT, timeout)
        c = self._conn
        if c is not None and self._conn_key != key:
            try:
                c.close()
            except Exception:                   # noqa: BLE001
                pass
            c = self._conn = None
        if c is None:
            c = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
            self._conn_key, self._conn = key, c
        return c

    def _http_round(self, method: str, path: str, body, headers: dict,
                    timeout: int):
        """发一次请求；连接坏掉（服务端关空闲连接/复位）时重建连接重试一次。"""
        last = None
        for attempt in (0, 1):
            conn = self._http_conn(timeout)
            try:
                conn.request(method, path, body=body, headers=headers)
                r = conn.getresponse()
                raw = r.read().decode("utf-8", "replace")
                return r.status, raw, r
            except Exception as exc:            # noqa: BLE001
                last = exc
                try:
                    conn.close()
                except Exception:               # noqa: BLE001
                    pass
                self._conn = None
        raise last

    # ---- 核心请求 ----
    def request(self, method: str, path: str, params: dict | None = None,
                timeout: int = 20, verbose: bool = False,
                blocks: int | None = None):
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

        status, raw, r = self._http_round(method, path, body, headers, timeout)

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
            plain = self._decrypt_p1(p1, k16resp, blocks)
        except Exception as exc:  # noqa: BLE001
            # 301 跳转 / 非信封体（如 /app/channel/ 的 Location 响应）
            return {"http": status, "encrypted": False, "raw": raw,
                    "location": r.getheader("Location") if hasattr(r, "getheader") else None,
                    "note": "非 <P0>.<P1> 信封: %r" % exc,
                    "json": self._try_json(raw)}
        return {"http": status, "encrypted": True, "raw_len": len(raw),
                "k16resp": k16resp.decode("latin1") if k16resp else None,
                # p1b/k16b：供调用方在不重发 HTTP 的前提下补解剩余块（部分解密回退用）
                "p1b": p1, "k16b": k16resp,
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
