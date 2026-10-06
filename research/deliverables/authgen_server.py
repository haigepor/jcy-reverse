# -*- coding: utf-8 -*-
"""authgen_server.py — 本地 `authentication` 取签服务（供 Apipost 手动/自动调试用）。

Apipost 里 `authentication` 头有 2 分钟左右的时效窗口，手动调试时反复粘贴很麻烦。
本服务在本地起一个 HTTP 端点，按需返回**当前时刻**的 `ts` 与 `authentication`，
Apipost 的「预执行操作」脚本可以每次发请求前自动来取。

启动::

    ./.venv/Scripts/python.exe research/deliverables/authgen_server.py
    # 默认监听 127.0.0.1:8791

接口::

    GET /auth            → {"ts": 1790..., "authentication": "6Msf...", "elapsed": 3.4}
    GET /auth?ts=1790... → 指定 ts（用于复现/回归）
    GET /forge?params={"a":1}&path=/app/video/device-base
                         → {"ts","authentication","body","k16","p1_len",...}
                           **一次产出可直接发送的 ts + auth + 合法 P0.P1 请求体**
                           （V12: P1 = CBC-E(key=K16, iv=reverse(K16), PKCS7(params))）
    GET /unwrap?body=P0.P1
                         → {"k16resp","p1_len","p1_hex"}  解响应 P0（离线可解）
    GET|POST /decrypt?body=P0.P1   (POST 时 body 即密文)
                         → {"k16resp","plain","json"}  **完整离线解密响应到明文 JSON**
                           （P0→priv_from_go.pem 得 K16resp；P1→decrypt_e 逐块 tweak 逆）
    GET /relay?path=/app/video/record&params={}
                         → 自动伪造 + 直发真实服务端 + 原样返回响应（含 decrypted）
                           （Apipost 侧无需配 body/header 的一键测试通道）
                           `&decrypt=0` → 只回原始信封，不解密（大响应秒回）
    GET|POST /proxy/<真实路径>?<原query>
                         → **透明代理**：注入新鲜 ts/authentication（POST 还生成加密 body）
                           后转发到真实服务端，**原样返回**响应。
                           Apipost 里只需把 URL 前缀 43.145.33.254:27990 换成
                           127.0.0.1:8791/proxy，无需任何变量/脚本。
    GET /plain           → 最近一次异步解密的结果（research/reports/last_plain.json）
    GET /health          → {"ok": true, "device_fp": "...", "boots": N}

注意：
  * 单次取签约 3–4 秒（Unicorn 执行 libcore.so 原函数），已复用模拟器实例
  * 只监听 127.0.0.1，不对外暴露
  * `ts` 与 `authentication` 必须成对使用（服务端校验二者绑定）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
RESEARCH = os.path.dirname(HERE)
ROOT = os.path.dirname(RESEARCH)
TOOLCHAIN = os.path.join(RESEARCH, "toolchain")
for _p in (os.path.join(ROOT, "src"), TOOLCHAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jcy_protocol.auth import build_input, custom_b64   # noqa: E402
import authgen as AG                                     # noqa: E402

_SESSION = None


def _session():
    """惰性创建并复用 UnicornESession（堆占用约 106KB/次，自动重建）。"""
    global _SESSION
    if _SESSION is None:
        _SESSION = AG.UnicornESession()
    return _SESSION


def make_auth(ts: int) -> dict:
    t0 = time.time()
    # 关键: 会话里的 key/iv 槽会被 e_enc() 覆写, 取签前必须复位成 auth 专用密钥对
    _s = _session()
    _s.e.fix_long_string(0x688130, AG.AES_KEY)
    _s.e.fix_long_string(0x688148, AG.AES_IV)
    a1 = custom_b64(build_input(ts, AG.DEVICE_FP).encode()).encode()
    body = _s.encrypt(a1)
    auth = custom_b64(body)
    return {
        "ts": ts,
        "authentication": auth,
        "input": build_input(ts, AG.DEVICE_FP),
        "ct0": body[:16].hex(),
        "elapsed": round(time.time() - t0, 2),
    }


# ---------------------------------------------------------------- V12: 请求体伪造
# f(K16) 已破解:  P1 = CBC-E(key=K16, iv=reverse(K16), PKCS7(params))
# E = libcore 自研分组密码 (与 authentication 头同一算法, 不是 AES)
_RS = os.path.join(RESEARCH, "captures", "rsa_scan")
if _RS not in sys.path:
    sys.path.insert(0, _RS)

from jcy_protocol.auth import ALPHABET, STD_B64          # noqa: E402
_TO_CUSTOM = str.maketrans(STD_B64, ALPHABET)

_PUB = None
_PRIV_GO = None


def _keys():
    global _PUB, _PRIV_GO
    if _PUB is None:
        from Crypto.PublicKey import RSA
        _PUB = RSA.import_key(open(os.path.join(_RS, "server_pub_2048_live.pem"), "rb").read())
        _PRIV_GO = RSA.import_key(open(os.path.join(_RS, "priv_from_go.pem"), "rb").read())
    return _PUB, _PRIV_GO


def cb64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode().translate(_TO_CUSTOM)


def cb64d(s: str) -> bytes:
    import base64
    s = s.strip().translate(str.maketrans(ALPHABET, STD_B64))
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def e_enc(pt: bytes, key: bytes, iv: bytes) -> bytes:
    """用复用中的 Unicorn 会话做 CBC-E(key, iv, PKCS7(pt))。

    管线约束: 明文长度必须是 4 的倍数 (b64 长度约束)。
    """
    s = _session()
    if len(pt) % 4:
        raise ValueError("明文长度 %d 必须是 4 的倍数" % len(pt))
    s.e.fix_long_string(0x688130, key)
    s.e.fix_long_string(0x688148, iv)
    L = next((c for c in range(1, len(pt) + 1) if 4 * ((c + 2) // 3) == len(pt)), None)
    if L is None:
        raise ValueError("明文长度 %d 无法用 b64 长度凑出" % len(pt))
    s._cur[0] = pt
    s._out.clear()
    inp = s.e.mkstr(b"\x00" * L)
    s.e.call(AG.DEV_BASE + AG.OFF_PIPE,
             (inp, AG.DEV_BASE + 0x688130, AG.DEV_BASE + 0x688148),
             sret=s.sret, timeout=120_000_000)
    return s._out.get("body", b"")


def forge(params: str, path: str = "/app/video/device-base") -> dict:
    """产出一次可直接发送的 (ts, authentication, body)。"""
    import secrets
    t0 = time.time()
    pt = (params if params is not None else "{}").encode()
    if len(pt) % 4:                      # 空格补齐 (JSON 允许尾随空白)
        pt += b" " * (-len(pt) % 4)
    k16 = secrets.token_bytes(16)
    p1 = e_enc(pt, k16, k16[::-1])
    from Crypto.Cipher import PKCS1_v1_5
    p0 = PKCS1_v1_5.new(_keys()[0]).encrypt(k16)
    body = cb64(p0) + "." + cb64(p1)
    ts = int(time.time() * 1000)
    auth = make_auth(ts)
    return {
        "ts": ts,
        "authentication": auth["authentication"],
        "body": body,
        "path": path,
        "k16": k16.hex(),
        "params": pt.decode("latin1"),
        "p0_len": len(p0),
        "p1_len": len(p1),
        "elapsed": round(time.time() - t0, 2),
    }


def unwrap(body: str) -> dict:
    """解响应 P0 → K16resp (离线可解); P1 仍需 E 的逆 (暂不可离线解)。"""
    s = (body or "").strip()
    if s.count(".") != 1:
        return {"ok": False, "error": "不是 <P0>.<P1> 形态"}
    from Crypto.Cipher import PKCS1_v1_5
    p0 = cb64d(s.split(".", 1)[0])
    p1 = cb64d(s.split(".", 1)[1])
    k = PKCS1_v1_5.new(_keys()[1]).decrypt(p0[:256], None)
    return {"ok": True, "p0_len": len(p0), "p1_len": len(p1),
            "k16resp": k.decode("latin1") if k else None,
            "p1_hex": p1.hex(),
            "note": "P1 为自研密码 E 的密文, 离线解需 E 的逆函数(未达成); "
                    "会话密钥对 = (key=K16req, iv=reverse(K16req))"}


_DEC = None


def _decryptor():
    """惰性创建 EDecryptor（响应 P1 的逐块 tweak 解密器）。

    V19: 默认 backend="auto" —— 优先走 C 转译引擎 (engine_c/jcy_engine.dll,
    639 块标定从~17s 降到亚秒级)，引擎缺失/异常时自动回退 Unicorn。
    可用环境变量 JCY_BACKEND=unicorn 强制回退，或 JCY_IMAGE 指定镜像。
    """
    global _DEC
    if _DEC is None:
        import decrypt_e as D
        _DEC = D.EDecryptor()
    return _DEC


def decrypt_response(body: str, blocks=None) -> dict:
    """完整离线解密响应体 <P0_b64>.<P1_b64> → 明文 JSON（V13 收官能力）。

    链路：P0 = RSA(pub_from_go, K16resp) --priv_from_go.pem--> K16resp
          P1 = E(key=K16resp, iv=reverse(K16resp), 逐块 tweak) --decrypt_e--> 明文
    blocks=N → 只解前 N 块（秒级，明文截断），用于快速看 code / 前几条数据。
    """
    s = (body or "").strip()
    if s.count(".") != 1:
        return {"ok": False, "error": "不是 <P0>.<P1> 形态", "len": len(s)}
    from Crypto.Cipher import PKCS1_v1_5
    t0 = time.time()
    p0 = cb64d(s.split(".", 1)[0])
    p1 = cb64d(s.split(".", 1)[1])
    k = PKCS1_v1_5.new(_keys()[1]).decrypt(p0[:256], None)
    if not k:
        return {"ok": False, "error": "P0 解不出 K16resp（非本客户端公钥 / 密文残缺）"}
    nblk_total = len(p1) // 16
    plain = _decryptor().decrypt(p1, k, blocks)
    txt = plain.decode("utf-8", "replace")
    try:
        j = json.loads(txt)
    except Exception:
        j = None
    partial = bool(blocks) and int(blocks) < nblk_total
    return {"ok": True, "k16resp": k.decode("latin1"),
            "p0_len": len(p0), "p1_len": len(p1), "plain_len": len(plain),
            "nblk_total": nblk_total, "partial": partial,
            "json": j, "plain": txt, "elapsed": round(time.time() - t0, 2)}


# ------------------------------------------------ 独立进程解密（防卡死服务）
LAST_PLAIN = os.path.join(RESEARCH, "reports", "last_plain.json")

# 持久进程池（V20）：每次请求都新建子进程 + 重新加载 101 MB 镜像是纯开销。
# 实测spawn 固定开销仅 10~47 ms（可忽略），真正的收益是**复用已加载的会话**：
# 6 进程 × 320 块 = 6369 ms vs 一次性子进程 10425 ms。
# 但扩展性亚线性（8 进程仅 4.25×，内存带宽饱和），故池大小取 CPU 半数。
_POOL = None
_POOL_N = None


def _pool():
    """惰性创建持久标定/解密进程池（每个 worker 一个 Unicorn 会话）。

    只在**并发**场景有意义：单请求延迟不变（标定本身就是串行链，见 V20 实测）。
    K 在真实流量里 100% 不复用（10 样本 10 个不同 K），所以缓存标定量无用，
    池的价值仅在于免掉「每次新建进程 + 重新 load 镜像」。
    """
    global _POOL, _POOL_N
    if _POOL is not None:
        return _POOL
    try:
        n = max(2, min(8, (os.cpu_count() or 4) // 2))
        research = os.path.dirname(HERE)
        if research not in sys.path:
            sys.path.insert(0, research)
        from calib_pool import CalibPool
        _POOL = CalibPool(nproc=n)
        _POOL_N = n
    except Exception:  # noqa: BLE001
        _POOL = None
    return _POOL


def _pool_calibrate(k16: bytes, nblk: int):
    """走进程池标定；不可用返回 None（调用方回退子进程）。"""
    p = _pool()
    if p is None:
        return None
    try:
        (C, rk, CONST, Cb), = p.calibrate_many([(k16, int(nblk))])
        return C, rk, CONST, Cb
    except Exception:  # noqa: BLE001
        return None


def _decrypt_subprocess(body: str, blocks=None, timeout: float = 1800.0) -> dict:
    """在**独立进程**里解密，调用方等待结果。

    为什么必须独立进程：E 的解密靠 Unicorn 仿真 libcore.so，长响应要跑几分钟。
    Unicorn 的 emu_start 在 C 扩展里长时间不释放 GIL，若放在服务进程的线程里执行，
    会把整个 HTTP 服务卡死（除 /health 外所有端点无响应）——这正是 Apipost 报
    `callback timed out` 的根因。独立进程则互不影响。
    """
    import subprocess
    cli = os.path.join(HERE, "decrypt_cli.py")
    cmd = [sys.executable, cli] + (["-", str(int(blocks))] if blocks else [])
    try:
        p = subprocess.run(cmd, input=(body or "").encode("utf-8"),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        txt = p.stdout.decode("utf-8", "replace").strip()
        if not txt:
            return {"ok": False, "error": "解密子进程无输出: "
                    + p.stderr.decode("utf-8", "replace")[:300]}
        return json.loads(txt)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "解密子进程超时 (%.0fs)" % timeout}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": repr(exc)}


def _decrypt_async(body: str, blocks=None) -> dict:
    """后台独立进程解密，结果**原子写**入 research/reports/last_plain.json，立即返回。"""
    import subprocess
    os.makedirs(os.path.dirname(LAST_PLAIN), exist_ok=True)
    cli = os.path.join(HERE, "decrypt_cli.py")
    cmd = [sys.executable, cli, LAST_PLAIN] + ([str(int(blocks))] if blocks else [])
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.stdin.write((body or "").encode("utf-8"))
        p.stdin.close()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": repr(exc)}
    return {"ok": True, "queued": True, "pid": p.pid, "result_file": LAST_PLAIN}


def _nblk_estimate(body: str) -> int:
    """从 <P0>.<P1> 粗估 P1 块数（用于决定同步/异步）。"""
    s = (body or "").strip()
    if s.count(".") != 1:
        return 0
    return max(0, int(len(s.split(".", 1)[1]) * 3 / 4) // 16)


def _c_backend_ready() -> bool:
    """C 引擎后端是否可用（决定能否省掉子进程隔离）。"""
    try:
        return _decryptor()._c_engine() is not None
    except Exception:  # noqa: BLE001
        return False


def _decrypt_auto(body: str, blocks=None, max_sync_blocks: int = 768) -> dict:
    """小块同步（Apipost 里能直接看到明文），大块转后台（避免超时）。

    blocks 显式指定「只解前 N 块」时按 N 判断（截断模式，通常很快）。
    阈值 512：实测子进程全量解密 512 块 ≈ 8s、列表 440 块 ≈ 7-11s，
    远小于Apipost 后任务的 900s 超时，同步即可让 jcy_plain 直接可用。

    V19: C 引擎后端下639 块也只要亚秒级，不再需要子进程隔离
    （子进程隔离是为 Unicorn 的长时间 emu_start 不释放 GIL 而设，
    C 引擎是纯本地计算，不占GIL）。
    """
    n = int(blocks) if blocks else _nblk_estimate(body)
    if _c_backend_ready():
        # C 后端够快 → 进程内直接解, 避开子进程冷启动 (~1s) 与结果文件往返
        return decrypt_response(body, blocks)
    if n and n > max_sync_blocks:
        r = _decrypt_async(body, blocks)
        r["note"] = ("响应约 %d 块，离线解密约 %d 秒后完成，已转后台；"
                     "完成后明文写入 %s（过期估算文案已更正：不是分钟级）"
                     % (n, max(3, int(n * 0.03)), LAST_PLAIN))
        return r
    return _decrypt_subprocess(body, blocks)


def _append_query(path: str, params: str) -> str:
    """把 params JSON 拼到 path 的 query 上（relay 的 GET 通道用）。"""
    s = (params or "").strip()
    if not s or s == "{}":
        return path
    sep = "&" if "?" in path else "?"
    try:
        pj = json.loads(s)
    except Exception:
        return path + sep + s.lstrip("?&")
    if not isinstance(pj, dict) or not pj:
        return path
    from urllib.parse import urlencode
    flat = {}
    for k, v in pj.items():
        flat[k] = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
    return path + sep + urlencode(flat)


def relay(path: str, params: str, method: str = "POST", decrypt: bool = True,
          blocks=None) -> dict:
    """本地一键通道: 自动伪造 + 直发真实服务端 + 原样返回响应。

    Apipost 侧只需一个 GET http://127.0.0.1:8791/relay?path=...&params=...
    无需配置 body / authentication。
    decrypt=0 → 只回原始 <P0>.<P1> 信封, 不解密（大响应时秒回）。
    """
    import http.client
    f = forge(params, path)
    h = {
        "x-version": "2020-09-17", "user-agent": "Dart/3.6 (dart:io)",
        "appid": "4150439554430529", "tcs": "2",
        "content-type": "application/json; charset=utf-8",
        "host": "43.145.33.254:27990",
        "ts": str(f["ts"]), "nonce": "12345678",
        "authentication": f["authentication"],
    }
    try:
        conn = http.client.HTTPConnection("43.145.33.254", 27990, timeout=15)
        # GET 不能带 body：带了会被服务端当参数解析 → 40000
        body = f["body"].encode() if method.upper() == "POST" else None
        if body is None:
            h.pop("content-type", None)
            # GET 的 params 加密不进 body，必须拼到 query，否则被服务端忽略（返回默认参数）
            send_path = _append_query(path, params)
        else:
            send_path = path
        conn.request(method, send_path, body=body, headers=h)
        r = conn.getresponse()
        raw = r.read().decode("utf-8", "replace")
        status = r.status
        conn.close()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "stage": "relay", "error": repr(exc), "forge": f}
    out = {"ok": True, "status": status, "response": raw,
           "verdict": classify(raw), "k16": f["k16"], "p1_len": f["p1_len"]}
    if decrypt and raw.count(".") == 1 and len(raw) > 400:
        try:
            out["unwrapped"] = unwrap(raw)
            out["decrypted"] = _decrypt_auto(raw, blocks)
        except Exception:
            pass
    return out


STORE = os.path.join(RESEARCH, "captures", "apipost_responses.jsonl")


def proxy(method: str, path: str, params: str = "{}") -> dict:
    """透明代理：注入新鲜签名(与加密 body)后转发到真实服务端，**原样返回**响应。

    Apipost 里只把 URL 前缀 `http://43.145.33.254:27990` 换成
    `http://127.0.0.1:8791/proxy`，路径 / query / method 全部保留即可，
    **无需任何变量、请求头或预执行脚本**。
    """
    import http.client
    f = forge(params, path)
    h = {
        "x-version": "2020-09-17", "user-agent": "Dart/3.6 (dart:io)",
        "appid": "4150439554430529", "tcs": "2",
        "host": "43.145.33.254:27990",
        "ts": str(f["ts"]), "nonce": "12345678",
        "authentication": f["authentication"],
    }
    try:
        conn = http.client.HTTPConnection("43.145.33.254", 27990, timeout=20)
        body = f["body"].encode() if method.upper() == "POST" else None
        if body is None:
            h.pop("content-type", None)
        else:
            h["content-type"] = "application/json; charset=utf-8"
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        raw = r.read().decode("utf-8", "replace")
        st = r.status
        conn.close()
    except Exception as exc:  # noqa: BLE001
        return {"status": 599, "raw": json.dumps({"ok": False, "error": repr(exc)})}
    return {"status": st, "raw": raw}


def classify(body: str) -> dict:
    """判定响应形态：加密业务数据 / 明文错误 / 其它。"""
    s = (body or "").strip()
    if not s:
        return {"kind": "empty", "ok": False, "note": "空响应"}
    if s.startswith("{"):
        try:
            j = json.loads(s)
            code = j.get("code")
            msgs = {
                30000: "解码异常（authentication 为空或格式错）",
                403501: "校验客户端签名失败（ts 与 auth 不配对 / auth 过期 / 被篡改）",
                403502: "检测到设备时间异常（ts 太旧）",
                40000: "业务参数错误（如 /app/danmu 缺 start_time_point）",
                20000: "业务层错误（认证已通过）",
                800131: "通讯失败：P1 解不开（会话密钥对错 —— 必须 key=K16 / iv=reverse(K16)）",
            }
            return {"kind": "plain_json", "ok": False, "code": code,
                    "message": j.get("message"), "note": msgs.get(code, "明文错误响应")}
        except Exception:
            return {"kind": "plain_text", "ok": False, "note": "明文（非 JSON）"}
    p0, dot, p1 = s.partition(".")
    if dot and len(p0) > 200 and len(p1) > 8:
        return {"kind": "encrypted", "ok": True,
                "p0_b64_len": len(p0), "p1_b64_len": len(p1),
                "note": "认证通过，服务端返回加密业务数据 <P0_b64>.<P1_b64>"}
    if len(s) <= 8:
        return {"kind": "not_found", "ok": False, "note": "路径不存在（404）"}
    return {"kind": "other", "ok": False, "len": len(s), "note": "其它形态"}


class Handler(BaseHTTPRequestHandler):
    server_version = "jcy-authgen/1.1"

    def _json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _raw(self, text, code=200, ctype="text/plain; charset=utf-8"):
        data = (text or "").encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _proxy_target(self, u, is_post=False):
        """把 /proxy/app/xxx?y=1 还原成 /app/xxx?y=1（POST 时抽出 params= 作为加密参数）。"""
        p = u.path[len("/proxy"):] or "/"
        q = u.query or ""
        params = "{}"
        if is_post and q:
            from urllib.parse import unquote
            m = re.search(r"(?:^|&)params=([^&]*)", q)
            if m:
                params = unquote(m.group(1)) or "{}"
                q = (q[:m.start()] + q[m.end():]).strip("&")
        if q:
            p += "?" + q
        return p, params

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path in ("/auth", "/"):
                ts = int(q["ts"][0]) if q.get("ts") else int(time.time() * 1000)
                self._json(make_auth(ts))
            elif u.path == "/forge":
                params = q["params"][0] if q.get("params") else "{}"
                path = q["path"][0] if q.get("path") else "/app/video/device-base"
                self._json(forge(params, path))
            elif u.path == "/unwrap":
                self._json(unwrap(q["body"][0] if q.get("body") else ""))
            elif u.path == "/decrypt":
                self._json(_decrypt_subprocess(q["body"][0] if q.get("body") else "",
                                               q["blocks"][0] if q.get("blocks") else None))
            elif u.path == "/relay":
                self._json(relay(q["path"][0] if q.get("path") else "/app/video/device-base",
                                 q["params"][0] if q.get("params") else "{}",
                                 (q["method"][0] if q.get("method") else "POST"),
                                 (q["decrypt"][0] != "0") if q.get("decrypt") else True,
                                 q["blocks"][0] if q.get("blocks") else None))
            elif u.path.startswith("/proxy"):
                _p, _pa = self._proxy_target(u)
                _r = proxy("GET", _p, _pa)
                self._raw(_r["raw"], _r["status"])
            elif u.path == "/plain":
                if os.path.exists(LAST_PLAIN):
                    try:
                        with open(LAST_PLAIN, encoding="utf-8") as f:
                            self._json(json.load(f))
                    except Exception as exc:  # noqa: BLE001
                        self._json({"ok": False, "error": repr(exc)}, 500)
                else:
                    self._json({"ok": False, "error": "还没有异步解密结果", "file": LAST_PLAIN}, 404)
            elif u.path == "/health":
                self._json({"ok": True, "device_fp": AG.DEVICE_FP,
                            "boots": getattr(_SESSION, "boots", 0) if _SESSION else 0,
                            "auth_len": 152})
            elif u.path == "/responses":
                n = 0
                if os.path.exists(STORE):
                    with open(STORE, encoding="utf-8") as f:
                        n = sum(1 for _ in f)
                self._json({"ok": True, "stored": n, "file": STORE})
            else:
                self._json({"ok": False, "error": "unknown path",
                            "paths": ["/auth", "/forge?params=&path=", "/unwrap?body=",
                                      "/decrypt?body=", "/relay?path=&params=&method=",
                                      "/proxy/<真实路径>", "/plain", "/health", "/responses",
                                      "POST /store", "POST /classify", "POST /decrypt"]}, 404)
        except Exception as exc:  # noqa: BLE001
            self._json({"ok": False, "error": repr(exc)}, 500)

    def do_POST(self):
        u = urlparse(self.path)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            if u.path == "/store":
                rec = json.loads(raw) if raw.strip().startswith("{") else {"body": raw}
                body = rec.get("body") or ""
                rec["verdict"] = classify(body)
                rec["stored_at"] = int(time.time() * 1000)
                if rec.get("decrypt") and rec["verdict"].get("kind") == "encrypted":
                    try:
                        rec["decrypted"] = _decrypt_auto(body)
                    except Exception as exc:  # noqa: BLE001
                        rec["decrypt_error"] = repr(exc)
                os.makedirs(os.path.dirname(STORE), exist_ok=True)
                with open(STORE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                self._json({"ok": True, "verdict": rec["verdict"],
                            "decrypted": rec.get("decrypted")})
            elif u.path == "/decrypt":
                self._json(_decrypt_subprocess(raw))
            elif u.path == "/classify":
                self._json({"ok": True, "verdict": classify(raw)})
            elif u.path.startswith("/proxy"):
                _p, _pa = self._proxy_target(u, is_post=True)
                _r = proxy("POST", _p, _pa)
                self._raw(_r["raw"], _r["status"])
            else:
                self._json({"ok": False, "error": "unknown path"}, 404)
        except Exception as exc:  # noqa: BLE001
            self._json({"ok": False, "error": repr(exc)}, 500)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("[authgen] %s %s\n" % (self.address_string(), fmt % args))


def main() -> int:
    ap = argparse.ArgumentParser(description="本地 authentication 取签服务")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--warmup", action="store_true", help="启动时先预热一次（首次取签更快）")
    a = ap.parse_args()

    print("预热中…" if a.warmup else "就绪。", flush=True)
    if a.warmup:
        r = make_auth(int(time.time() * 1000))
        print("预热完成 %.2fs, ct0=%s" % (r["elapsed"], r["ct0"]), flush=True)

    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print("authgen 服务已启动: http://%s:%d/auth" % (a.host, a.port), flush=True)
    print("  取签:  curl http://%s:%d/auth" % (a.host, a.port), flush=True)
    print("  健康:  curl http://%s:%d/health" % (a.host, a.port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
