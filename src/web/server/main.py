# -*- coding: utf-8 -*-
"""jcy-web 本地后端桥 —— 浏览器与囧次元协议之间的唯一通道。

为什么必须有这一层（Web 端三项硬约束，见 docs/frontend.md）：
  1. E 加密层依赖 Unicorn × libcore.so，浏览器跑不了 → 复用 research/deliverables
     的 JcyApi 做签名/信封加密/响应解密，前端只见明文 JSON；
  2. 视频直链要求 User-Agent 置空 + 按域伪造 Referer，浏览器禁设这些头 →
     /stream 做 Range 流式代理，按 JcyApi.direct_headers 规则注入；
  3. 主 API 是明文 HTTP 且无 CORS → 同源反代消除 mixed content 与 CORS。

端点：
  GET|POST /api/<真实路径>?<query>    任意端点透传（POST body JSON → 信封参数）
  POST     /resolve                   {vid, play?, part?} → 播放凭证+解析器 → urls[]
  GET      /stream?url=<直链>         视频流代理（Range 转发 + 头注入 + 域名白名单）
  GET      /health                    存活检查

运行：../../.venv/Scripts/python.exe server/main.py  （默认 127.0.0.1:8792）
"""
from __future__ import annotations

import os
import sys
from urllib.parse import urlsplit
import time

# ---- 复用研究区交付物（jcy_api → jcy_client → authgen/decrypt_e 链路）----
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
for _p in (
    os.path.join(_ROOT, "research", "deliverables"),
    os.path.join(_ROOT, "research", "captures", "rsa_scan"),
    os.path.join(_ROOT, "src", "tools"),
):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, Request, Response  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import JSONResponse, StreamingResponse  # noqa: E402
import httpx  # noqa: E402

import jcy_api as JA  # noqa: E402

# ---- C 引擎（jcy_engine.dll）全局态串行化 ----
# DLL 内部为单例镜像/全局寄存器态，多线程并发 encrypt_with_x/encrypt_with_iv
# 会触发原生崩溃（现场特征：并发基准 ConnectionReset，进程消失）。
# 预先 import 并包一层进程级锁：decrypt_e 的 _c_engine() 拿到的是同一模块对象。
import threading as _th
_CE_LOCK = _th.RLock()  # init 内部会调 load → 必须可重入


def _ce_locked(name):
    _orig = getattr(_CE, name, None)
    if not callable(_orig):
        return None

    def _w(*a, **k):
        with _CE_LOCK:
            return _orig(*a, **k)
    _w.__name__ = name + "_locked"
    return _w


try:
    import sys as _sys
    _research = os.path.abspath(os.path.join(_HERE, "..", "..", "..", "research"))
    if _research not in _sys.path:
        _sys.path.insert(0, _research)
    import c_engine as _CE  # noqa: E402
    # "encrypt" = POST 请求 P1 的 C 引擎加密（2026-10-07 取代 EOracle），同样跑引擎 → 必须加锁
    for _n in ("encrypt_with_x", "encrypt_with_iv", "encrypt", "init", "load"):
        _w = _ce_locked(_n)
        if _w:
            setattr(_CE, _n, _w)
    print("[bridge] c_engine locked wrappers installed", flush=True)
except Exception as _e:  # noqa: BLE001
    print("[bridge] c_engine lock skip: %r" % _e, flush=True)

app = FastAPI(title="jcy-web bridge", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    # 放行本机与内网来源（vite.config.ts 的 dev server 端口是 5174；host:true 时
    # 手机通过 http://<本机IP>:5174 访问）。桥只 bind 127.0.0.1，外网不可达。
    allow_origin_regex=(
        r"^http://(localhost|127\.0\.0\.1|\[::1\]"
        r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?$"
    ),
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Range", "Accept-Ranges", "Content-Length"],
)

_CLIENT: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    global _CLIENT
    if _CLIENT is None:
        # 有限连接数 + 较长读超时（起播 Range 探测走大文件 CDN）
        _CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(20, read=60), follow_redirects=True)
    return _CLIENT


@app.on_event("startup")
def _warm_auth() -> None:
    """后台预热 auth（避免首批并发请求各自冷启动 authgen 子进程互相拖慢）。"""
    def _go():
        try:
            get_api().request("GET", "/app/config")
            print("[bridge] auth warmed", flush=True)
        except Exception as e:  # noqa: BLE001
            print("[bridge] auth warm fail: %r" % e, flush=True)
    threading.Thread(target=_go, daemon=True, name="auth-warm").start()


@app.get("/health")
async def health():
    return {"ok": True, "api": "jcy-web-bridge"}


@app.get("/debug")
def debug():
    """引擎/后端自检：排查「同一份代码两个进程速度差 3×」这类环境漂移。"""
    import decrypt_e as _DE  # noqa: PLC0415
    d = _DE.EDecryptor()
    c = d._c_engine()
    info = {"cwd": os.getcwd(), "exe": sys.executable,
            "backend": d.backend, "c_ready": d._c_ready,
            "env_backend": os.environ.get("JCY_BACKEND"),
            "env_image": os.environ.get("JCY_IMAGE"),
            "env_dll": os.environ.get("JCY_DLL"),
            "env_proxy": os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")}
    try:
        import c_engine as _ce  # noqa: PLC0415
        info["dll"] = _ce.loaded_path()
        info["image_inited"] = getattr(_ce, "_inited_path", None)
    except Exception as exc:  # noqa: BLE001
        info["dll_err"] = repr(exc)
    # 标定吞吐实测：不同块数各一次（全新 K，模拟新响应）
    try:
        import time as _t
        rates = {}
        for n in (40, 200, 600, 1200):
            K = os.urandom(16)
            t0 = _t.perf_counter()
            d.calibrate(K, n)
            ms = (_t.perf_counter() - t0) * 1000
            rates["n%d" % n] = {"ms": round(ms, 1), "ms_per_blk": round(ms / n, 3)}
        info["calib"] = rates
    except Exception as exc:  # noqa: BLE001
        info["calib_err"] = repr(exc)
    try:
        import c_engine as _ce  # noqa: PLC0415
        info["heap"] = _ce.heap_stat()
    except Exception as exc:  # noqa: BLE001
        info["heap_err"] = repr(exc)
    try:
        import ctypes as _ct
        from ctypes import wintypes as _wt

        class _PMC(_ct.Structure):
            _fields_ = [("cb", _wt.DWORD), ("PageFaultCount", _wt.DWORD),
                        ("PeakWorkingSetSize", _ct.c_size_t),
                        ("WorkingSetSize", _ct.c_size_t),
                        ("QuotaPeakPagedPoolUsage", _ct.c_size_t),
                        ("QuotaPagedPoolUsage", _ct.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", _ct.c_size_t),
                        ("QuotaNonPagedPoolUsage", _ct.c_size_t),
                        ("PagefileUsage", _ct.c_size_t),
                        ("PeakPagefileUsage", _ct.c_size_t)]
        pmc = _PMC()
        pmc.cb = _ct.sizeof(_PMC)
        if _ct.windll.psapi.GetProcessMemoryInfo(
                _ct.windll.kernel32.GetCurrentProcess(),
                _ct.byref(pmc), pmc.cb):
            info["rss_mb"] = round(pmc.WorkingSetSize / 1048576, 1)
    except Exception as exc:  # noqa: BLE001
        info["rss_err"] = repr(exc)
    return info


# ---------------------------------------------------------------- API 透传
@app.api_route("/api/{path:path}", methods=["GET", "POST"])
async def api_proxy(path: str, request: Request):
    """任意囧次元端点透传：GET 纯 query；POST body JSON 作信封业务参数。"""
    api = get_api()
    real = "/app/" + path if not path.startswith("/") else path
    if request.url.query:
        real += "?" + request.url.query
    params = None
    if request.method == "POST":
        raw = await request.body()
        if raw:
            import json
            try:
                params = json.loads(raw)
            except Exception:  # noqa: BLE001
                params = {}
    if request.method == "GET":
        ck = "G:" + real
        hit = _cache_get(ck)
        if hit is not None:
            return JSONResponse(hit)
    try:
        res = await _run_jcy(api.request, request.method, real, params)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"code": -2, "message": "上游请求失败: %r" % exc}, status_code=502)
    if request.method == "GET" and isinstance(res, dict) and res.get("code") in (200, 20000):
        _cache_put(ck, res)
    return JSONResponse(res)


# V24 并行化：C 转译引擎上线后 Unicorn 不再在热路径（仅 authgen 冷启动子进程），
# DLL 标定内部为单例全局态 → 标定调用需全局锁，其余（HTTP/RSA/AES 求逆/缓存命中）
# 均可并行。每线程独立 JcyApi（各自 EDecryptor/EOracle/auth 缓存），互不竞态。
import asyncio  # noqa: E402
import concurrent.futures as _futures  # noqa: E402
import threading  # noqa: E402

_JCY_EXECUTOR = _futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="jcy")
_TLS = threading.local()
_AUTH_LOCK = threading.Lock()  # 防止多线程同时冷启动 authgen 子进程


async def _run_jcy(fn, *args):
    """JcyClient 为同步 http.client + DLL/Unicorn：丢进线程池并行，避免阻塞事件循环。"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_JCY_EXECUTOR, lambda: fn(*args))


def get_api() -> JA.JcyApi:
    api = getattr(_TLS, "api", None)
    if api is None:
        with _AUTH_LOCK:
            api = JA.JcyApi(timeout=30)
        _TLS.api = api
    return api


# ---- GET 响应短 TTL 缓存：吸收 TanStack Query 重复请求 / 翻页重叠 / StrictMode 双挂 ----
_RESP_TTL = 30.0
# 低频变更端点（频道/配置/轮播/签到规则/会员价）放宽到 5 分钟
_RESP_TTL_LONG = 300.0
_LONG_TTL_MARKERS = ("config", "channel", "banners", "sign_rule", "vip_price")
# /resolve：同 vid/part 的 source+urls 跨请求 100% 稳定（2026-10-07 连测 3 次），
# 一次观看会话内重复解析直接命中，60s 足够短以免吃掉直链轮换。
_RESP_TTL_RESOLVE = 60.0
_RESP_CACHE: dict[str, tuple[float, object]] = {}
_RESP_CACHE_CAP = 300
_RESP_LOCK = threading.Lock()


def _ttl_for(key: str) -> float:
    if key.startswith("R:"):
        return _RESP_TTL_RESOLVE
    if any(m in key for m in _LONG_TTL_MARKERS):
        return _RESP_TTL_LONG
    return _RESP_TTL


def _cache_get(key: str):
    now = time.time()
    ttl = _ttl_for(key)
    with _RESP_LOCK:
        hit = _RESP_CACHE.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
        if hit:
            _RESP_CACHE.pop(key, None)
    return None


def _cache_put(key: str, payload) -> None:
    with _RESP_LOCK:
        if len(_RESP_CACHE) >= _RESP_CACHE_CAP:
            _RESP_CACHE.pop(next(iter(_RESP_CACHE)), None)
        _RESP_CACHE[key] = (time.time(), payload)


# ---------------------------------------------------------------- 播放解析
@app.post("/resolve")
async def resolve(body: dict):
    """播放闭环服务端半程：/app/video/play 凭证 + 外链解析器 → 多清晰度 urls。"""
    vid = str(body.get("vid") or "").strip()
    if not vid:
        return JSONResponse({"code": 40000, "message": "缺少 vid"}, status_code=400)
    play_fmt = str(body.get("play") or "mp4")
    part = body.get("part")
    # 结果缓存：source/urls 同 (vid, play, part) 跨请求稳定 → 重复解析秒回
    ck = "R:%s|%s|%s" % (vid, play_fmt, part or "")
    hit = _cache_get(ck)
    if hit is not None:
        _register_dynamic_hosts(hit)      # 缓存命中也要续直链域名白名单 TTL
        return JSONResponse(hit)
    api = get_api()
    try:
        r = await _run_jcy(api.play, vid, play_fmt, part, True, True)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"code": -2, "message": "解析失败: %r" % exc}, status_code=502)
    # 前端只需要 urls/playAddr/code；lua/play 原文体积大且无用途，剥离
    r.pop("lua", None)
    play = r.pop("play", None)
    if isinstance(play, dict):
        r["message"] = play.get("message")
    # 直链域名登记进动态白名单（/stream 放行的依据），见 _register_dynamic_hosts
    _register_dynamic_hosts(r)
    if r.get("urls") or r.get("playAddr"):
        _cache_put(ck, r)
    return JSONResponse(r)


# ---------------------------------------------------------------- 视频流代理
# 域名白名单 = 静态后缀（历史观测值兜底）∪ 动态登记（resolve 响应里出现过的直链域名）。
# 直链 CDN 随片源变化（小红书 xhscdn 即 2026-10 新增案例），纯静态表每遇新 CDN 就要
# 手工补；动态表让 resolve 成功返回的域名自动放行一段时间。签名直链有效期通常数小时，
# TTL 取 6h 覆盖一次观看会话；重解析会自动续期。
_STREAM_HOST_SUFFIXES = (
    "myqcloud.com", "toutiaovod.com", "douyinvod.com", "bdxiguavod.com",
    "aliyuncs.com", "kwimgs.com", "dcarvod.com", "douyin.com",
    "zshtys888.com", "xajtl.com",
)

_DYN_HOSTS: dict[str, float] = {}
_DYN_TTL = 6 * 3600
_DYN_CAP = 512
_DYN_LOCK = threading.Lock()


def _register_dynamic_hosts(payload) -> None:
    """resolve 成功后登记直链域名（urls[].url / urls[].playAddr / playAddr[]）。"""
    now = time.time()
    urls: list[str] = []
    if isinstance(payload, dict):
        for u in payload.get("urls") or []:
            if isinstance(u, dict):
                for k in ("url", "playAddr"):
                    v = u.get(k)
                    if isinstance(v, str) and v.startswith("http"):
                        urls.append(v)
        for v in payload.get("playAddr") or []:
            if isinstance(v, str) and v.startswith("http"):
                urls.append(v)
    with _DYN_LOCK:
        if len(_DYN_HOSTS) > _DYN_CAP:
            for h, exp in list(_DYN_HOSTS.items()):
                if exp <= now:
                    _DYN_HOSTS.pop(h, None)
            if len(_DYN_HOSTS) > _DYN_CAP:   # 仍超上限：整表自愈清空
                _DYN_HOSTS.clear()
        for u in urls:
            host = (urlsplit(u).hostname or "").lower()
            if host:
                _DYN_HOSTS[host] = now + _DYN_TTL


def _allowed(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if any(host == s or host.endswith("." + s) for s in _STREAM_HOST_SUFFIXES):
        return True
    with _DYN_LOCK:
        exp = _DYN_HOSTS.get(host)
    return bool(exp and exp > time.time())


@app.api_route("/stream", methods=["GET", "HEAD"])
async def stream(request: Request, url: str):
    """按 Lua custom_head 规则注入 UA/Referer，Range 原样转发，流式回传。"""
    if not _allowed(url):
        return JSONResponse({"code": 403, "message": "域名不在直链白名单"}, status_code=403)
    headers = JA.JcyApi.direct_headers(url)      # {"User-Agent": "", "Referer": ...}
    rng = request.headers.get("range")
    fwd = {k: v for k, v in headers.items() if v is not None}
    if rng:
        fwd["Range"] = rng
    elif request.method == "HEAD":
        # HEAD 探测总大小：上游发 Range bytes=0-0 → 206 + Content-Range 全长（多数 CDN 不接受真 HEAD）
        fwd["Range"] = "bytes=0-0"
    client = get_client()
    try:
        req = client.build_request("GET", url, headers=fwd)
        resp = await client.send(req, stream=True)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"code": -2, "message": "CDN 请求失败: %r" % exc}, status_code=502)

    out = {}
    for h in ("content-type", "content-length", "content-range", "accept-ranges"):
        if resp.headers.get(h):
            out[h] = resp.headers[h]

    if request.method == "HEAD":
        await resp.aclose()
        return Response(status_code=resp.status_code, headers=out)

    async def gen():
        try:
            async for chunk in resp.aiter_bytes(256 * 1024):
                yield chunk
        finally:
            await resp.aclose()

    return StreamingResponse(gen(), status_code=resp.status_code, headers=out,
                             media_type=resp.headers.get("content-type", "video/mp4"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8792, log_level="info")
