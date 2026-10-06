# -*- coding: utf-8 -*-
"""jcy_api.py — 囧次元 App 级接口客户端（正常请求 → 直接返回明文数据）。

在 JcyClient（35 接口实测矩阵的管线）之上封装 App 业务层：
authentication 签名、POST 信封加密（P0.P1）、响应离线解密全部自动完成，
调用方拿到的是解密后的明文 JSON，无任何手动解密步骤。

  库用法::

      from jcy_api import JcyApi
      api = JcyApi()
      api.video_list(channel=1)          # 首页列表
      api.video_detail(113459)           # 详情（含集数）
      api.search("吞噬星空")              # 搜索
      api.danmu(113459, "第1集")          # 弹幕
      api.play(113459)                   # 播放凭证 → 解析器 → 多清晰度直链
      api.request("GET", "/app/config")  # 任意端点透传

  CLI 用法（仓库根目录）::

      ./.venv/Scripts/python.exe research/deliverables/jcy_api.py config
      .../jcy_api.py list --channel 1 --page 1
      .../jcy_api.py detail 113459
      .../jcy_api.py search 吞噬星空
      .../jcy_api.py play 113459            # 打印 1080P/4K 直链
      .../jcy_api.py danmu 113459 第1集
      .../jcy_api.py get  "/app/vod_comment/getlist?vid=113459&page=1"
      .../jcy_api.py post "/app/video/record" '{}'

说明:
  * 游客态可用的端点（config/列表/详情/搜索/弹幕/评论/播放等 25 个）直接可用；
    需登录态的端点（/app/users/info、/app/history 等）返回 50008 属服务端预期。
  * authentication 通过 authgen 子进程生成并落盘缓存（.auth_cache.json，
    80s 复用窗口 < 服务端 2min 校验），跨进程/跨命令复用，避免重复 3-4s 取签。
  * 播放链解析器参数（盐/密钥/解析器地址）优先取 play 响应下发的现役 Lua，
    缺失时回退 V14 收官默认值（盐 pzizhsqjjt）。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from urllib.parse import urlencode, quote, urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import jcy_client as JC  # noqa: E402  (自带 sys.path 装配)

AUTH_CACHE = os.path.join(_HERE, ".auth_cache.json")


# ---------------------------------------------------------------- 客户端
class DiskAuthClient(JC.JcyClient):
    """在 JcyClient 的 90s 内存缓存外增加磁盘缓存，CLI 反复调用免重复取签。"""

    TTL = 80.0  # 秒；服务端对 ts 的容忍窗口为 2 分钟，留安全余量

    def _auth_header(self):
        now = time.time()
        try:
            with open(AUTH_CACHE, encoding="utf-8") as f:
                o = json.load(f)
            if o.get("auth") and now - o.get("at", 0) < self.TTL:
                return int(o["ts"]), o["auth"]
        except Exception:  # noqa: BLE001
            pass
        ts, auth = super()._auth_header()
        try:
            with open(AUTH_CACHE, "w", encoding="utf-8") as f:
                json.dump({"ts": ts, "auth": auth, "at": now}, f)
        except Exception:  # noqa: BLE001
            pass
        return ts, auth


class JcyApi:
    """App 级 API。所有方法返回解密后的明文 JSON dict（含 code/message/data）。"""

    # 现役解析器默认参数（V14 收官；优先被 play 响应下发的 Lua 覆写）
    SALT = "pzizhsqjjt"
    PARSER = "http://yh.jx.xajtl.com/vo1v03.php?url="
    AES_KEY = "rdcibneoapyspqlt"
    AES_IV = "fyoofrebaxjwioxn"
    APP_VERSION = "1.5.8.0"
    PLATFORM = "Android"

    # 直链 Referer 特例（Lua custom_head 规则；默认 UA 空、Referer=直链自身）
    REFERER_OVERRIDES = {
        "aliyuncs.com": "https://www.piccopilot.com",
        "toutiaovod.com": "",
        "kwimgs.com": "https://www.kuaishou.com",
        "dcarvod.com": "https://www.dongchedi.com",
        "douyinvod.com": "https://www.douyin.com",
    }

    def __init__(self, timeout: int = 25):
        if os.environ.get("JCY_HOST"):
            JC.HOST = os.environ["JCY_HOST"]
        if os.environ.get("JCY_PORT"):
            JC.PORT = int(os.environ["JCY_PORT"])
        self.timeout = timeout
        self.cli = DiskAuthClient()

    # ---- 底层 ----
    def request(self, method: str, path: str, params: dict | None = None) -> dict:
        r = self.cli.request(method, path, params, timeout=self.timeout)
        if r.get("encrypted") and r.get("json") is not None:
            return r["json"]
        if r.get("encrypted"):
            return {"code": -1, "message": "响应已解密但非 JSON",
                    "plain_head": r.get("plain", b"")[:200].decode("utf-8", "replace")}
        j = r.get("json")
        if isinstance(j, dict):
            return j  # 明文错误（30000/403501/40000/50008…）或明文 JSON 端点（如弹幕）
        return {"code": -1, "message": "非 JSON 响应", "raw_head": (r.get("raw") or "")[:200]}

    @staticmethod
    def ok(j: dict) -> bool:
        return isinstance(j, dict) and j.get("code") in (200, 20000)

    @staticmethod
    def data(j: dict):
        """取业务 data；服务端部分端点 data 直接是载荷，部分再包一层。"""
        return j.get("data") if isinstance(j, dict) else None

    # ---- 配置类 ----
    def config(self):
        return self.request("GET", "/app/config")

    def channels(self):
        return self.request("GET", "/app/channel?top-level=true")

    def banners(self, channel: int = 0):
        return self.request("GET", "/app/banners/%s" % channel)

    def update_list(self, date: str):
        """date: YYYY-MM-DD 排期表"""
        return self.request("GET", "/app/video_update_list/%s" % date)

    def sign_rule(self):
        return self.request("GET", "/app/task/sign_rule")

    def vip_prices(self):
        return self.request("GET", "/app/vip_price/list")

    # ---- 视频类 ----
    def video_list(self, channel: int = 1, sort: str = "weight",
                   limit: int = 6, page: int = 1):
        q = urlencode({"channel": channel, "sort": sort, "limit": limit, "page": page})
        return self.request("GET", "/app/video/list?" + q)

    def video_detail(self, vid):
        return self.request("GET", "/app/video/detail?id=%s" % vid)

    def search(self, key: str, limit: int = 25, page: int = 1):
        q = urlencode({"key": key, "limit": limit, "page": page})
        return self.request("GET", "/app/video/search?" + q)

    def suggest(self, key: str, limit: int = 10, page: int = 1):
        """搜索联想词（/app/video/key，非播放密钥交换）"""
        q = urlencode({"key": key, "limit": limit, "page": page})
        return self.request("GET", "/app/video/key?" + q)

    def comments(self, vid, page: int = 1, limit: int = 20):
        q = urlencode({"vid": vid, "limit": limit, "page": page})
        return self.request("GET", "/app/vod_comment/getlist?" + q)

    def comment_top(self, vid):
        return self.request("GET", "/app/vod_comment/gettop?vid=%s" % vid)

    def comment_hot(self, vid):
        return self.request("GET", "/app/vod_comment/gethitstop?vid=%s" % vid)

    def danmu(self, vid, part: str, play: str = "mp4",
              start_ms: int = 0, end_ms: int = 60000):
        """弹幕（必带 part 集名；该端点响应为明文 JSON）。播放中按 60s 轮询增量。"""
        q = urlencode({"vid": vid, "play": play, "part": part,
                       "start_time_point": start_ms, "end_time_point": end_ms})
        return self.request("GET", "/app/danmu?" + q)

    # ---- 播放链 ----
    def play(self, vid, play_fmt: str = "mp4", part: str | None = None,
             resolve: bool = True):
        """播放凭证 + 解析器。返回::

            {"code": ..., "play": <play 原始响应>, "source": <source 串>,
             "lua": <现役解析脚本>, "playAddr": [...],
             "urls": [{"name","vcodec","format","url","headers"}, ...]}

        resolve=False 时只拿播放凭证，不请求外链解析器。
        """
        if part is None:
            det = self.data(self.video_detail(vid)) or {}
            for ln in det.get("parts") or []:
                if isinstance(ln, dict) and ln.get("part"):
                    part = ln["part"][0]
                    play_fmt = ln.get("play") or play_fmt
                    break
        part = part or "第1集"
        q = "/app/video/play?id=%s&play=%s&part=%s" % (
            vid, quote(str(play_fmt)), quote(str(part)))
        pj = self.request("POST", q, {})
        out = {"code": pj.get("code") if isinstance(pj, dict) else None,
               "play": pj, "source": None, "lua": None,
               "playAddr": [], "urls": []}
        pd = self.data(pj)
        if isinstance(pd, list):                      # 现役形态: data 直接是条目数组
            entries = pd
        elif isinstance(pd, dict) and isinstance(pd.get("data"), list):
            entries = pd["data"]
        else:
            entries = []
        entry = entries[0] if entries else {}
        source, lua = entry.get("url"), entry.get("parse") or ""
        out["source"], out["lua"] = source, lua
        if not source or not resolve:
            return out

        salt, aes_key, aes_iv, parser = self._lua_params(lua)
        ts = int(time.time() * 1000)
        s1 = hashlib.md5((self.APP_VERSION + salt + str(ts)).encode()).hexdigest()
        s2 = hashlib.md5((source + salt + str(ts)).encode()).hexdigest()
        import http.client
        # 解析器前缀转 (host, 相对路径)，如 "http://yh.jx.xajtl.com/vo1v03.php?url="
        prest = parser.split("://", 1)[-1]
        phost, _, ppath = prest.partition("/")
        conn = http.client.HTTPConnection(phost, 80, timeout=self.timeout)
        try:
            conn.request("GET", "/" + ppath + source + "&t=" + str(ts), headers={
                "x-time": str(ts), "x-form": self.PLATFORM,
                "x-sign1": s1, "x-sign2": s2,
                "user-agent": "Dart/3.6 (dart:io)"})
            r = conn.getresponse()
            ptxt = r.read().decode("utf-8", "replace")
        finally:
            conn.close()
        pobj = self._parse_resolver(ptxt, aes_key, aes_iv)
        pa = pobj.get("data", {}).get("playAddr") if isinstance(pobj, dict) else None
        out["playAddr"] = pa if isinstance(pa, list) else []
        out["resolver_raw"] = pobj if pobj is not None else ptxt[:400]
        if not out["playAddr"] and isinstance(pobj, dict) and pobj.get("url"):
            # 旧结构：单 URL（{code:200, type:"mp4", url:...}），无清晰度分级
            url = pobj["url"]
            out["urls"].append({"name": str(pobj.get("type") or "mp4"),
                                "vcodec": None, "format": pobj.get("type"),
                                "url": url, "headers": self.direct_headers(url)})
            return out
        for it in out["playAddr"]:
            url = (it.get("m3u8FileDomain") or "") + (it.get("addr") or "")
            out["urls"].append({
                "name": ("%s %s" % (it.get("desc", ""), it.get("title", ""))).strip(),
                "vcodec": it.get("vcodec"), "format": it.get("format"),
                "url": url, "headers": self.direct_headers(url)})
        return out

    @classmethod
    def _lua_params(cls, lua: str):
        def rx(pat, default):
            m = re.search(pat, lua)
            return m.group(1) if m else default
        salt = rx(r'salt\s*=\s*"([^"]+)"', cls.SALT)
        aes_key = rx(r'aes_key\s*=\s*"([^"]+)"', cls.AES_KEY)
        aes_iv = rx(r'aes_iv\s*=\s*"([^"]+)"', cls.AES_IV)
        urls = re.findall(r'https?://[^\s"\'\]]+', lua)
        parser = next((u for u in urls if u.rstrip("/").endswith("=") or ".php?url=" in u),
                      cls.PARSER)
        return salt, aes_key, aes_iv, parser

    @classmethod
    def _parse_resolver(cls, ptxt: str, aes_key: str, aes_iv: str):
        """解析器响应：明文 JSON 优先，失败按 Lua 兜底走 AES128-CBC。

        密文编码候选：hex → 自定义字母表 b64 → 标准 b64（实测两种都有出现）。
        """
        try:
            return json.loads(ptxt)
        except Exception:  # noqa: BLE001
            pass
        import base64
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        from jcy_protocol.auth import custom_b64d
        s = ptxt.strip()
        candidates = []
        if re.fullmatch(r"[0-9a-fA-F]+", s or "x") and len(s) % 32 == 0:
            candidates.append(bytes.fromhex(s))
        for dec in (custom_b64d,
                    lambda t: base64.b64decode(t + "=" * (-len(t) % 4))):
            try:
                candidates.append(dec(s))
            except Exception:  # noqa: BLE001
                pass
        for raw in candidates:
            try:
                pt = unpad(AES.new(aes_key.encode(), AES.MODE_CBC,
                                   aes_iv.encode()).decrypt(raw), 16)
                return json.loads(pt.decode("utf-8"))
            except Exception:  # noqa: BLE001
                continue
        raise ValueError("解析器响应无法解析（明文 JSON/AES hex/b64 均失败），头 80 字节: %r" % s[:80])

    @classmethod
    def direct_headers(cls, url: str) -> dict:
        host = urlsplit(url).hostname or ""
        referer = url
        for dom, ref in cls.REFERER_OVERRIDES.items():
            if host.endswith(dom):
                referer = ref
                break
        return {"User-Agent": "", "Referer": referer}


# ---------------------------------------------------------------- CLI
def _print(obj):
    txt = json.dumps(obj, ensure_ascii=False, indent=1)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(txt)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="囧次元 App 级接口客户端（自动签名/加密/解密）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("config")
    sub.add_parser("channels")
    p = sub.add_parser("banner"); p.add_argument("channel", nargs="?", type=int, default=0)
    p = sub.add_parser("list")
    p.add_argument("--channel", type=int, default=1); p.add_argument("--sort", default="weight")
    p.add_argument("--limit", type=int, default=6); p.add_argument("--page", type=int, default=1)
    p = sub.add_parser("detail"); p.add_argument("vid")
    p = sub.add_parser("search"); p.add_argument("key")
    p.add_argument("--limit", type=int, default=25); p.add_argument("--page", type=int, default=1)
    p = sub.add_parser("suggest"); p.add_argument("key")
    p = sub.add_parser("update"); p.add_argument("date", nargs="?", default=time.strftime("%Y-%m-%d"))
    p = sub.add_parser("comments"); p.add_argument("vid"); p.add_argument("--page", type=int, default=1)
    p = sub.add_parser("danmu"); p.add_argument("vid"); p.add_argument("part")
    p.add_argument("--start", type=int, default=0); p.add_argument("--end", type=int, default=60000)
    p = sub.add_parser("play"); p.add_argument("vid"); p.add_argument("part", nargs="?")
    p.add_argument("--play", default="mp4"); p.add_argument("--no-resolve", action="store_true")
    p = sub.add_parser("get"); p.add_argument("path")
    p = sub.add_parser("post"); p.add_argument("path"); p.add_argument("json", nargs="?", default="{}")
    a = ap.parse_args(argv)

    api = JcyApi()
    t0 = time.time()
    if a.cmd == "config":
        r = api.config()
    elif a.cmd == "channels":
        r = api.channels()
    elif a.cmd == "banner":
        r = api.banners(a.channel)
    elif a.cmd == "list":
        r = api.video_list(a.channel, a.sort, a.limit, a.page)
    elif a.cmd == "detail":
        r = api.video_detail(a.vid)
    elif a.cmd == "search":
        r = api.search(a.key, a.limit, a.page)
    elif a.cmd == "suggest":
        r = api.suggest(a.key)
    elif a.cmd == "update":
        r = api.update_list(a.date)
    elif a.cmd == "comments":
        r = api.comments(a.vid, a.page)
    elif a.cmd == "danmu":
        r = api.danmu(a.vid, a.part, start_ms=a.start, end_ms=a.end)
    elif a.cmd == "play":
        r = api.play(a.vid, a.play, a.part, resolve=not a.no_resolve)
        if r.get("urls"):
            print("# 可播直链（%d 条，独立完整文件，切换清晰度=换索引）" % len(r["urls"]))
            for i, u in enumerate(r["urls"]):
                print("[%d] %s (%s/%s)\n    %s\n    头: %s" % (
                    i, u["name"], u["vcodec"], u["format"], u["url"],
                    json.dumps(u["headers"], ensure_ascii=False)))
            print("# 完整响应:")
        elif r.get("source") and a.no_resolve:
            print("# source 串: %s" % r["source"])
    elif a.cmd == "get":
        r = api.request("GET", a.path)
    elif a.cmd == "post":
        r = api.request("POST", a.path, json.loads(a.json))
    _print(r)
    sys.stderr.write("[%s] %.1fs code=%s\n" % (
        a.cmd, time.time() - t0, r.get("code") if isinstance(r, dict) else "?"))
    return 0 if api.ok(r) else 1


if __name__ == "__main__":
    sys.exit(main())
