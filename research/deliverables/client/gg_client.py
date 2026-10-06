# -*- coding: utf-8 -*-
"""囧次元 (com.tudou.tool / package:guoguo) API client skeleton
逆向来源: out/jadx_src + libapp.so 字符串取证 (见 ../VERIFICATION.txt)
所有不确定值均为占位符: TOKEN/APPID/SIGN_* —— 需在真机抓包后回填。
"""
import base64
import hashlib
import json
import time
from hashlib import md5

import requests

HOST_API = "http://pzl.clicli.blog:8087"   # 静态证据: libapp.so 字符串
HOST_API2 = "http://pzl.clicli.blog:8088"  # 分享域 (GShareDomain port 可配)
HOST_VOD = "https://vod.api.zshtys888.com" # 点播解析域

APPID = "APPID"            # 常量; 数值需抓包回填
TOKEN = "TOKEN"            # /app/users/login 返回 user_token
TIMESTAMP_FN = int          # utils_timestamp (秒)

# ---------- 与内嵌 Lua utils 等价的方法 (out/VERIFICATION.txt 第3节) ----------

def utils_md5(s: str) -> str:
    return md5(s.encode()).hexdigest()

def utils_timestamp() -> int:
    return int(time.time())

def utils_base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def utils_base64_decode(s: str) -> bytes:
    return base64.b64decode(s)

def utils_aes128cbc_encrypt(key: bytes, iv: bytes, data: bytes,
                            padding: str = "pkcs7") -> bytes:
    """与 vmplugin.utils_aes128cbc_encrypt 等价; padding 经 option["padding"] 传入"""
    from Crypto.Cipher import AES
    assert len(key) == 16 and len(iv) == 16
    if padding == "pkcs7":
        pad = 16 - len(data) % 16
        data = data + bytes([pad]) * pad
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

def utils_aes128cbc_decrypt(key: bytes, iv: bytes, data: bytes,
                            padding: str = "pkcs7") -> bytes:
    from Crypto.Cipher import AES
    out = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    if padding == "pkcs7":
        out = out[:-out[-1]]
    return out

# ---------- 签名占位 (需抓包确认组合顺序) ----------

def sign(body: dict, rule: dict) -> dict:
    """GSignRuleData(extend_sign_encourage, GSignRuleItem(key)) 服务端规则。
    候选参与字段: apk_sign / signnum / current_timestamp / nonce / appid /
    secretid / token 。 SIGN_ALGO: md5 | sha1 | hmac-md5 | aes-cbc
    抓包时先打印 rule 全量, 再按 GET 顺序重放。"""
    raise NotImplementedError("回填 SIGN_FN 后启用")

HEADERS = {
    "X-Token": TOKEN,        # user_token 头 (libapp.so: "X-Token")
    "appid": APPID,
    # 以下按抓包回填: sign / timestamp / nonce / signnum / apk_sign
}

# ---------- 接口清单 (来自 libapp.so 字符串, 全部实测路径) ----------

class Api:
    s = requests.Session()

    @classmethod
    def get(cls, path, params=None, **kw):
        r = cls.s.get(HOST_API + path, params=params, headers=HEADERS, **kw)
        env = r.json()
        assert env["code"] == 0, env
        return env["data"]

    # 配置 / 更新
    def app_config(self):        return self.get("/app/config")          # GAppConfig(data:[GAppConfigItem])
    def app_update(self):        return self.get("/app/update")          # GUpdate/GUpdateData(下载索引 {"downloadIndex":..})

    # 账号
    def smscode(self, phone):    return self.get("/app/users/smscode", {"phone": phone})
    def login(self, phone, code):return self.get("/app/users/login", {"phone": phone, "code": code})
    def user_info(self):         return self.get("/app/users/info")      # GUserInfo

    # 内容
    def video_list(self, **q):   return self.get("/app/video/list", q)   # GVideoPage(total:..)
    def video_detail(self, vid): return self.get("/app/video/detail", {"vid": vid})  # GVideoDetail
    def video_source(self, vid): return self.get("/app/video_source", {"vid": vid})  # GVideoSourceItem(play:..)
    def search(self, kw, page=1):return self.get("/app/video/search", {"keyword": kw, "page": page})
    def video_key(self, vid):    return self.get("/app/video/key", {"vid": vid})     # 播放密钥交换 (RSA/AES 环节)

    # 播放链路 (深度点)
    def play(self, vid, cid):    return self.get("/app/video/play", {"vid": vid, "cid": cid})
    def play_connect(self, vid): return self.get("/app/video/play-connect", {"vid": vid})
    def play_addr(self, **q):
        """GUrlParsed(name, raw_play_url, m3u8FileDomain) -> getM3U8Url / getM3U8File"""
        return self.get("/app/playaddr/v4/client", q)

    # VIP / 任务 / 弹幕
    def vip_price(self):         return self.get("/app/vip_price/list")
    def vip_buy(self, **q):      return self.get("/app/vip_price/buy", q)
    def vip_exchange(self, code):return self.get("/app/vip_ticket/exchange", {"code": code})
    def task(self):              return self.get("/app/task/task")
    def danmaku(self, vid):      return self.get("/api_utils/danmaku/danmaku", {"vid": vid})

# ---------- 解析管线 (Lua source -> httpGet -> urlParsed) ----------
# 规则: Lua 脚本经 vmplugin.invoke_method('httpGet', json{url,header})
# 可注入 lua_header; 结果经 json.decode 进 GUrlParsed;
# m3u8 再经 getM3U8File/checkM3u8; #EXT-X-KEY: 用 utils_aes128cbc_decrypt。

if __name__ == "__main__":
    cfg = Api().app_config()      # 先拉配置拿 GSignRuleData + 分享域
    print(json.dumps(cfg, ensure_ascii=False)[:500])


# =====================================================================
# 第二阶段 (2026-09-28): 已验证加密层 — 全部经真机 hook + 解密实测
# 证据: out/API_ANALYSIS.md 增补节; out/hex_log.jsonl; out/ffi_log.jsonl
# =====================================================================

HOST_API_LIVE = "http://43.145.33.254:27990"   # 当前生效主 API (抓包确认)

# --- 通道 1: 监控通道 (libcore.so call, C2 心跳) ---
MON_KEY = b"qPwClBj7j7ZQraSm"
MON_IV  = b"p3JdVQl3q7WQJIgG"

# --- 通道 2: 信令通道 (libloader.so call, WebRTC/上报) ---
SIG_KEY = b"kFGTbLlOzFHQCIKp"
SIG_IV  = b"F3q22XoM8l6T2Ydc"


def channel_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> str:
    """通道帧加密: AES-128-CBC PKCS7 → base64 (单字符串进出 FFI call)"""
    return utils_aes128cbc_encrypt(key, iv, plaintext).hex() and \
        __import__("base64").b64encode(utils_aes128cbc_encrypt(key, iv, plaintext)).decode()


def channel_decrypt(b64frame: str, key: bytes, iv: bytes) -> bytes:
    """通道帧解密: base64 → AES-128-CBC PKCS7 unpad"""
    return utils_aes128cbc_decrypt(key, iv, base64.b64decode(b64frame))


def monitor_frame(action: str, params: dict, filler_pairs: int = 12) -> str:
    """构造监控通道上行帧: 诱饵 JSON (随机 16 字符键值对) 内嵌真实指令。"""
    import random, string
    def rnd16():
        return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    obj = {}
    for _ in range(filler_pairs):
        obj[rnd16()] = rnd16()
    obj["action"] = action
    obj["params"] = json.dumps(params)
    return channel_encrypt(json.dumps(obj).encode(), MON_KEY, MON_IV)


def signaling_request(action: str, params: dict, filler_pairs: int = 12) -> str:
    """信令通道上行 (libloader call 的输入): 同诱饵 JSON 结构, kFGT 系 key"""
    import random, string
    def rnd16():
        return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    obj = {}
    for _ in range(filler_pairs_default()):
        obj[rnd16()] = rnd16()
    obj["action"] = action
    obj.update(params)
    return channel_encrypt(json.dumps(obj).encode(), SIG_KEY, SIG_IV).encode()


def filler_pairs_default():
    return 12


def signaling_decrypt_response(b64frame: str) -> bytes:
    """信令通道响应解密 — 实测: VuVH8nti+... → get_app_info JSON"""
    return channel_decrypt(b64frame, SIG_KEY, SIG_IV)


def monitor_decrypt_response(b64frame: str) -> bytes:
    """监控通道响应解密 (119B → 128B 帧已知结构)"""
    return channel_decrypt(b64frame, MON_KEY, MON_IV)


# --- 通道 3: HTTP API (43.145.33.254:27990) ---
# 头集合 (HeadersInterceptor 池引用实证):
#   APPID / ts(毫秒) / nonce(8位数字) / tcs=2 / x-version=2020-09-17 / authentication=<X-Token b64>
# body: "<P0_b64>.<P1_b64>" = apiEncrypt(随机 AES key/iv 加密业务 JSON + RSA-2048 包裹会话密钥)
# X-Token: 服务器响应头 new-token 下发, 与 ts/nonce 绑定 → 必须真机登录一次获取, 无法纯离线构造。

HTTP_HEADERS_STATIC = {
    "appid": "com.tudou.tool",
    "tcs": "2",
    "x-version": "2020-09-17",
    "user-agent": "Dart/3.6 (dart:io)",
}

def http_headers(x_token_b64: str) -> dict:
    """构造 HTTP 请求头。x_token_b64: 真机登录后 hook TokenInterceptor 抓到的 authentication 值"""
    h = dict(HTTP_HEADERS_STATIC)
    h["ts"] = str(int(time.time() * 1000))
    h["nonce"] = str(random.randint(10 ** 7, 10 ** 8 - 1))
    h["authentication"] = x_token_b64
    return h


# 常用 GET 端点 (无 body, 仅需有效头):
#   GET /app/video/list?channel=1&sort=weight&limit=6&page=1
#   GET /app/video/detail?id=<vid>
#   GET /app/banners/0   /app/channel?top-level=true   /app/danmu?vid=<vid>&play=mp4
# POST 端点 (body 需 apiEncrypt, 见 API_ANALYSIS.md §C):
#   /app/video/play?id=<vid>&play=<fmt>  /app/video/play-connect
#   /app/video/record  /app/video/device-base (登录)  /app/messagebox/give_me
