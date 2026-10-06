# -*- coding: utf-8 -*-
"""tmp_w1_apipost_create.py — 直调 Apipost MCP JSON-RPC 创建播放链两节点。

背景：ZCode 侧 create_target 参数无法随调用传输（schema 陷阱），按记忆
apipost-mcp-setup 用 python 直调 https://open.apipost.net/mcp。

节点 1：视频播放凭证 POST /app/video/play（复用视频列表节点的预/后任务模板）
节点 2：播放解析器 GET http://yh.jx.xajtl.com/vo1v03.php（纯外链，内联 md5 签名）
"""
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.expanduser("~/.zcode/cli/config.json"), encoding="utf-8"))
SERVER = CFG["mcp"]["servers"]["apipost-mcp"]
TOKEN = SERVER["headers"]["api-token"]
URL = SERVER["url"]
PROJECT = "6ef0f75d8470000"
FOLDER_VIDEO = "6ef0f76ca470000"      # 视频与播放

_ssl = __import__("ssl").create_default_context()
_ssl.check_hostname = False
import ssl as _sslmod
_ssl.verify_mode = _sslmod.CERT_NONE

SESSION = {"id": None}
_idc = [0]


def _post(payload):
    req = urllib.request.Request(URL, data=json.dumps(payload).encode(), method="POST", headers={
        "content-type": "application/json", "accept": "application/json, text/event-stream",
        "api-token": TOKEN, **({"Mcp-Session-Id": SESSION["id"]} if SESSION["id"] else {}),
    })
    r = urllib.request.urlopen(req, timeout=120, context=_ssl)
    sid = r.headers.get("Mcp-Session-Id") or r.headers.get("mcp-session-id")
    if sid:
        SESSION["id"] = sid
    body = r.read().decode("utf-8", "replace")
    # 响应可能是 SSE（data: 行）或纯 JSON
    if body.lstrip().startswith("event:") or "\ndata:" in body or body.lstrip().startswith("data:"):
        for line in body.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        return None
    return json.loads(body) if body.strip() else None


def rpc(method, params=None, notify=False):
    _idc[0] += 1
    payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if not notify:
        payload["id"] = _idc[0]
    r = _post(payload)
    if notify:
        return None
    if not r:
        raise RuntimeError("空响应: %s" % method)
    if "error" in r:
        raise RuntimeError("%s 错误: %s" % (method, json.dumps(r["error"], ensure_ascii=False)[:400]))
    return r.get("result")


# ---------------------------------------------------------------- 脚本文本
FORGE_PRE = '''// ===== 囧次元 自动取签 + 伪造加密请求体（加固版 v2）=====
// 前置：先运行「启动本地取签服务.bat」，看到 "authgen service started" 即可。
// 调本地 /forge 现算新鲜的 ts + authentication + 加密请求体，注入环境变量并直改请求头。
var _path = "/app/video/play";
var _url = "http://127.0.0.1:8791/forge?path=" + encodeURIComponent(_path)
         + "&params=" + encodeURIComponent("{}");
var _r = null;
console.log("[jcy] pre-script start -> " + _url);
try {
    await $.ajax({ method: "GET", url: _url, timeout: 120000,
        success: function (resp) { _r = resp; },
        error: function (e) { console.error("[jcy] $.ajax error: " + e); } });
} catch (e) {
    console.warn("[jcy] await $.ajax 异常, 走同步 XHR 兜底: " + e);
}
if (!_r) {
    try {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", _url, false);
        xhr.send(null);
        console.log("[jcy] xhr status=" + xhr.status);
        if (xhr.status === 200 && xhr.responseText) { _r = JSON.parse(xhr.responseText); }
    } catch (e2) { console.warn("[jcy] 同步 XHR 也失败: " + e2); }
}
if (_r && typeof _r === "string") { try { _r = JSON.parse(_r); } catch (e3) {} }
if (_r && !_r.authentication && _r.data && _r.data.authentication) { _r = _r.data; }
if (!_r || !_r.authentication) {
    console.error("[jcy] ❌ 取签失败，请先启动 authgen_server.py --warmup");
} else {
    var _auth = String(_r.authentication).replace(/[\\r\\n\\t]/g, "");
    var _ts = String(_r.ts);
    var _body = String(_r.body);
    try { apt.variables.set("jcy_auth", _auth); } catch (e) {}
    try { apt.globals.set("jcy_auth", _auth); } catch (e) {}
    try { apt.variables.set("jcy_ts", _ts); } catch (e) {}
    try { apt.globals.set("jcy_ts", _ts); } catch (e) {}
    try { apt.variables.set("jcy_body", _body); } catch (e) {}
    try { apt.globals.set("jcy_body", _body); } catch (e) {}
    try { apt.removeRequestHeader("ts"); } catch (e) {}
    try { apt.removeRequestHeader("authentication"); } catch (e) {}
    try { apt.removeRequestHeader("nonce"); } catch (e) {}
    try { apt.setRequestHeader("ts", _ts); } catch (e) {}
    try { apt.setRequestHeader("authentication", _auth); } catch (e) {}
    try { apt.setRequestHeader("nonce", String(Math.floor(Math.random() * 90000000 + 10000000))); } catch (e) {}
    try { apt.setRequestHeader("content-type", "application/json; charset=utf-8"); } catch (e) {}
    console.log("[jcy] ✅ ts=" + _ts + " auth=" + _auth.slice(0, 24) + "... body_len=" + _body.length);
}
'''

DECRYPT_POST = '''// ===== 囧次元 响应判定 + 离线解密 + 归档 =====
// P0=RSA(priv_from_go 解出 K16resp)；P1=E(K16resp) 逐块求逆 → 明文 JSON。
// 前置：本机运行 ./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup
// 关闭解密：环境变量 jcy_decrypt = 0。
var text = (response.raw && response.raw.responseText) || "";
var isEnvelope = text.indexOf(".") > 0 && text.length > 400 && text.charAt(0) !== "{";
var wantDecrypt = String(apt.variables.get("jcy_decrypt") || "1") !== "0";
if (isEnvelope) {
    apt.assert('response.raw.responseText.indexOf(".") > 0');
    console.log("[jcy] ✅ 认证通过, 返回加密业务数据 " + text.length + "B");
} else {
    console.warn("[jcy] ⚠ 非加密响应(明文错误码或空): " + text.slice(0, 200));
}
await $.ajax({
    method: "POST",
    url: "http://127.0.0.1:8791/store",
    timeout: 900000,
    headers: { "content-type": "application/json" },
    data: JSON.stringify({
        body: text,
        decrypt: isEnvelope && wantDecrypt,
        path: (typeof request !== "undefined" && request && request.url) ? request.url : "",
        ts: apt.variables.get("jcy_ts")
    }),
    success: function (r) {
        console.log("[jcy] 归档 verdict=" + JSON.stringify(r.verdict));
        if (r.decrypted && r.decrypted.ok) {
            var plain = JSON.stringify(r.decrypted.json);
            console.log("[jcy] 🔓 明文 " + r.decrypted.plain_len + "B: " + String(plain).slice(0, 600));
            apt.variables.set("jcy_plain", plain);
            apt.variables.set("jcy_k16resp", r.decrypted.k16resp);
            // 播放凭证专用：把 source 串写入 jcy_source 供「播放解析器」节点直接引用
            try {
                var j = r.decrypted.json;
                var arr = j && j.data;
                if (Array.isArray(arr) && arr[0] && arr[0].url) {
                    apt.variables.set("jcy_source", String(arr[0].url));
                    console.log("[jcy] ▶ jcy_source = " + String(arr[0].url));
                }
            } catch (e) {}
        } else if (r.decrypted && r.decrypted.error) {
            console.warn("[jcy] 解密失败: " + r.decrypted.error);
        }
    },
    error: function (e) {
        console.error("[jcy] 归档/解密失败: 请启动 authgen_server.py --warmup", e);
    }
});
'''

MD5_JS = open(os.path.join(HERE, "tmp_md5.js"), encoding="utf-8").read()
# 去掉 module.exports 行（预执行脚本非模块环境）
MD5_JS = "\n".join(l for l in MD5_JS.splitlines() if "module.exports" not in l)

PARSER_PRE = '''// ===== 囧次元 播放解析器签名（现役 lua：md5(x + "pzizhsqjjt" + ts)）=====
// 盐/算法取自 /app/video/play 响应下发的 parse 脚本（2026-10-05 实测）：
//   x-sign1 = md5(app_version + 盐 + ts)   app_version = "1.5.8.0"
//   x-sign2 = md5(source + 盐 + ts)        source = 播放凭证 data[0].url
// x-time = ts 毫秒；x-form = device_info.platform = "Android"
// 本节点纯外链不依赖本地取签服务；md5 为 RFC1321 标准实现(已与 hashlib 交叉验证)。
''' + MD5_JS + '''
var _SALT = "pzizhsqjjt";
var _ver = String(apt.variables.get("jcy_playver") || "1.5.8.0");
var _src = String(apt.variables.get("jcy_source") || "");
var _ts = String(Date.now());
if (!_src) {
    console.error("[jcy] ❌ 缺少变量 jcy_source（先发送「视频播放凭证」节点，或手填 source 串）");
} else {
    var _s1 = md5(_ver + _SALT + _ts);
    var _s2 = md5(_src + _SALT + _ts);
    try { apt.variables.set("jcy_ptime", _ts); } catch (e) {}
    try { apt.variables.set("jcy_sign1", _s1); } catch (e) {}
    try { apt.variables.set("jcy_sign2", _s2); } catch (e) {}
    try { apt.removeRequestHeader("x-time"); } catch (e) {}
    try { apt.removeRequestHeader("x-sign1"); } catch (e) {}
    try { apt.removeRequestHeader("x-sign2"); } catch (e) {}
    try { apt.setRequestHeader("x-time", _ts); } catch (e) {}
    try { apt.setRequestHeader("x-sign1", _s1); } catch (e) {}
    try { apt.setRequestHeader("x-sign2", _s2); } catch (e) {}
    console.log("[jcy] ✅ 解析器签名 ts=" + _ts + " sign1=" + _s1);
}
'''

PARSER_POST = '''// ===== 解析器响应判定：code==200 且含 playAddr（多清晰度）=====
var text = (response.raw && response.raw.responseText) || "";
try {
    var obj = JSON.parse(text);
    if (obj && (obj.code === 200 || obj.code === "200")) {
        var pa = obj.data && obj.data.playAddr;
        apt.assert("1==1");
        console.log("[jcy] ✅ 解析器 code=200, playAddr=" + (pa ? pa.length + " 个清晰度" : "(无)"));
        if (pa) {
            for (var i = 0; i < pa.length; i++) {
                console.log("[jcy] [" + i + "] " + (pa[i].desc || "") + " " + (pa[i].title || "")
                    + " " + (pa[i].vcodec || "") + " " + (pa[i].m3u8FileDomain || "") + (pa[i].addr || ""));
            }
        }
        apt.variables.set("jcy_parser_json", text);
    } else {
        apt.assert("1==2");
        console.warn("[jcy] ⚠ 解析器返回 code=" + (obj && obj.code) + ": " + text.slice(0, 200));
    }
} catch (e) {
    apt.assert("1==2");
    console.warn("[jcy] ⚠ 响应非明文 JSON(可能是 AES128-CBC 密文, key=rdcibneoapyspqlt iv=fyoofrebaxjwioxn): "
        + text.slice(0, 200));
}
'''

DESC_PLAY = """【2026-10-05 全链路打通 · 实测收官】播放凭证接口：给定视频 id + 线路格式 + 集数，返回 source 串 + 现役解析脚本。
完整播放链（全部实测验证）：
  1) GET /app/video/list (频道列表) → 选 id
  2) GET /app/video/detail?id=<id> → data.parts[]（线路: play=mp4, play_zh=线路3, part=["第1集"]）+ source
  3) POST /app/video/play?id=<id>&play=<parts[].play>&part=<parts[].part[k]>（本节点）
     → data[0].url = source 串（如 6157c9c16182997848431|f1b1811956986|0101c304d5f96|9214e904e808e2）
     → data[0].parse = 服务器下发的现役 Lua 解析脚本（aes_key/aes_iv/盐/解析器列表都在里面）
  4) GET http://yh.jx.xajtl.com/vo1v03.php?url=<source>&t=<ts>（见「播放解析器」节点）
     → {code:200, data.playAddr:[{title,desc,vcodec,addr,m3u8FileDomain,...}]} 多清晰度
  5) 直链 = m3u8FileDomain + addr；请求头按 parse 内 custom_head 规则：User-Agent 空，Referer=直链自身
     （toutiaovod.com 的 Referer 置空；aliyuncs→piccopilot.com；kwimgs→kuaishou.com；dcarvod→dongchedi.com；douyinvod→douyin.com）
实测样例(id=113459 第1集)：playAddr[0]=高清1080P H265 MP4(腾讯云, 206MB, HTTP206 ftyp ✓)
  playAddr[1]=超清4K H265 MP4(头条v3.toutiaovod.com, 438MB, HTTP206 ftyp ✓) —— 1080p/4K 切换=playAddr 数组索引。
请求体 = 伪造信封 {{jcy_body}}（内容为 {} 的 P0.P1 信封，由预脚本经本地 /forge 现算）。
前置：本机运行 ./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup。
后脚本会自动解密明文并把 data[0].url 写入变量 jcy_source（供「播放解析器」节点直接引用）。
一键兜底：GET http://127.0.0.1:8791/relay?path=/app/video/play&params={"id":"113459","play":"mp4","part":"第1集"}&method=POST"""

DESC_PARSER = """【2026-10-05 实测打通】外链播放解析器（无需囧次元头，只需 4 个 x-* 头）。
签名算法取自 /app/video/play 响应下发的现役 Lua（2026-10-05 实测；注意盐已从旧版 v50gjcy 更换）：
  盐 = "pzizhsqjjt"
  x-time = ts(毫秒)；x-form = "Android"
  x-sign1 = md5("1.5.8.0" + 盐 + ts)   // app_version，来自 device_info
  x-sign2 = md5(source + 盐 + ts)      // source = 播放凭证响应 data[0].url
请求 = GET 本节点 ?url=<source>&t=<ts>
响应：明文 JSON {code:200, data:{playAddr:[...]}}（若为密文则 AES128-CBC 解密，key=rdcibneoapyspqlt iv=fyoofrebaxjwioxn，同样来自 Lua）。
playAddr[] 每项 {title,desc,vcodec,addr,m3u8FileDomain,format}，直链 = m3u8FileDomain+addr；
清晰度列表 = playAddr 数组（App 按 desc+title 显示，如"1080P 高清"/"4K 超清"）。
直链请求头按 Lua custom_head：User-Agent 空；Referer=直链自身（toutiaovod.com Referer 置空）。
实测样例（source=6157c9c16182997848431|...，2026-10-05）：
  [0] 高清 1080P H265 MP4 → https://1251413404.vod2.myqcloud.com/... (HTTP 206, video/mp4, ftyp ✓, 217168708B)
  [1] 超清 4K  H265 MP4 → https://v3.toutiaovod.com/... (HTTP 206, video/mp4, ftyp ✓, 459730607B)
预脚本已内联 md5(RFC1321，与 hashlib 交叉验证)，自动现算 ts+签名并写 jcy_ptime/jcy_sign1/jcy_sign2。
url 参数填 {{jcy_source}}（由「视频播放凭证」节点的后脚本写入），也可手填 source 串。"""

HEADERS_BASE = [
    ("appid", "4150439554430529", "应用ID, 恒定"),
    ("ts", "{{jcy_ts}}", "毫秒时间戳，与 authentication 成对，预脚本注入"),
    ("nonce", "12345678", "8位随机数(服务端不校验)"),
    ("tcs", "2", "恒定为 2"),
    ("x-version", "2020-09-17", "协议版本, 恒定"),
    ("authentication", "{{jcy_auth}}", "客户端本地生成的签名头，预脚本经 /forge 注入"),
    ("content-type", "application/json; charset=utf-8", "POST 必须"),
    ("user-agent", "Dart/3.6 (dart:io)", "Flutter dart:io 栈"),
]


def hp(pairs):
    return {"parameter": [
        {"description": d, "field_type": "string", "is_checked": 1,
         "key": k, "not_null": 1, "value": v, "schema": {"type": "string"}}
        for k, v, d in pairs]}


def task(name, code):
    return {"type": "customScript", "enabled": 1, "name": name, "data": code}


def main():
    only = os.environ.get("ONLY", "")  # play | parser | 空=全部
    rpc("initialize", {"protocolVersion": "2024-11-05",
                       "capabilities": {},
                       "clientInfo": {"name": "jcy-create", "version": "1.0"}})
    rpc("notifications/initialized", {}, notify=True)

    node_play = {
        "project_id": PROJECT, "target_type": "api", "parent_id": FOLDER_VIDEO,
        "name": "视频播放凭证", "tool_version": "1.0.0",
        "method": "POST", "url": "http://43.145.33.254:27990/app/video/play",
        "protocol": "http/1.1", "description": DESC_PLAY,
        "request": {
            "auth": {"type": "inherit"},
            "body": {"mode": "json", "raw": "{{jcy_body}}", "parameter": [],
                     "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}},
            "pre_tasks": [task("取签 + 伪造加密请求体", FORGE_PRE)],
            "post_tasks": [task("响应判定 + 离线解密 + 归档(写 jcy_source)", DECRYPT_POST)],
            "header": hp(HEADERS_BASE),
            "query": hp([
                ("id", "113459", "视频ID(列表/详情返回)"),
                ("play", "mp4", "线路格式，取 detail.parts[].play"),
                ("part", "第1集", "集数，取 detail.parts[].part[k]，中文需 URL 编码"),
            ]),
            "cookie": {"cookie_encode": 1, "parameter": []},
            "restful": {"parameter": []},
        },
        "response": {"is_check_result": 1, "example": [
            {"expect": {"code": "200", "content_type": "json", "is_default": 1,
                        "mock": "", "name": "成功", "schema": {"type": "object"},
                        "verify_type": "schema", "sleep": 0},
             "raw": "", "raw_parameter": [], "headers": []}]},
        "tags": ["播放链"],
    }
    r1 = None
    if only in ("", "play"):
        r1 = rpc("tools/call", {"name": "create_target", "arguments": node_play})
    print("[1] create 视频播放凭证:", json.dumps(r1, ensure_ascii=False)[:300] if r1 else None)

    node_parser = {
        "project_id": PROJECT, "target_type": "api", "parent_id": FOLDER_VIDEO,
        "name": "播放解析器", "tool_version": "1.0.0",
        "method": "GET", "url": "http://yh.jx.xajtl.com/vo1v03.php",
        "protocol": "http/1.1", "description": DESC_PARSER,
        "request": {
            "auth": {"type": "noauth"},
            "body": {"mode": "none", "parameter": [], "raw": "",
                     "raw_parameter": [], "raw_schema": {"type": "object"}, "binary": {}},
            "pre_tasks": [task("现役 Lua 签名（内联 md5）", PARSER_PRE)],
            "post_tasks": [task("解析器响应判定", PARSER_POST)],
            "header": hp([
                ("x-time", "{{jcy_ptime}}", "ts 毫秒，预脚本现算"),
                ("x-form", "Android", "device_info.platform"),
                ("x-sign1", "{{jcy_sign1}}", "md5(app_version+盐+ts)，盐=pzizhsqjjt"),
                ("x-sign2", "{{jcy_sign2}}", "md5(source+盐+ts)"),
                ("user-agent", "Dart/3.6 (dart:io)", "与 App 一致"),
            ]),
            "query": hp([
                ("url", "{{jcy_source}}", "source 串(播放凭证 data[0].url)，或手填"),
                ("t", "{{jcy_ptime}}", "ts 毫秒，与 x-time 相同"),
            ]),
            "cookie": {"cookie_encode": 1, "parameter": []},
            "restful": {"parameter": []},
        },
        "response": {"is_check_result": 1, "example": [
            {"expect": {"code": "200", "content_type": "json", "is_default": 1,
                        "mock": "", "name": "成功", "schema": {"type": "object"},
                        "verify_type": "schema", "sleep": 0},
             "raw": "", "raw_parameter": [], "headers": []}]},
        "tags": ["播放链"],
    }
    r2 = None
    if only in ("", "parser"):
        r2 = rpc("tools/call", {"name": "create_target", "arguments": node_parser})
    print("[2] create 播放解析器:", json.dumps(r2, ensure_ascii=False)[:300] if r2 else None)


if __name__ == "__main__":
    main()
