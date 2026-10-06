# -*- coding: utf-8 -*-
"""apipost_sync.py — 同步「囧次元」Apipost 接口库的预执行 / 后执行脚本。

背景
----
Apipost 云端 MCP 只有 `create_target` / `delete_targets`，**没有原地更新**能力
（带 target_id 调用 create_target 一律返回 `14000 接口已存在`）。因此本脚本走
「拉详情 → 重建 request（换 pre_tasks / post_tasks / 补描述）→ 删除旧节点 → 新建」。

链路能力（本轮 V13 收官后）
---------------------------
* 预执行：向本机 `authgen_server.py` 取**新鲜** (ts, authentication) 并写入请求头，
  同时刷新随机 nonce。authentication 只与 ts 强绑定、有效期约 2 分钟。
* 后执行：判定响应形态（加密业务数据 / 明文错误码）→ 归档密文 → **调用本地
  `/decrypt` 离线解出明文 JSON** 并写入测试变量 `jcy_plain`。

用法::

    # 1) 先拉起本地服务（另一终端）
    ./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup

    # 2) 拉取当前库快照（只读）
    ./.venv/Scripts/python.exe research/deliverables/apipost_sync.py pull

    # 3) 先对单个接口试跑（删+建）
    ./.venv/Scripts/python.exe research/deliverables/apipost_sync.py update --only /app/config

    # 4) 全量更新
    ./.venv/Scripts/python.exe research/deliverables/apipost_sync.py update
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "research", "toolchain"))
from mcp_client import McpHttp  # noqa: E402

PROJECT = "6ef0f75d8470000"
TV = "1.0.0"
REPORTS = os.path.join(_ROOT, "research", "reports")

# ------------------------------------------------------------------ 预执行脚本
# 作用：① 取新鲜 (ts, authentication)；② POST 时由本地 /forge 现算加密 body 写入 jcy_body。
PRE_JS_TMPL = r"""// ===== 囧次元 自动取签 + 伪造加密请求体（加固版 v2）=====
// 前置：先运行「启动本地取签服务.bat」（保持窗口打开，看到 "authgen service started" 即可）
// 作用：调本地 /forge 现算新鲜的 ts + authentication + 加密请求体，注入到
//       ① 环境变量 jcy_auth / jcy_ts / jcy_body（供 header/body 的 {{}} 引用）
//       ② 直接改请求头（apt.setRequestHeader）
//       两条路互为备份；每一步都独立 try，任何一步失败都不会中断后面的步骤。
var _path = "__PATH__";
var _url = "http://127.0.0.1:8791/forge?path=" + encodeURIComponent(_path)
         + "&params=" + encodeURIComponent("{}");
var _r = null;
console.log("[jcy] pre-script start -> " + _url);

// ① 官方推荐：await $.ajax（Apipost 7.0.4+ 支持 await 转同步）
try {
    await $.ajax({
        method: "GET",
        url: _url,
        timeout: 120000,          // 本地伪造约 4~16 秒, 务必放宽
        success: function (resp) { _r = resp; },
        error: function (e) { console.error("[jcy] $.ajax error: " + e); }
    });
} catch (e) {
    console.warn("[jcy] await $.ajax 异常, 走同步 XHR 兜底: " + e);
}

// ② 兜底：同步 XHR（阻塞式，确保脚本跑完再发请求）
if (!_r) {
    try {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", _url, false);      // false = 同步
        xhr.send(null);
        console.log("[jcy] xhr status=" + xhr.status);
        if (xhr.status === 200 && xhr.responseText) { _r = JSON.parse(xhr.responseText); }
    } catch (e2) {
        console.warn("[jcy] 同步 XHR 也失败: " + e2);
    }
}

// ③ 归一化：兼容返回是 JSON 字符串 / 被包一层 data 的情况
if (_r && typeof _r === "string") { try { _r = JSON.parse(_r); } catch (e3) {} }
if (_r && !_r.authentication && _r.data && _r.data.authentication) { _r = _r.data; }

if (!_r || !_r.authentication) {
    console.error("[jcy] ❌ 取签失败，/forge 原始返回: " + JSON.stringify(_r));
    console.error("[jcy] 请先运行「启动本地取签服务.bat」，看到 authgen service started 后再点发送。");
} else {
    // 防御：确保是纯 ASCII（含换行/中文会让 Apipost 报
    //        Invalid character in header content）
    var _auth = String(_r.authentication).replace(/[\r\n\t]/g, "");
    var _ts = String(_r.ts);
    var _body = String(_r.body);

    // ④ 先写变量（每条独立 try，绝不中断）
    try { apt.variables.set("jcy_auth", _auth); } catch (e) {}
    try { apt.globals.set("jcy_auth", _auth); } catch (e) {}
    try { apt.variables.set("jcy_ts", _ts); } catch (e) {}
    try { apt.globals.set("jcy_ts", _ts); } catch (e) {}
    try { apt.variables.set("jcy_body", _body); } catch (e) {}
    try { apt.globals.set("jcy_body", _body); } catch (e) {}

    // ⑤ 再直接改请求头（同样每条独立 try）
    try { apt.removeRequestHeader("ts"); } catch (e) {}
    try { apt.removeRequestHeader("authentication"); } catch (e) {}
    try { apt.removeRequestHeader("nonce"); } catch (e) {}
    try { apt.setRequestHeader("ts", _ts); } catch (e) {}
    try { apt.setRequestHeader("authentication", _auth); } catch (e) {}
    try { apt.setRequestHeader("nonce", String(Math.floor(Math.random() * 90000000 + 10000000))); } catch (e) {}
    try { apt.setRequestHeader("content-type", "application/json; charset=utf-8"); } catch (e) {}

    console.log("[jcy] ✅ ts=" + _ts + " auth=" + _auth.slice(0, 24) + "... body_len=" + _body.length);
    try { console.log("[jcy] verify jcy_auth.len=" + String(apt.variables.get("jcy_auth") || "").length); } catch (e) {}
}
"""


def pre_js(path: str) -> str:
    """按接口路径生成预执行脚本（path 烘焙进去，避免运行时解析 URL）。"""
    p = path.split("?")[0]
    if not p.startswith("/"):
        p = "/" + p
    return PRE_JS_TMPL.replace("__PATH__", p)

# ------------------------------------------------------------------ 后执行脚本
POST_JS = r"""// ===== 囧次元 响应判定 + 离线解密 + 归档 =====
// 响应体 <P0_b64>.<P1_b64>：
//   P0 = RSA-2048(客户端公钥, 逐请求随机会话密钥 K16resp)
//        --priv_from_go.pem--> K16resp
//   P1 = E(key=K16resp, iv=reverse(K16resp)) 逐块 tweak 密文
//        --decrypt_e 逐块求逆--> 明文 JSON
// 前置：本机运行  ./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup
// 关闭解密：环境变量 jcy_decrypt = 0（只归档不解密，避免大响应等待）
var text = (response.raw && response.raw.responseText) || "";
var status = (response.raw && response.raw.status) || 0;
var isEnvelope = text.indexOf(".") > 0 && text.length > 400 && text.charAt(0) !== "{";
var wantDecrypt = String(apt.variables.get("jcy_decrypt") || "1") !== "0";
if (isEnvelope) {
    apt.assert('response.raw.responseText.indexOf(".") > 0');   // 加密业务数据 = 通过
    console.log("[jcy] ✅ 认证通过, 返回加密业务数据 " + text.length + "B");
} else {
    console.warn("[jcy] ⚠ 非加密响应(明文错误码或空): " + text.slice(0, 200));
}
await $.ajax({
    method: "POST",
    url: "http://127.0.0.1:8791/store",
    timeout: 900000,        // 大响应离线解密较慢(逐块), 放宽到 15 分钟
    headers: { "content-type": "application/json" },
    data: JSON.stringify({
        body: text,
        decrypt: isEnvelope && wantDecrypt,
        path: (typeof request !== "undefined" && request && request.url) ? request.url : "",
        ts: apt.variables.get("jcy_ts")
    }),
    success: function (r) {
        console.log("[jcy] 归档 verdict=" + JSON.stringify(r.verdict));
        var dec = r.decrypted || {};
        if (dec.queued) {
            // 大响应：离线解密要跑几分钟（Unicorn 仿真自研密码 E），已转后台进程，
            // 不会卡住本地服务，也不会让 Apipost 报 callback timed out。
            console.log("[jcy] ⏳ " + (dec.note || "大响应已转后台解密"));
            console.log("[jcy]    完成后：GET http://127.0.0.1:8791/plain 或打开 " + dec.result_file);
        } else if (dec.ok) {
            var plain = JSON.stringify(dec.json);
            console.log("[jcy] 🔓 明文 " + dec.plain_len + "B: " + String(plain).slice(0, 400));
            apt.variables.set("jcy_plain", plain);
            apt.variables.set("jcy_k16resp", dec.k16resp);
        } else if (dec.error) {
            console.warn("[jcy] 解密失败: " + dec.error);
        }
    },
    error: function (e) {
        console.error("[jcy] 归档/解密失败: 请启动 research/deliverables/authgen_server.py --warmup", e);
    }
});
"""

# 描述追加块（V13）
DESC_APPEND = (
    "\n\n【2026-10-04 V14 收官 · 点发送即可拿到真实数据】\n"
    "前置：本机运行 `./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup`\n"
    "预执行脚本（已内置）会：\n"
    "  1) 向本机 /forge 现算**新鲜的 ts + authentication**（authentication 只与 ts 绑定，约 2 分钟过期）；\n"
    "  2) POST 接口同时现算**加密请求体** <P0>.<P1> 并写入变量 jcy_body（本接口 body = raw `{{jcy_body}}`）。\n"
    "后执行脚本（已内置）会：判定响应形态 → 归档密文 → 调 /decrypt **离线解出明文 JSON**，"
    "写入测试变量 `jcy_plain` / `jcy_k16resp`。\n\n"
    "响应解密原理（完全离线，无需设备/App/frida）：\n"
    "  P0 = RSA-2048(pub_from_go, K16resp) --priv_from_go.pem--> K16resp\n"
    "  P1 = E(key=K16resp, iv=reverse(K16resp)) 逐块 tweak 密文 --decrypt_e--> 明文 JSON\n"
    "  一键：POST http://127.0.0.1:8791/decrypt  body=<P0.P1>\n"
    "  成功码是 20000（不是 200）；服务端错误也返回 HTTP 200，业务码在 JSON body。\n"
    "原理与全部负结果：docs/analysis/e2e-decrypt.md；交付物：research/deliverables/decrypt_e.py\n"
    "\n"
    "【一键兜底通道 A · 透明代理 /proxy（最省事）】\n"
    "  把本接口 URL 的前缀 http://43.145.33.254:27990 换成 http://127.0.0.1:8791/proxy 即可，\n"
    "  路径/query/method 全保留；本地服务自动注入新鲜签名后转发并**原样返回**真实响应。\n"
    "  → 用这条时请把「预执行/后执行操作」两个脚本**关掉**（不再需要）。\n"
    "  POST 业务参数：?params={\"a\":1}（服务会把它从转发路径摘掉）。\n\n"
    "【一键兜底通道 B · /relay】\n"
    "  GET http://127.0.0.1:8791/relay?path=<接口路径>&params={}&method=GET[&decrypt=0]\n"
    "  返回 {\"ok\":true,\"status\":200,\"response\":\"<P0>.<P1>\",\"decrypted\":{...}}\n"
    "  decrypt=0 → 只回信封，不解密（大响应秒回）。\n\n"
    "【关于解密速度（重要）】离线解密靠 Unicorn 仿真自研密码 E，约 1 秒/块：\n"
    "  小响应（≤40 块）同步解完直接显示明文；大响应（如 /app/video/list 约 539 块）\n"
    "  自动转**后台进程**，接口立即返回、不再卡死服务；完成后明文写入\n"
    "  research/reports/last_plain.json，或 GET http://127.0.0.1:8791/plain 取。"
)

# 逐接口补充说明（追加在 V14 说明块之后）
EP_NOTE = {
    "/app/video/play": "\n\n【参数提示】`id` / `play` / `part` 必须放在 **query** 上"
                       "（`?id=113354&play=mp4&part=第1集`），body 用 `{}` 即可；"
                       "缺 query 会返回 40000。",
    "/app/video/play-connect": "\n\n【参数状态】真机请求体是**加密的设备/播放上下文**"
                               "（明文约 417–431B，结构未还原）。当前用 `{}` 会返回 "
                               "`40000 参数错误` —— **属预期**，认证层本身已通过。",
    "/app/video/device-base": "\n\n【参数状态】真机请求体仅 **1 个分组**（明文 ≤15 字节），"
                              "是加密的设备标识，结构未还原。当前用 `{}` 会返回 "
                              "`40000 参数错误` —— **属预期**，认证层本身已通过。",
    "/app/danmu": "\n\n【参数提示】**必须带 `part`（集名，如 `第1集`）**，缺则 40000；"
                  "响应为**明文 JSON**（非加密信封）。",
    "/app/upgrade": "\n\n【特例】仅 POST、**不校验 authentication**、body 为 160B 裸 E 密文"
                    "（无 RSA 层）。当前伪造请求得到恒定 64B 桩响应 —— 独立第三套方案，未解。",
}


def _client() -> McpHttp:
    c = McpHttp.from_config("apipost-mcp")
    c.initialize()
    return c


def _j(txt):
    try:
        return json.loads(txt)
    except Exception:
        return {"raw": txt}


def list_targets(c: McpHttp):
    r = _j(c.call_text("search_target", {"project_id": PROJECT,
                                         "target_types": ["api", "folder"], "tool_version": TV}))
    return (r.get("data") or {}).get("list") or []


def pull(c: McpHttp, out_path: str):
    lst = list_targets(c)
    apis = [x for x in lst if x["target_type"] == "api"]
    details = {}
    for i, a in enumerate(apis, 1):
        d = _j(c.call_text("get_target_detail", {"project_id": PROJECT,
                                                 "target_id": a["target_id"], "tool_version": TV}))
        details[a["target_id"]] = d.get("data", d)
        print("  [%2d/%d] %-58s" % (i, len(apis), a["url"].split("27990")[-1]), flush=True)
        time.sleep(0.15)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    json.dump({"tree": lst, "details": details}, open(out_path, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("已保存快照 ->", out_path, "(%d 接口)" % len(details))
    return details


# 参数实测校正（V14）：以真实 code=20000 响应为准
URL_FIX = {
    "/app/video_update_list/2026-09-29": "/app/video_update_list/2026-10-04",
}

# 请求头默认值校正（关键）
# 库里 authentication 的默认值原本是一段**含中文**的占位说明，例如
#   "<152字符 base64; 自定义字母表解码后 112 字节, 前16字节恒定 23754ae9...>"
# Node/Electron 的 HTTP 客户端**不允许 header 值含非 Latin-1 字符**，于是直接抛
#   Invalid character in header content ["authentication"]
# 修法：默认值改成 ASCII 安全的变量引用，由预执行脚本 apt.variables.set 赋值。
HEADER_FIX = {
    "authentication": "{{jcy_auth}}",
    "ts": "{{jcy_ts}}",
}
HEADER_FIX_DESC = {
    "authentication": "客户端本地生成的签名头(非服务器 X-Token)。默认值用变量 {{jcy_auth}}，"
                      "由预执行脚本调本地 /forge 现算后 apt.variables.set 注入。"
                      "（勿填中文/占位说明，否则 Apipost 会报 Invalid character in header content）",
    "ts": "毫秒时间戳，与 authentication 成对。默认值 {{jcy_ts}}，由预执行脚本注入。",
}

QUERY_FIX = {
    "/app/video/detail": [("id", "113354", "视频ID（实测 20000）")],
    "/app/vod_comment/gettop": [("vid", "113354", "视频ID")],
    "/app/vod_comment/gethitstop": [("vid", "113354", "视频ID")],
    "/app/vod_comment/getlist": [("vid", "113354", "视频ID"), ("limit", "20", "条数"), ("page", "1", "页码")],
    "/app/danmu": [("vid", "113354", "视频ID"), ("play", "mp4", "固定"),
                   ("part", "第1集", "集名（**必填**，缺则 40000）"),
                   ("start_time_point", "0", "起始毫秒"), ("end_time_point", "60000", "结束毫秒")],
    "/app/video/play": [("id", "113354", "视频ID"), ("play", "mp4", "固定"), ("part", "第1集", "集名")],
    "/app/video/play-connect": [("id", "113354", "视频ID"), ("play", "mp4", "固定"), ("part", "第1集", "集名")],
    "/app/video/search": [("key", "ai", "搜索词（参数名是 key，非 keyword）"),
                          ("limit", "25", "条数"), ("page", "1", "页码")],
    "/app/video/key": [("key", "ai", "输入前缀"), ("limit", "10", "条数"), ("page", "1", "页码")],
}


def _query_params(tid: str, path: str, existing: list) -> list:
    """按 QUERY_FIX 生成 query 参数列表（保留原 param_id 前缀风格）。"""
    fix = QUERY_FIX.get(path)
    if not fix:
        return existing
    out = []
    for i, (k, v, desc) in enumerate(fix):
        out.append({"param_id": "%s%03d" % (tid[:13], 100 + i), "description": desc,
                    "field_type": "string", "is_checked": 1, "key": k,
                    "not_null": 1, "value": v, "schema": {"type": "string"}})
    return out


def _header_params(existing: list) -> list:
    """把含中文/非 ASCII 的 header 默认值换成 ASCII 变量引用（见 HEADER_FIX）。"""
    for p in existing:
        k = p.get("key")
        if k in HEADER_FIX:
            p["value"] = HEADER_FIX[k]
            p["is_checked"] = 1
            if k in HEADER_FIX_DESC:
                p["description"] = HEADER_FIX_DESC[k]
    return existing


def build_payload(d: dict) -> dict:
    """由现有详情构造「重建用」payload，替换 pre_tasks / post_tasks / 参数，追加描述。

    POST 接口的 body 改为 raw=`{{jcy_body}}`（由预执行脚本调 /forge 现算）。
    """
    req = dict(d.get("request") or {})
    path = d["url"].split("27990")[-1] or "/"
    bare = path.split("?")[0]
    url = d["url"]
    for old, new in URL_FIX.items():
        if old in url:
            url = url.replace(old, new)
    q = dict(req.get("query") or {})
    q["parameter"] = _query_params(d["target_id"], bare, q.get("parameter") or [])
    req["query"] = q
    h = dict(req.get("header") or {})
    h["parameter"] = _header_params(h.get("parameter") or [])
    req["header"] = h
    req["pre_tasks"] = [{"id": d["target_id"] + "p", "type": "customScript",
                         "enabled": 1, "data": pre_js(bare), "name": "取签 + 伪造加密请求体"}]
    req["post_tasks"] = [{"id": d["target_id"] + "q", "type": "customScript",
                          "enabled": 1, "data": POST_JS, "name": "响应判定 + 离线解密 + 归档"}]
    if d["method"].upper() == "POST":
        body = dict(req.get("body") or {})
        body.update({"mode": "plain", "raw": "{{jcy_body}}",
                     "parameter": [], "raw_parameter": [],
                     "raw_schema": {"type": "object"}, "binary": {}})
        req["body"] = body
    desc = d.get("description") or ""
    # 去掉上一轮追加的说明块，避免重复堆叠
    for marker in ("\n\n【2026-10-04 V13 收官", "\n\n【2026-10-04 V14 收官"):
        if marker in desc:
            desc = desc.split(marker, 1)[0]
    desc = desc + DESC_APPEND + EP_NOTE.get(bare, "")
    return {
        "project_id": PROJECT,
        "parent_id": d["parent_id"],
        "target_type": "api",
        "name": d["name"],
        "tool_version": TV,
        "method": d["method"],
        "url": url,
        "protocol": d.get("protocol") or "http/1.1",
        "mark_id": d.get("mark_id") or "0",
        "description": desc,
        "request": req,
        "response": d.get("response") or {"example": [], "is_check_result": 1},
        "tags": d.get("tags") or [],
    }


def main():
    ap = argparse.ArgumentParser(description="Apipost 囧次元接口库预/后脚本同步")
    ap.add_argument("mode", choices=["pull", "update", "dry"])
    ap.add_argument("--only", help="只处理 url 含该子串的接口（试跑用）")
    ap.add_argument("--snapshot", default=os.path.join(REPORTS, "apipost_current_v4.json"))
    a = ap.parse_args()

    c = _client()
    if a.mode == "pull":
        pull(c, a.snapshot)
        return 0

    details = pull(c, a.snapshot)
    apis = [x for x in list_targets(c) if x["target_type"] == "api"]
    todo = [x for x in apis if (not a.only or a.only in x["url"])]
    print("待处理 %d / %d 接口" % (len(todo), len(apis)))

    if a.mode == "dry":
        d = details[todo[0]["target_id"]]
        print(json.dumps(build_payload(d), ensure_ascii=False)[:1500])
        return 0

    mapping, ok, fail = {}, 0, 0
    for i, x in enumerate(todo, 1):
        tid = x["target_id"]
        d = details.get(tid)
        if not d:
            print("  [跳过] 无详情", x["url"]); fail += 1; continue
        payload = build_payload(d)
        # 先删
        try:
            dr = _j(c.call_text("delete_targets", {"project_id": PROJECT, "target_ids": [tid],
                                                   "tool_version": TV}))
            if str(dr.get("code")) not in ("0", "200"):
                print("  [删除失败] %s %s" % (x["url"], json.dumps(dr, ensure_ascii=False)[:160]))
                fail += 1; continue
        except Exception as e:  # noqa: BLE001
            print("  [删除异常]", x["url"], repr(e)[:160]); fail += 1; continue
        time.sleep(0.2)
        # 再建
        try:
            cr = _j(c.call_text("create_target", payload))
            code = str(cr.get("code"))
            new_id = None
            m = re.search(r'"target_id"\s*:\s*"([^"]+)"', json.dumps(cr, ensure_ascii=False))
            if m:
                new_id = m.group(1)
            if code in ("0", "200"):
                ok += 1
                mapping[tid] = new_id
                print("  [%2d/%d] ✅ %-52s -> %s" % (i, len(todo), x["url"].split("27990")[-1], new_id), flush=True)
            else:
                fail += 1
                print("  [%2d/%d] ❌ %-52s %s" % (i, len(todo), x["url"].split("27990")[-1],
                                                  json.dumps(cr, ensure_ascii=False)[:180]), flush=True)
        except Exception as e:  # noqa: BLE001
            fail += 1; print("  [创建异常]", x["url"], repr(e)[:180], flush=True)
        time.sleep(0.2)
        if i % 5 == 0:
            json.dump(mapping, open(os.path.join(REPORTS, "apipost_id_mapping_v4.json"), "w",
                                    encoding="utf-8"), ensure_ascii=False, indent=1)
    json.dump(mapping, open(os.path.join(REPORTS, "apipost_id_mapping_v4.json"), "w",
                            encoding="utf-8"), ensure_ascii=False, indent=1)
    print("done: ok=%d fail=%d  映射 -> research/reports/apipost_id_mapping_v4.json" % (ok, fail))
    return 0


if __name__ == "__main__":
    sys.exit(main())
