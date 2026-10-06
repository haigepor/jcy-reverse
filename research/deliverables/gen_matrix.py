# -*- coding: utf-8 -*-
"""gen_matrix.py — 由 tmp_all_endpoints.json 生成 35 接口端到端实测矩阵文档。"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(ROOT, "research", "tmp_all_endpoints.json")
DST = os.path.join(ROOT, "docs", "api", "live-matrix.md")

# 端点中文名 + 备注（人工）
META = {
    "/app/config": ("全局配置", "弹窗/开关/风控等全局配置"),
    "/app/channel?top-level=true": ("频道列表", "首页频道聚合"),
    "/app/channel/": ("频道列表(301)", "301 跳转源, 无加密体"),
    "/app/config/channel": ("频道配置", "POST 上报/拉取"),
    "/app/config/video": ("视频页配置", "播放器配置"),
    "/app/banners/0": ("Banner(首页)", "频道 0"),
    "/app/banners/1": ("Banner(日漫)", "频道 1"),
    "/app/banners/2": ("Banner(国漫)", "频道 2"),
    "/app/video/list?channel=1&sort=weight&limit=6&page=1": ("视频列表", "核心列表接口"),
    "/app/video/detail?id=113354": ("视频详情", "单部番剧详情"),
    "/app/video/search?key=ai&limit=25&page=1": ("搜索", "参数名 key(非 keyword)"),
    "/app/video/key?key=ai&limit=10&page=1": ("搜索联想", "搜索框联想词"),
    "/app/video_update_list/2026-10-04": ("更新排期表", "按日期"),
    "/app/video/record": ("播放记录上报", "POST"),
    "/app/video/play-connect": ("播放连接", "POST；需真机加密上下文 → 40000"),
    "/app/video/play?id=113354&play=mp4&part=%E7%AC%AC1%E9%9B%86":
        ("播放凭证", "**参数在 query**（?id=&play=&part=），body 用 `{}`；返回播放直链"),
    "/app/video/play": ("播放凭证", "**参数在 query**（?id=&play=&part=），body 用 `{}`"),
    "/app/video/device-base": ("设备信息上报", "POST；真机 body 仅 1 块(明文≤15B)，结构未还原 → 40000"),
    "/app/danmu?vid=113354&play=mp4&part=%E7%AC%AC1%E9%9B%86&start_time_point=0&end_time_point=60000":
        ("弹幕拉取", "**必带 part（集名）**；响应为明文 JSON"),
    "/app/vod_comment/gettop?vid=113354": ("热评置顶", ""),
    "/app/vod_comment/gethitstop?vid=113354": ("热评命中", ""),
    "/app/vod_comment/getlist?vid=113354&page=1": ("评论列表", ""),
    "/app/users/clearimg": ("清图上报", "POST"),
    "/app/users/task": ("用户任务", "POST"),
    "/app/history": ("观看历史", "POST"),
    "/app/history/localcahce": ("本地缓存上报", "官方拼写 localcahce"),
    "/app/task/sign_rule": ("签到规则", ""),
    "/app/messagebox/give_me": ("收件箱", "POST"),
    "/app/messagebox/dynamic": ("动态消息", "POST"),
    "/app/upgrade": ("升级检查", "特例: 大写 Authentication + 216B 裸二进制"),
    "/app/v2/config/host": ("Host 配置(v2)", "路径已失效"),
    "/app/users/info": ("用户信息", "游客态"),
    "/app/vip_price/list": ("VIP 价格", ""),
    "/app/task/task": ("任务列表", "POST"),
    "/app/playaddr/v4/client?vid=113354": ("播放地址 v4", "路径已失效"),
    "/app/login/smscode": ("短信验证码", "路径已失效"),
}


def main():
    data = json.load(open(SRC, encoding="utf-8"))
    lines = []
    lines.append("# 囧次元 API 端到端实测矩阵（35 接口）\n")
    lines.append("> 生成时间：2026-10-04 · 驱动 `research/tmp_all_endpoints_par.py`（6 worker 并行）\n")
    lines.append("> 数据源：`research/tmp_all_endpoints.json`（真实请求 + 离线解密，无需设备/App/frida）\n")
    lines.append("\n判定：响应体解出 `{\"code\":20000,...}` + 真实 data = ✅ 通过；"
                 "明文错误码 / 404 = 业务或路径问题。\n")
    lines.append("\n| # | 方法 | 路径 | 名称 | HTTP | 结果 | 明文 | code | 备注 |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    ok = raw = err = biz = 0
    for i, (path, r) in enumerate(data.items(), 1):
        name, note = META.get(path, ("", ""))
        method = r.get("method", "?")
        http = r.get("http", "-")
        if r.get("error"):
            res, plen, code = "❌ 异常", "-", "-"
            note = (note + " " + r["error"][:60]).strip()
            err += 1
        elif r.get("plain") is not None:
            code = (r.get("json") or {}).get("code") if isinstance(r.get("json"), dict) else None
            res = "✅ 通过" if code == 20000 else "⚠ 业务码"
            plen = "%dB" % r.get("plain_len", 0)
            if code == 20000:
                ok += 1
            else:
                biz += 1
        else:
            rawv = r.get("raw", "")
            # 明文 JSON 响应（如 /app/danmu 带 part 后返回明文）也按业务码判定
            j = None
            if rawv.lstrip().startswith("{"):
                try:
                    j = json.loads(rawv)
                except Exception:
                    j = None
            if isinstance(j, dict) and "code" in j:
                code = j.get("code")
                res = "✅ 通过" if code == 20000 else "⚠ 业务码"
                plen = "%dB" % len(rawv)
                if code == 20000:
                    ok += 1
                else:
                    biz += 1
                note = (note + " " + str(j.get("message", ""))).strip()
            else:
                res, plen, code = "➖ 非加密", "-", "-"
                note = (note + " " + repr(rawv[:50])).strip()
                raw += 1
        lines.append("| %d | %s | `%s` | %s | %s | %s | %s | %s | %s |"
                     % (i, method, path, name, http, res, plen, code, note))
    lines.append("\n## 汇总\n")
    lines.append("| 项 | 值 |")
    lines.append("|---|---|")
    lines.append("| 接口总数 | %d |" % len(data))
    lines.append("| 解出真实数据(20000) | %d |" % ok)
    lines.append("| 加密但业务码非 20000 | %d |" % biz)
    lines.append("| 非加密响应(301/特例/404) | %d |" % raw)
    lines.append("| 异常 | %d |" % err)
    lines.append("\n> 服务端错误也返回 HTTP 200，业务码在 JSON body。"
                 "`/app/upgrade` 为特例（非 P0.P1）；`/app/channel/` 为 301 跳转。\n")
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    open(DST, "w", encoding="utf-8").write("\n".join(lines))
    print("已生成 ->", DST, " ok=%d raw=%d err=%d / %d" % (ok, raw, err, len(data)))


if __name__ == "__main__":
    sys.exit(main())
