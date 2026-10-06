# -*- coding: utf-8 -*-
"""pull_apipost_detail.py — 拉取「囧次元」接口库中每个 API 的详情。

依赖 pull_apipost.py 产出的 apipost_tree.json。

输出::
    research/reports/apipost_details.json   每个接口的完整详情
    research/reports/apipost_details.md     可读汇总（鉴权头组 / 参数 / 加密形态）
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import paths as _P  # noqa: E402
from mcp_client import McpHttp  # noqa: E402

PROJECT_ID = os.environ.get("APIPOST_PROJECT", "6ef0f75d8470000")
TV = "1.0.0"
IN_JSON = os.path.join(_P.REPORTS, "apipost_tree.json")
OUT_JSON = os.path.join(_P.REPORTS, "apipost_details.json")
OUT_MD = os.path.join(_P.REPORTS, "apipost_details.md")


def main():
    nodes = json.load(open(IN_JSON, encoding="utf-8"))
    apis = [n for n in nodes if n["type"] == "api"]
    print("待拉取接口: %d" % len(apis))

    c = McpHttp.from_config("apipost-mcp")
    c.initialize()

    details = []
    for i, n in enumerate(apis, 1):
        try:
            txt = c.call_text("get_target_detail", {
                "project_id": PROJECT_ID, "target_id": n["id"], "tool_version": TV})
            d = json.loads(txt)
        except Exception as ex:
            print("  [%2d] %s 失败: %r" % (i, n["name"], ex))
            continue
        details.append({"tree": n, "detail": d})
        code = (d or {}).get("code")
        print("  [%2d/%d] %-22s code=%s" % (i, len(apis), n["name"], code))

    json.dump(details, open(OUT_JSON, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    # ---------------- 生成可读汇总 ----------------
    lines = ["# Apipost「囧次元」接口库详情汇总", "",
             "- project_id: `%s`" % PROJECT_ID,
             "- 接口数: %d" % len(details), ""]
    for item in details:
        t = item["tree"]
        d = item["detail"] or {}
        data = d.get("data") or {}
        lines.append("## %s  `%s`" % (t["name"], t["method"]))
        lines.append("")
        lines.append("- URL: `%s`" % (t.get("url") or data.get("url") or "-"))
        lines.append("- target_id: `%s`" % t["id"])
        if isinstance(data, dict):
            desc = data.get("description")
            if desc:
                lines.append("- 说明: %s" % str(desc).replace("\n", " ")[:300])
            for key in ("request", "response", "header", "query"):
                if key in data:
                    lines.append("- %s: `%s`" % (key, json.dumps(data[key], ensure_ascii=False)[:400]))
            extra = [k for k in data if k not in
                     ("description", "request", "response", "header", "query", "url", "method", "name")]
            if extra:
                lines.append("- 其它字段: %s" % ", ".join(extra))
        lines.append("")

    open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("已写出:\n  %s\n  %s" % (OUT_JSON, OUT_MD))
    return 0


if __name__ == "__main__":
    sys.exit(main())
