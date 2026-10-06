# -*- coding: utf-8 -*-
"""pull_apipost.py — 通过 apipost-mcp 递归拉取「囧次元」接口库的完整目录树。

输出::
    research/reports/apipost_tree.json     目录树（含每个节点的 id/name/type/parent）
    research/reports/apipost_tree.md       可读的树形清单

用法::

    ./.venv/Scripts/python.exe research/toolchain/pull_apipost.py
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
OUT_JSON = os.path.join(_P.REPORTS, "apipost_tree.json")
OUT_MD = os.path.join(_P.REPORTS, "apipost_tree.md")


def search(c, **kw):
    """search_target → 节点列表。响应形如 {"code":0,"data":{"list":[{...}]}}"""
    args = {"project_id": PROJECT_ID, "tool_version": TV}
    args.update({k: v for k, v in kw.items() if v is not None})
    txt = c.call_text("search_target", args)
    try:
        d = json.loads(txt)
    except Exception:
        return None, txt
    if d.get("code") != 0:
        return None, d
    data = d.get("data") or {}
    if isinstance(data, dict):
        return data.get("list") or [], None
    if isinstance(data, list):
        return data, None
    return None, d


def main():
    c = McpHttp.from_config("apipost-mcp")
    info = c.initialize()
    print("serverInfo:", info)

    # 根目录（parent_id = "0"）
    root, err = search(c, parent_id="0")
    if root is None:
        print("根目录查询失败:", err)
        return 1

    nodes = []
    queue = [(n, "0") for n in root]
    seen = set()
    while queue:
        node, parent = queue.pop(0)
        nid = str(node.get("target_id") or node.get("id") or "")
        if not nid or nid in seen:
            continue
        seen.add(nid)
        rec = {
            "id": nid,
            "parent_id": str(node.get("parent_id") or parent),
            "name": node.get("name"),
            "type": node.get("target_type") or node.get("type"),
            "url": node.get("url"),
            "method": node.get("method"),
        }
        nodes.append(rec)
        if rec["type"] == "folder":
            kids, e = search(c, parent_id=nid)
            if kids is None:
                print("  !! 展开失败 %s (%s): %s" % (rec["name"], nid, e))
                continue
            queue.extend((k, nid) for k in kids)

    print("共 %d 个节点" % len(nodes))
    json.dump(nodes, open(OUT_JSON, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    # 生成树形 markdown
    by_parent = {}
    for n in nodes:
        by_parent.setdefault(n["parent_id"], []).append(n)

    lines = ["# Apipost「囧次元」接口库目录树", "",
             "- project_id: `%s`" % PROJECT_ID,
             "- 节点总数: %d" % len(nodes), ""]
    order = {"folder": 0, "api": 1, "doc": 2}

    def walk(pid, depth):
        for n in sorted(by_parent.get(pid, []), key=lambda x: (order.get(x["type"], 9), x["name"] or "")):
            if n["type"] == "folder":
                lines.append("%s- **[目录] %s**  `%s`" % ("  " * depth, n["name"], n["id"]))
                walk(n["id"], depth + 1)
            elif n["type"] == "api":
                lines.append("%s- `%s` %s  `%s`" % ("  " * depth, n["method"] or "?", n["name"], n["id"]))
                if n.get("url"):
                    lines.append("%s  - %s" % ("  " * depth, n["url"]))
            else:
                lines.append("%s- _[%s]_ %s  `%s`" % ("  " * depth, n["type"], n["name"], n["id"]))

    walk("0", 0)
    open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("已写出:\n  %s\n  %s" % (OUT_JSON, OUT_MD))
    return 0


if __name__ == "__main__":
    sys.exit(main())
