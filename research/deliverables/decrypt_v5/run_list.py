# -*- coding: utf-8 -*-
"""端到端: 拉取囧次元视频列表 (真实数据)。

路径: app 正常发请求 → 服务端返回 <P0>.<P1> 密文 → app 用运行时 RSA 私钥解 P0 得会话 key
      → 解 P1 得业务 JSON。本脚本从进程内存取回该 JSON (通道 3 的替代解密路径)。

前置: app 已启动并加载首页 (或已下拉刷新); 设备 frida-server 在运行。
用法:
    python run_list.py                 # 打印列表
    python run_list.py --json out.json # 保存完整 JSON
    python run_list.py --channel 1     # 只显示 cid==1
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mem_plaintext import extract  # noqa: E402


def _clean_parse(txt):
    """V6: 大窗口读到的缓冲可能带脏字节 —— 小窗口起截、去控制字符、修非法转义后解析。"""
    import re
    i = txt.find('{"total":')
    if i < 0:
        return None
    seg = re.sub("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", txt[i:])
    seg = re.sub(r'\\(?!["\\/bfnrtu])', r"\\\\", seg)
    try:
        obj, _ = json.JSONDecoder(strict=False).raw_decode(seg)
        return obj
    except Exception:
        return None


def fetch_list(max_hits=3):
    res = extract('"items":[{"id":', back=32768, fwd=524288, max_hits=max_hits)
    if not res:
        res = []
    # 优先: 每个命中先按原始方式解析; 失败则用清洗回退, 取 items 最多的一份
    best = None
    for r in res:
        obj = None
        try:
            obj = json.loads(r["text"])
        except Exception:
            obj = _clean_parse(r["text"])
        if isinstance(obj, dict) and obj.get("items"):
            if best is None or len(obj["items"]) > len(best["items"]):
                best = obj
    if best is None and res:
        best = _clean_parse(max(res, key=lambda r: r["len"])["text"])
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="保存完整 JSON 到此文件")
    ap.add_argument("--channel", type=int, help="只看指定 cid")
    ap.add_argument("--limit", type=int, default=30, help="最多显示条数")
    a = ap.parse_args()

    data = fetch_list()
    if data is None:
        print("未取到列表。请先启动 app 并停留在首页/刷新一次。", file=sys.stderr)
        sys.exit(2)

    items = data.get("items", [])
    if a.channel is not None:
        items = [it for it in items if it.get("cid") == a.channel]

    print("total=%s  items=%d" % (data.get("total"), len(items)))
    print("-" * 72)
    print("%-9s %-5s %-24s %-12s %s" % ("id", "cid", "name", "year", "continu"))
    print("-" * 72)
    for it in items[: a.limit]:
        print("%-9s %-5s %-24s %-12s %s" % (
            it.get("id"), it.get("cid"), (it.get("name") or "")[:22],
            it.get("year"), it.get("continu", "")))

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        print("\n[+] 已保存 %s (%d bytes)" % (a.json, os.path.getsize(a.json)))


if __name__ == "__main__":
    main()
