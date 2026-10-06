# -*- coding: utf-8 -*-
# verify_server.py — 服务器实测: 正例 / 阴性对照 / 重复性
import os, sys, time, random
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import authgen as AG


def nonce():
    return "%08d" % random.randint(0, 99999999)


def run_case(name, auth, ts, path="/app/config"):
    n = nonce()
    try:
        st, rs, data = AG.probe_server(ts, auth, n, path)
        print("%-28s ts=%d nonce=%s -> %s %s (%d B) head=%r" %
              (name, ts, n, st, rs, len(data), data[:48]))
        return st, data
    except Exception as ex:
        print("%-28s -> 异常 %r" % (name, ex))
        return None, None


def main():
    results = {}
    # --- 正例 1: 当前 ts ---
    ts1 = int(time.time() * 1000)
    a1 = AG.gen(ts1)
    results["pos1"] = run_case("正例#1 有效auth", a1, ts1)

    # --- 阴性对照: 同一 ts, 篡改 auth ---
    bad = list(a1)
    bad[40] = 'A' if bad[40] != 'A' else 'B'
    run_case("阴性#1 篡改auth", "".join(bad), ts1)

    # --- 阴性对照: 空 auth ---
    run_case("阴性#2 空auth", "", ts1)

    # --- 阴性对照: 旧 ts (过期) ---
    ts_old = ts1 - 3600 * 1000
    a_old = AG.gen(ts_old)
    run_case("阴性#3 过期ts(-1h)", a_old, ts_old)

    # --- 正例 2: 新 ts + 另一个端点 (重复性) ---
    ts2 = int(time.time() * 1000)
    a2 = AG.gen(ts2)
    results["pos2"] = run_case("正例#2 /app/banners/0", a2, ts2, "/app/banners/0")

    # --- 正例 3 ---
    ts3 = int(time.time() * 1000)
    a3 = AG.gen(ts3)
    results["pos3"] = run_case("正例#3 /app/channel", a3, ts3, "/app/channel?top-level=true")

    print()
    print("=== 汇总 ===")
    ok = all(results[k][0] == 200 for k in ("pos1", "pos2", "pos3"))
    print("三个正例均返回 200:", ok)
    print("生成一致 (pos1 head):", results["pos1"][1][:20] if results["pos1"][1] else None)


if __name__ == "__main__":
    main()
