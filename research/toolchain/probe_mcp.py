# -*- coding: utf-8 -*-
"""probe_mcp.py — 验证 WorkBuddy 用户级 MCP 配置（~/.workbuddy-ai/mcp.json）中的 server 可用性。

对每个 server 发送 MCP `initialize` 握手：
  * http / sse  → POST JSON-RPC
  * stdio       → 启动子进程，写入一行 JSON-RPC 后读取响应

用法::

    ./.venv/Scripts/python.exe research/toolchain/probe_mcp.py
"""
import json
import os
import subprocess
import sys
import threading
import time

CONFIG = os.path.join(os.path.expanduser("~"), ".workbuddy-ai", "mcp.json")

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "jcy-probe", "version": "1.0"},
    },
}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}


def load_config():
    with open(CONFIG, encoding="utf-8") as f:
        return json.load(f)


def probe_http(name, cfg, timeout=20):
    import http.client
    from urllib.parse import urlparse

    url = urlparse(cfg["url"])
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    hdrs.update(cfg.get("headers") or {})
    conn = http.client.HTTPSConnection(url.netloc, timeout=timeout)
    conn.request("POST", url.path, body=json.dumps(INIT), headers=hdrs)
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, body


def _reader(proc, sink):
    try:
        for line in proc.stdout:
            sink.append(line.rstrip("\n"))
    except Exception:
        pass


def probe_stdio(name, cfg, timeout=90):
    cmd = cfg["command"]
    args = cfg.get("args") or []
    env = dict(os.environ)
    env.update(cfg.get("env") or {})
    proc = subprocess.Popen(
        [cmd] + args,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    lines = []
    t = threading.Thread(target=_reader, args=(proc, lines), daemon=True)
    t.start()

    def send(obj):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    send(INIT)
    t0 = time.time()
    while time.time() - t0 < timeout:
        if any('"result"' in x or '"error"' in x for x in lines):
            break
        time.sleep(0.5)
    init_line = next((x for x in lines if '"result"' in x or '"error"' in x), None)

    tool_line = None
    if init_line:
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        send(LIST_TOOLS)
        t1 = time.time()
        while time.time() - t1 < timeout:
            hits = [x for x in lines if '"id":2' in x or '"id": 2' in x]
            if hits:
                tool_line = hits[-1]
                break
            time.sleep(0.5)

    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    return init_line, tool_line, lines[:3]


def summarize(line):
    if not line:
        return "无响应"
    try:
        d = json.loads(line.split("data:", 1)[-1].strip())
    except Exception:
        return line[:120]
    if "error" in d:
        return "ERROR %s" % json.dumps(d["error"], ensure_ascii=False)[:160]
    r = d.get("result", {})
    si = r.get("serverInfo") or {}
    tools = r.get("tools")
    txt = "serverInfo=%s %s" % (si.get("name"), si.get("version"))
    if tools is not None:
        txt += "  tools=%d" % len(tools)
        if tools:
            txt += "  例: %s" % ", ".join(t.get("name", "?") for t in tools[:5])
    return txt


def main():
    print("配置文件: %s" % CONFIG)
    cfg = load_config()
    servers = cfg.get("mcpServers") or {}
    print("server 数: %d -> %s\n" % (len(servers), ", ".join(servers)))
    rc = 0
    for name, c in servers.items():
        typ = c.get("type") or "stdio"
        print("=== %s (%s) ===" % (name, typ))
        if typ in ("http", "sse", "streamable-http", "remote"):
            try:
                st, body = probe_http(name, c)
                print("  HTTP %s" % st)
                print("  %s" % summarize(body))
            except Exception as ex:
                print("  异常: %r" % ex)
                rc = 1
        else:
            try:
                init_line, tool_line, head = probe_stdio(name, c)
                print("  initialize: %s" % summarize(init_line))
                print("  tools/list: %s" % summarize(tool_line))
                if not init_line:
                    print("  原始输出前 3 行: %s" % head)
                    rc = 1
            except Exception as ex:
                print("  异常: %r" % ex)
                rc = 1
        print()
    print("结果: %s" % ("全部通过" if rc == 0 else "存在失败"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
