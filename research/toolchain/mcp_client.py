# -*- coding: utf-8 -*-
"""mcp_client.py — 极简 MCP (Streamable HTTP) JSON-RPC 客户端。

用于在不重启会话的前提下直调 `~/.workbuddy-ai/mcp.json` 中配置的
http 型 MCP server（当前用于 apipost-mcp）。

用法::

    ./.venv/Scripts/python.exe research/toolchain/mcp_client.py list
    ./.venv/Scripts/python.exe research/toolchain/mcp_client.py call get_project_tree '{"project_id":"..."}'

作为库使用::

    from mcp_client import McpHttp
    c = McpHttp.from_config("apipost-mcp")
    c.initialize()
    print(c.tools())
    print(c.call("get_project_tree", {"project_id": "..."}))
"""
import json
import os
import sys
import http.client
from urllib.parse import urlparse

CONFIG = os.path.join(os.path.expanduser("~"), ".workbuddy-ai", "mcp.json")
PROTOCOL = "2024-11-05"


def _parse_body(text):
    """兼容 application/json 与 text/event-stream 两种响应形态。"""
    text = text.strip()
    if not text:
        return None
    if text.startswith("{") or text.startswith("["):
        return json.loads(text)
    # SSE：逐行找 data:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload:
                try:
                    return json.loads(payload)
                except Exception:
                    continue
    return None


class McpHttp:
    def __init__(self, url, headers=None, timeout=30):
        self.url = url
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.session_id = None
        self._id = 0
        self.server_info = None

    @classmethod
    def from_config(cls, name, path=CONFIG):
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
        entry = (cfg.get("mcpServers") or {}).get(name)
        if not entry:
            raise KeyError("配置中找不到 server: %s" % name)
        return cls(entry["url"], entry.get("headers"), int(entry.get("timeoutMs", 30000)) // 1000 or 30)

    # ---------------------------------------------------------------- 传输
    def _post(self, payload):
        u = urlparse(self.url)
        hdrs = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        hdrs.update(self.headers)
        if self.session_id:
            hdrs["Mcp-Session-Id"] = self.session_id
        conn = http.client.HTTPSConnection(u.netloc, timeout=self.timeout)
        conn.request("POST", u.path or "/", body=json.dumps(payload), headers=hdrs)
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        sid = r.getheader("Mcp-Session-Id")
        status = r.status
        conn.close()
        if sid:
            self.session_id = sid
        return status, body

    def _rpc(self, method, params=None, notify=False):
        self._id += 1
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            msg["id"] = self._id
        status, body = self._post(msg)
        if notify:
            return status, None
        data = _parse_body(body)
        if data is None:
            raise RuntimeError("HTTP %s 但无法解析响应: %r" % (status, body[:300]))
        if "error" in data:
            raise RuntimeError("MCP error: %s" % json.dumps(data["error"], ensure_ascii=False))
        return status, data.get("result")

    # ---------------------------------------------------------------- API
    def initialize(self):
        _, res = self._rpc("initialize", {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "jcy-mcp-client", "version": "1.0"},
        })
        self.server_info = (res or {}).get("serverInfo") or {}
        self._rpc("notifications/initialized", {}, notify=True)
        return self.server_info

    def tools(self):
        _, res = self._rpc("tools/list", {})
        return (res or {}).get("tools") or []

    def call(self, name, arguments=None):
        _, res = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        return res

    def call_text(self, name, arguments=None):
        """把 tools/call 的结果拼成纯文本。"""
        res = self.call(name, arguments) or {}
        out = []
        for item in res.get("content") or []:
            if item.get("type") == "text":
                out.append(item.get("text", ""))
            else:
                out.append(json.dumps(item, ensure_ascii=False))
        return "\n".join(out)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    name = os.environ.get("MCP_SERVER", "apipost-mcp")
    c = McpHttp.from_config(name)
    info = c.initialize()
    print("[%s] serverInfo = %s" % (name, json.dumps(info, ensure_ascii=False)))

    cmd = sys.argv[1]
    if cmd == "list":
        for t in c.tools():
            print("  %-28s %s" % (t.get("name"), (t.get("description") or "").split("\n")[0][:80]))
        return 0
    if cmd == "call":
        tool = sys.argv[2]
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        print(c.call_text(tool, args))
        return 0
    print("未知命令: %s" % cmd)
    return 1


if __name__ == "__main__":
    sys.exit(main())
