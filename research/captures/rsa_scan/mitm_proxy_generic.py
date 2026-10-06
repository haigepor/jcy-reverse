# -*- coding: utf-8 -*-
"""mitm_proxy_generic.py — 通用 HTTP 抓包代理 (按 Host 头转发)。

用途: 囧次元播放链路的解析接口 (yh.jx.xajtl.com 等) 不是 43.145.33.254,
      需要按 Host 动态选上游, 才能把 Lua 解析请求也抓下来。

配置 (示例):
  adb reverse tcp:27991 tcp:27991
  adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d <解析接口IP> --dport 80 -j REDIRECT --to-ports 27991'"

日志: research/captures/live/generic_capture.jsonl / generic_bodies.jsonl
"""
import json
import os
import socket
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
LIVE = os.path.join(ROOT, "research", "captures", "live")
LOG = os.path.join(LIVE, "generic_capture.jsonl")
BODIES = os.path.join(LIVE, "generic_bodies.jsonl")
LISTEN = ("127.0.0.1", 27991)
lock = threading.Lock()


def log(obj, path):
    with lock:
        os.makedirs(LIVE, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def recv_until(sock, sep, initial=b"", maxbytes=1 << 22):
    buf = initial
    while sep not in buf:
        c = sock.recv(65536)
        if not c:
            return buf, b""
        buf += c
        if len(buf) > maxbytes:
            break
    head, _, rest = buf.partition(sep)
    return head, rest


def headers_dict(head):
    out = {}
    for l in head.split(b"\r\n")[1:]:
        k, _, v = l.partition(b":")
        if k.strip():
            out[k.decode("latin1").strip()] = v.decode("latin1").strip()
    return out


def clen_te(head):
    clen, chunked, close = 0, False, False
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        k, v = k.strip().lower(), v.strip().lower()
        if k == b"content-length":
            try:
                clen = int(v)
            except Exception:
                clen = 0
        elif k == b"transfer-encoding" and b"chunked" in v:
            chunked = True
        elif k == b"connection" and b"close" in v:
            close = True
    return clen, chunked, close


def dechunk(body):
    out, i = b"", 0
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(body[i:j].split(b";")[0].strip(), 16)
        except Exception:
            break
        if n == 0:
            break
        out += body[j + 2:j + 2 + n]
        i = j + 2 + n + 2
    return out if out else body


def read_body(sock, rest, clen, chunked):
    body = rest
    if chunked:
        while not body.endswith(b"0\r\n\r\n"):
            c = sock.recv(65536)
            if not c:
                break
            body += c
        return body
    while len(body) < clen:
        c = sock.recv(65536)
        if not c:
            break
        body += c
    return body


def handle(client):
    client.settimeout(60)
    pending = b""
    try:
        while True:
            head, rest = recv_until(client, b"\r\n\r\n", pending)
            if not head:
                break
            reqline = head.split(b"\r\n")[0].decode("latin1")
            clen, chunked, req_close = clen_te(head)
            req_body = read_body(client, rest, clen, chunked)
            pending = b""
            h = headers_dict(head)
            host = h.get("Host", "")
            if ":" in host:
                up_host, up_port = host.rsplit(":", 1)
                up_port = int(up_port)
            else:
                up_host, up_port = host, 80
            if not up_host:
                break
            try:
                up = socket.create_connection((up_host, up_port), timeout=25)
                up.settimeout(60)
            except Exception as e:
                print("[UP-FAIL]", host, e, flush=True)
                try:
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                except Exception:
                    pass
                break
            up.sendall(head + b"\r\n\r\n" + req_body)
            rhead, rrest = recv_until(up, b"\r\n\r\n")
            rclen, rchunked, rclose = clen_te(rhead)
            resp_body = read_body(up, rrest, rclen, rchunked)
            try:
                up.close()
            except Exception:
                pass
            rstatus = rhead.split(b"\r\n")[0].decode("latin1")
            rlog = dechunk(resp_body) if rchunked else resp_body
            log({"t": time.strftime("%H:%M:%S"), "req": reqline, "host": host,
                 "req_headers": h, "req_body_len": len(req_body),
                 "status": rstatus, "resp_body_len": len(rlog)}, LOG)
            log({"req": reqline, "host": host,
                 "req_body_ascii": req_body.decode("latin1")[:200000],
                 "resp_body_ascii": rlog.decode("latin1")[:400000]}, BODIES)
            print("[REQ]", host, reqline[:70], "|", rstatus, "resp=", len(rlog), flush=True)
            client.sendall(rhead + b"\r\n\r\n" + resp_body)
            if req_close or rclose:
                break
    except socket.timeout:
        pass
    except Exception as e:
        print("[ERR]", type(e).__name__, e, flush=True)
    finally:
        try:
            client.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(128)
    print("[*] generic proxy listening on", LISTEN, "(按 Host 转发)", flush=True)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
