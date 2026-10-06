# -*- coding: utf-8 -*-
"""v5 抓包代理 (keep-alive 版): 监听 127.0.0.1:27990，转发到真实 API，支持单连接多事务。

修复: 原版每个请求后即关闭连接，导致 Dart HttpClient 复用连接发重定向请求时被 reset -> App 报 300103 网络错误。

配置:
  adb reverse tcp:27990 tcp:27990
  adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d 43.145.33.254 --dport 27990 -j REDIRECT --to-ports 27990'"
"""
import socket, threading, json, time, base64

UPSTREAM = ("43.145.33.254", 27990)
LISTEN = ("127.0.0.1", 27990)
LOG = r"C:\Users\haige\Desktop\instruct\囧次元\research\captures\rsa_scan\proxy_now.jsonl"
BODIES = r"C:\Users\haige\Desktop\instruct\囧次元\research\captures\rsa_scan\bodies_now.jsonl"
lock = threading.Lock()


def log(obj):
    with lock:
        with open(LOG, "a", encoding="utf-8") as f:
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


def parse_clen_te(head):
    clen = 0
    chunked = False
    close = False
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        k = k.strip().lower(); v = v.strip().lower()
        if k == b"content-length":
            try: clen = int(v)
            except Exception: clen = 0
        elif k == b"transfer-encoding" and b"chunked" in v:
            chunked = True
        elif k == b"connection" and b"close" in v:
            close = True
    return clen, chunked, close


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


def headers_dict(head):
    out = {}
    for l in head.split(b"\r\n")[1:]:
        k, _, v = l.partition(b":")
        if k.strip():
            out[k.decode("latin1").strip()] = v.decode("latin1").strip()
    return out


def handle(client):
    client.settimeout(120)
    pending = b""
    try:
        while True:
            head, rest = recv_until(client, b"\r\n\r\n", pending)
            if not head:
                break
            reqline = head.split(b"\r\n")[0].decode("latin1")
            clen, chunked, req_close = parse_clen_te(head)
            req_body = read_body(client, rest, clen, chunked)
            pending = b""

            try:
                up = socket.create_connection(UPSTREAM, timeout=25)
                up.settimeout(60)
            except Exception as e:
                print("[UP-FAIL]", e, flush=True)
                break
            up.sendall(head + b"\r\n\r\n" + req_body)
            rhead, rrest = recv_until(up, b"\r\n\r\n")
            rclen, rchunked, rclose = parse_clen_te(rhead)
            resp_body = read_body(up, rrest, rclen, rchunked)
            try: up.close()
            except Exception: pass

            rstatus = rhead.split(b"\r\n")[0].decode("latin1")
            h = headers_dict(head); rh = headers_dict(rhead)
            rec = {"t": time.strftime("%H:%M:%S"), "req": reqline, "req_headers": h,
                   "req_body_len": len(req_body), "status": rstatus, "resp_headers": rh,
                   "resp_body_len": len(resp_body)}
            log(rec)
            with lock:
                with open(BODIES, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "req": reqline,
                        "req_body_hex": req_body.hex(),
                        "req_body_ascii": req_body.decode("latin1")[:200000],
                        "resp_status": rstatus,
                        "resp_body_hex": resp_body.hex()[:800000],
                        "resp_body_ascii": resp_body.decode("latin1")[:200000],
                        "resp_body_len": len(resp_body),
                    }, ensure_ascii=False) + "\n")
            print("[REQ]", reqline[:60], "| auth=", len(h.get("authentication", "")), "| ts=", h.get("ts"),
                  "| body=", len(req_body), "|", rstatus, "resp=", len(resp_body),
                  "| loc=", rh.get("Location", ""), flush=True)

            client.sendall(rhead + b"\r\n\r\n" + resp_body)
            if req_close or rclose:
                break
    except socket.timeout:
        pass
    except Exception as e:
        print("[ERR]", type(e).__name__, e, flush=True)
    finally:
        try: client.close()
        except Exception: pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(128)
    print("[*] proxy(keep-alive) listening on", LISTEN, "->", UPSTREAM, flush=True)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
