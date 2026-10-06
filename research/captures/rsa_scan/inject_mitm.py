# -*- coding: utf-8 -*-
"""重放注入代理: keep-alive 抓包代理 (mitm_proxy_live 版式) + 按请求行匹配注入响应体.

用途: 响应体重放 D-oracle —— 把历史 P0.P1 响应体原样塞回给 app,
app native api_decrypt 会解封 P0 取会话 key 并解 P1, 明文进 Dart 堆
(用 watch_plain.py 抓)。注入事务额外落盘 inject_log.jsonl。

用法:
  python inject_mitm.py                          # 纯透传+落盘
  python inject_mitm.py --inject-req /app/config/video --inject-body body.txt [--inject-once]
前置: adb reverse tcp:27990 tcp:27990
      adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d 43.145.33.254 --dport 27990 -j REDIRECT --to-ports 27990'"
"""
import socket, threading, json, time, os, argparse

UPSTREAM = ("43.145.33.254", 27990)
LISTEN = ("127.0.0.1", 27990)
HERE = os.path.dirname(os.path.abspath(__file__))
OUTD = os.path.join(HERE, "replay")
LOG = os.path.join(OUTD, "proxy_capture.jsonl")
BODIES = os.path.join(OUTD, "proxy_bodies.jsonl")
ILOG = os.path.join(OUTD, "inject_log.jsonl")
lock = threading.Lock()

ARGS = None  # 填充于 main


def log(obj):
    with lock:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def ilog(obj):
    with lock:
        with open(ILOG, "a", encoding="utf-8") as f:
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


def dechunk(body):
    out = b""
    i = 0
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

            # ---- 注入分支: 请求行命中 → 直接回注入体, 不触上游
            skipped = (ARGS and ARGS.inject_skip
                       and any(s in reqline for s in ARGS.inject_skip.split(",")))
            inj_n = None
            body = b""
            do_inject = False
            if (ARGS and ARGS.inject_req and not skipped
                    and ARGS.inject_req in reqline):
                if CORPUS:
                    inj_n, body = next_corpus_body(reqline)
                    do_inject = inj_n is not None
                elif inject_budget_ok():
                    inj_n, body = -1, ARGS.inject_body_bytes
                    do_inject = True
            if do_inject:
                resp = (b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Connection: keep-alive\r\n"
                        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                client.sendall(resp)
                print("[INJECT #%s] %s -> %dB" % (inj_n, reqline[:70], len(body)), flush=True)
                ilog({"t": time.strftime("%H:%M:%S"), "req": reqline, "n": inj_n,
                      "body_len": len(body)})
                log({"t": time.strftime("%H:%M:%S"), "req": reqline,
                     "req_headers": headers_dict(head), "req_body_len": len(req_body),
                     "status": "INJECTED", "resp_body_len": len(body)})
                if req_close:
                    break
                continue

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
            resp_log = dechunk(resp_body) if rchunked else resp_body
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
                        "resp_body_hex": resp_log.hex()[:800000],
                        "resp_body_ascii": resp_log.decode("latin1")[:200000],
                        "resp_body_len": len(resp_log),
                        "resp_chunked": rchunked,
                    }, ensure_ascii=False) + "\n")
            print("[REQ]", reqline[:60], "| ts=", h.get("ts"),
                  "| body=", len(req_body), "|", rstatus, "resp=", len(resp_body), flush=True)

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


Injected = 0
CORPUS = []       # [{"n","path","body"}] --inject-dir 模式(端点匹配)
CORPUS_PTR = 0
CORPUS_DONE = set()


def inject_budget_ok():
    global Injected
    if ARGS.inject_once and Injected >= 1:
        return False
    Injected += 1
    return True


def req_path(reqline):
    parts = reqline.split()
    return parts[1].split("?")[0] if len(parts) >= 2 else ""


def next_corpus_body(reqline):
    """端点匹配轮播: 从指针向后找 endpoints 含当前请求路径的体, 注入并推进。
    返回 (n, bytes) 或 (None, None)=透传。"""
    global CORPUS_PTR
    if not CORPUS:
        return None, None
    path = req_path(reqline)
    if not path:
        return None, None
    L = len(CORPUS)
    for off in range(L):
        e = CORPUS[(CORPUS_PTR + off) % L]
        if e["n"] in CORPUS_DONE:
            continue
        if path in e["endpoints"]:
            CORPUS_PTR = (CORPUS_PTR + off + 1) % L
            CORPUS_DONE.add(e["n"])
            return e["n"], e["body"]
    return None, None


def main():
    global ARGS, CORPUS
    ap = argparse.ArgumentParser()
    ap.add_argument("--inject-req", default=None, help="请求行子串, 命中即注入")
    ap.add_argument("--inject-body", default=None, help="注入的响应体文件 (P0.P1 文本)")
    ap.add_argument("--inject-dir", default=None, help="语料目录 (bNNN.txt 顺序轮播)")
    ap.add_argument("--inject-once", action="store_true", help="只注入一次")
    ap.add_argument("--inject-skip", default="upgrade",
                    help="逗号分隔子串, 命中则透传不注入 (默认 upgrade 防弹窗卡死)")
    ARGS = ap.parse_args()
    if ARGS.inject_dir:
        idx = os.path.join(ARGS.inject_dir, "index.jsonl")
        for line in open(idx, encoding="utf-8"):
            r = json.loads(line)
            with open(os.path.join(ARGS.inject_dir, r["file"]), "r", newline="") as f:
                CORPUS.append({"n": r["n"], "endpoints": set(r["endpoints"]),
                               "body": f.read().strip().encode()})
        print("[*] 语料 %d 体 <- %s" % (len(CORPUS), ARGS.inject_dir), flush=True)
        ARGS.inject_body_bytes = b""
    elif ARGS.inject_body:
        with open(ARGS.inject_body, "rb") as f:
            ARGS.inject_body_bytes = f.read().strip()
        print("[*] 注入体 %dB <- %s" % (len(ARGS.inject_body_bytes), ARGS.inject_body), flush=True)
    else:
        ARGS.inject_body_bytes = b""
    os.makedirs(OUTD, exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(128)
    print("[*] inject-proxy listening on", LISTEN, "->", UPSTREAM, flush=True)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
