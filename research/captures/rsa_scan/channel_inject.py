#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""channel_inject.py — 囧次元 (com.tudou.tool) 监控通道抓帧 + 通道注入 D-oracle 骨架

通道: TCP 43.145.33.254:27990 (iptables REDIRECT 到本机), 帧 = 单条标准 b64(AES-128-CBC/PKCS7)
key = qPwClBj7j7ZQraSm, iv = p3JdVQl3q7WQJIgG (双源验证: blutter 对象池 + EVP hook, 见 chan1_monitor.py)

server→app 帧格式 (无磁盘样本, 以下为【推断】, 见 docs/crypto/monitor-channel.md 证据缺口):
  - 无帧头/长度前缀/序列号的证据; FFI 边界 (device_doracle 实证) 是单个 b64 字符串进出
    native call@0x307a38, 故推断网络帧 = 一条完整 b64 串, 帧边界 = b64 字符 run 的边界
    (定界符未知: 可能是 \\n / 无定界直接连发)。本脚本对两种都自适应: 按最大 b64 run 扫描,
    解密成功 (PKCS7 合法 + JSON 含 action/list/16 字符诱饵键) 即判为一帧。
  - 独立密钥: 推断与上行共用 qPwC (通道内无第二密钥的静态证据); 若下行实际用其他 key,
    --listen 抓到的帧会持续 pad-fail, 据此可判。

用法:
  python channel_inject.py --listen                     # 纯抓帧 (透传 + 落盘 channel_frames.jsonl)
  python channel_inject.py --inject-file body.txt       # 先抓帧, 首个上行帧出现后注入 (shape 默认 payload)
  python channel_inject.py --inject-file inj.json --shape list --trailer lf
  python channel_inject.py --selftest                   # 离线自检 (不动网络)

--inject-file 内容两种都认:
  1. 完整明文 JSON 信封 ({"action":"api_decrypt","payload":{...}} 或 {"list":[...]})
  2. 裸 P0.P1 字符串 (无 { 开头) → 按 --shape 自动包信封, --path 默认 /app/video/device-base

环境坑 (research/captures/rsa_scan, 2026-10-03 记录):
  - Windows SO_REUSEADDR 允许双绑 → 旧代理残留会抢走流量且新代理无报错。本脚本 Windows 下
    用 SO_EXCLUSIVEADDRUSE 绑定 (双绑直接报错), 并在启动前跑 netstat 诊断。
  - 配套: adb reverse tcp:27990 tcp:27990
          adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d 43.145.33.254 --dport 27990 -j REDIRECT --to-ports 27990'"
"""
import argparse
import base64
import json
import os
import random
import socket
import string
import subprocess
import sys
import threading
import time

from Crypto.Cipher import AES

MON_KEY = b"qPwClBj7j7ZQraSm"
MON_IV = b"p3JdVQl3q7WQJIgG"
DEFAULT_UPSTREAM = ("43.145.33.254", 27990)
DEFAULT_PATH = "/app/video/device-base"
B64SET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
MIN_RUN = 32          # 最短候选: >=24 字符 (18B 密文); 32 更稳 (2 块)
MAX_BUF = 1 << 22     # 单方向扫描缓冲上限 4MB

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FRAMES = os.path.join(HERE, "channel_frames.jsonl")

_log_lock = threading.Lock()
_frames_path = DEFAULT_FRAMES


def log_record(rec):
    rec["t"] = time.strftime("%Y-%m-%d %H:%M:%S")
    rec["ts"] = round(time.time(), 3)
    with _log_lock:
        with open(_frames_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    tag = rec.get("event") or ("frame:" + rec.get("dir", "?"))
    brief = rec.get("plaintext", "")
    if len(brief) > 90:
        brief = brief[:90] + "..."
    print("[%s] %s %s" % (tag, rec.get("t"), brief), flush=True)


# ---------------------------------------------------------------- 密码层

def _unpad7(b):
    if not b or len(b) % 16:
        return None
    n = b[-1]
    if 1 <= n <= 16 and b[-n:] == bytes([n]) * n:
        return b[:-n]
    return None


def ch_decrypt(b64txt):
    """b64 → AES-CBC(qPwC) 解密 + PKCS7 去填充。失败返回 None。"""
    try:
        raw = base64.b64decode(b64txt + "=" * ((4 - len(b64txt) % 4) % 4))
        if len(raw) == 0 or len(raw) % 16:
            return None
        return _unpad7(AES.new(MON_KEY, AES.MODE_CBC, MON_IV).decrypt(raw))
    except Exception:
        return None


def ch_encrypt(plain):
    if isinstance(plain, str):
        plain = plain.encode("utf-8")
    pad = 16 - len(plain) % 16
    plain += bytes([pad]) * pad
    return base64.b64encode(AES.new(MON_KEY, AES.MODE_CBC, MON_IV).encrypt(plain)).decode()


def looks_like_monitor_frame(pt):
    """明文判帧: JSON 对象且含 action/list 或 16 字符诱饵键。"""
    try:
        obj = json.loads(pt.decode("utf-8"))
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    if "action" in obj or "list" in obj:
        return True
    return any(isinstance(k, str) and len(k) == 16 for k in obj)


def rnd16():
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))


def build_envelope(body, shape, path=DEFAULT_PATH, decoys=0):
    """把裸 P0.P1 字符串包成注入信封。body 为原样字符串 (含点)。"""
    obj = {}
    for _ in range(decoys):
        obj[rnd16()] = rnd16()
    if shape == "payload":
        obj["action"] = "api_decrypt"
        obj["payload"] = {"data": json.dumps(body), "path": path}
    else:  # list
        obj["list"] = [{"action": "api_decrypt",
                        "params": json.dumps({"data": body, "path": path})}]
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def load_inject_plaintext(args):
    """返回 (明文 JSON 字符串, 来源说明)。文件内容是 JSON 信封则原样用, 否则视为裸 P0.P1。"""
    raw = ""
    if args.inject_file:
        raw = open(args.inject_file, encoding="utf-8-sig").read().strip()
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            src = "file-envelope"
        except Exception:
            obj = None
        if obj is not None:
            if args.shape and (("list" not in obj and obj.get("action") != "api_decrypt")):
                print("[!] 文件已是信封 JSON, 忽略 --shape=%s 原样注入" % args.shape, flush=True)
            return json.dumps(obj, separators=(",", ":"), ensure_ascii=False), src
    body = raw or (args.body or "").strip()
    if not body:
        raise SystemExit("注入内容为空: --inject-file 文件既非 JSON 也非裸 P0.P1, 且未给 --body")
    return build_envelope(body, args.shape, args.path, args.decoys), "file-body(auto-wrap,%s)" % args.shape


# ---------------------------------------------------------------- 帧扫描 (粘包/半包)

class FrameScanner:
    """滚动缓冲扫描: 提取最大 b64 run, 解密成功即为一帧。

    处理: 粘包 (多帧连发/无定界)、半包 (b64 跨 recv 到达, 未完 run 留缓冲续扫)。
    已被非 b64 字节终止的 run 若解密失败 → 丢弃 (HTTP 的 P0.P1 体等噪声)。
    缓冲末尾未终止的 run 若 len%4==0 且解密+判帧成功 → 急切收帧 (应对无定界连发)。
    """

    def __init__(self, maxbuf=MAX_BUF):
        self.buf = b""
        self.maxbuf = maxbuf

    def feed(self, data):
        """喂一段原始字节, 返回 [(b64, pre_hex, post_hex, plaintext, terminated)]"""
        self.buf += data
        out = []
        while True:
            n = len(self.buf)
            i = 0
            while i < n and self.buf[i] not in B64SET:
                i += 1
            if i >= n:
                self.buf = b""
                break
            j = i
            while j < n and self.buf[j] in B64SET:
                j += 1
            run = self.buf[i:j]
            terminated = j < n
            pre = self.buf[max(0, i - 8):i].hex()
            recs = []            # [(b64, pt, post_hex)]
            consumed_end = None  # 本轮消费到的 buf 偏移

            # 1) 整 run 成帧
            if len(run) >= MIN_RUN and len(run) % 4 == 0 and run.count(b"=") <= 2:
                pt = ch_decrypt(run.decode("ascii", "ignore"))
                if pt is not None and looks_like_monitor_frame(pt):
                    post = self.buf[j:j + 8].hex() if terminated else ""
                    recs.append((run.decode("ascii", "ignore"),
                                 pt.decode("utf-8", "replace"), post))
                    consumed_end = j

            # 2) 前缀分裂: 无定界连发 → 逐 4 字符尝试切出独立帧
            if not recs and len(run) >= MIN_RUN:
                pos = 0
                L = len(run)
                while pos + MIN_RUN <= L:
                    seg = None
                    for kk in range(pos + MIN_RUN, L + 1, 4):
                        piece = run[pos:kk]
                        if piece.count(b"=") > 2:
                            continue
                        pt = ch_decrypt(piece.decode("ascii", "ignore"))
                        if pt is not None and looks_like_monitor_frame(pt):
                            seg = (kk, piece, pt)
                            break
                    if seg is None:
                        break
                    kk, piece, pt = seg
                    post = self.buf[i + kk:i + kk + 8].hex() if (i + kk) < n else ""
                    recs.append((piece.decode("ascii", "ignore"),
                                 pt.decode("utf-8", "replace"), post))
                    pos = kk
                if recs:
                    consumed_end = i + pos

            for b64txt, pt, post in recs:
                out.append((b64txt, pre, post, pt, terminated))

            if consumed_end is not None:
                self.buf = self.buf[consumed_end:]
                continue
            if terminated:
                self.buf = self.buf[j:]      # 噪声丢弃
                continue
            # 未终止且未收帧: 保留 run 起点等待续传; 超限丢弃
            if n - i > self.maxbuf:
                print("[WARN] 扫描缓冲超限, 丢弃 %dB 疑似噪声" % (n - i), flush=True)
                self.buf = b""
            else:
                self.buf = self.buf[i:]
            break
        return out


# ---------------------------------------------------------------- 代理

class Conn:
    _next_id = [1]
    _lock = threading.Lock()

    def __init__(self, client, addr):
        with Conn._lock:
            self.id = Conn._next_id[0]
            Conn._next_id[0] += 1
        self.client = client
        self.addr = addr
        self.upstream = None
        self.clock = threading.Lock()      # client 发送锁 (透传与注入共用)
        self.alive = threading.Event()
        self.alive.set()

    def close(self):
        if self.alive.is_set():
            self.alive.clear()
            for s in (self.client, self.upstream):
                try:
                    s.close()
                except Exception:
                    pass


class Proxy:
    def __init__(self, listen, upstream):
        self.listen = listen
        self.upstream = upstream
        self.conns = []
        self.conns_lock = threading.Lock()
        self.first_up_conn = None           # 首个看到上行帧的连接 (注入汇合点)
        self.up_event = threading.Event()

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt":
            # 防 SO_REUSEADDR 双绑陷阱: 独占绑定, 双绑时报错而非静默抢不到流量
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(self.listen)
        srv.listen(128)
        print("[*] channel proxy listening on %s:%d -> %s:%d" %
              (self.listen[0], self.listen[1], self.upstream[0], self.upstream[1]), flush=True)
        while True:
            c, a = srv.accept()
            conn = Conn(c, a)
            with self.conns_lock:
                self.conns.append(conn)
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        print("[CONN #%d] %s:%d" % (conn.id, conn.addr[0], conn.addr[1]), flush=True)
        try:
            up = socket.create_connection(self.upstream, timeout=15)
        except Exception as e:
            print("[CONN #%d] 上游连接失败: %s  (检查 iptables/网络, 见 --diagnose)" % (conn.id, e), flush=True)
            conn.close()
            return
        up.settimeout(None)
        conn.upstream = up
        t1 = threading.Thread(target=self.pump, args=(conn, conn.client, conn.upstream, "up"), daemon=True)
        t2 = threading.Thread(target=self.pump, args=(conn, conn.upstream, conn.client, "down"), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        print("[CONN #%d] closed" % conn.id, flush=True)
        conn.close()
        with self.conns_lock:
            if conn in self.conns:
                self.conns.remove(conn)

    def pump(self, conn, src, dst, direction):
        scanner = FrameScanner()
        try:
            while conn.alive.is_set():
                data = src.recv(65536)
                if not data:
                    break
                for b64txt, pre, post, pt, term in scanner.feed(data):
                    self.on_frame(conn, direction, b64txt, pre, post, pt, term)
                if direction == "down":
                    with conn.clock:
                        dst.sendall(data)
                else:
                    dst.sendall(data)
        except (OSError, socket.timeout):
            pass
        finally:
            conn.close()

    def on_frame(self, conn, direction, b64txt, pre, post, pt, terminated):
        rec = {"event": "frame", "conn": conn.id, "dir": direction,
               "b64_len": len(b64txt), "ct_len": len(b64txt) * 3 // 4,
               "b64": b64txt, "plaintext": pt,
               "pre_hex": pre, "post_hex": post, "terminated": terminated}
        if direction == "up":
            if injector_state["armed"] and injector_state["conn"] is None:
                injector_state["conn"] = conn
                self.up_event.set()
            if conn is injector_state.get("conn") and injector_state["left"] > 0:
                injector_state["left"] -= 1
                rec["post_inject"] = 3 - injector_state["left"]
        log_record(rec)


injector_state = {"armed": False, "conn": None, "left": 0}


# ---------------------------------------------------------------- 注入器

def inject_loop(proxy, args, plaintext):
    b64frame = ch_encrypt(plaintext)
    payload = b64frame.encode()
    trailer = {"none": b"", "lf": b"\n", "crlf": b"\r\n"}[args.trailer]
    print("[INJECT] 就绪: shape=%s trailer=%s b64len=%d 明文=%s" %
          (args.shape, args.trailer, len(b64frame), plaintext[:160]), flush=True)

    # 汇合: 等首个上行帧 (app 的 recv 循环正等服务器数据, 窗口最佳), 超时则退回首条连接
    if not proxy.up_event.wait(timeout=args.inject_after):
        print("[INJECT] %ds 内未见上行帧 (心跳未跑/通道未激活), 退回首条连接注入" % args.inject_after, flush=True)
        deadline = time.time() + 20
        while time.time() < deadline:
            with proxy.conns_lock:
                if proxy.conns:
                    break
            time.sleep(0.2)
    if injector_state["conn"] is not None:
        conn = injector_state["conn"]
        src = "首个上行帧所在连接"
    else:
        with proxy.conns_lock:
            conn = proxy.conns[0] if proxy.conns else None
        src = "首条连接(无上行帧参考)"
    if conn is None or not conn.alive.is_set():
        print("[INJECT-FAIL] 无可用连接 (app 未建立到 27990 的链路)。诊断: netstat -ano | grep 27990", flush=True)
        return
    injector_state["left"] = 3
    time.sleep(args.inject_delay)
    for i in range(args.repeat):
        try:
            with conn.clock:
                conn.client.sendall(payload + trailer)
        except Exception as e:
            print("[INJECT-FAIL] 写入 app 方向失败: %s (连接可能已断)" % e, flush=True)
            return
        log_record({"event": "inject", "conn": conn.id, "dir": "down",
                    "shape": args.shape, "trailer": args.trailer, "round": i + 1,
                    "b64": b64frame, "plaintext": plaintext, "via": src,
                    "note": "已写入 app 方向 socket, 等待 app native dispatcher (call@0x307a38) 消费"})
        if i < args.repeat - 1:
            time.sleep(args.interval)
    print("[INJECT] 注入完成, 后续 3 条上行帧将以 post_inject 标记落盘; Ctrl+C 退出", flush=True)


# ---------------------------------------------------------------- 诊断

def netstat_listeners(port):
    try:
        r = subprocess.run(["netstat", "-ano"], capture_output=True, timeout=20)
        out = (r.stdout or b"").decode("utf-8", "replace")
    except Exception as e:
        print("[DIAG] netstat 不可用: %s" % e, flush=True)
        return []
    return [l.strip() for l in out.splitlines()
            if (":%d " % port) in l and "LISTENING" in l.upper()]


def preflight(listen, upstream):
    print("[DIAG] 1) 监听端口占用检查 (Windows SO_REUSEADDR 双绑陷阱):", flush=True)
    rows = netstat_listeners(listen[1])
    if rows:
        for r in rows:
            print("      LISTENING: %s" % r, flush=True)
        print("      !!! 端口 %d 已有监听者。若是旧代理残留请先结束对应 PID (taskkill /F /PID <pid>)," % listen[1], flush=True)
        print("      !!! 否则流量可能被旧进程抢走。本脚本用独占绑定, 双绑会直接报错。", flush=True)
    else:
        print("      无残留监听, OK", flush=True)
    print("[DIAG] 2) 上游连通性探测 %s:%d ..." % upstream, flush=True)
    try:
        s = socket.create_connection(upstream, timeout=8)
        s.close()
        print("      上游可达 OK", flush=True)
    except Exception as e:
        print("      上游不可达: %s" % e, flush=True)
        print("      检查项: 宿主机出网 / iptables 规则是否仍生效 "
              "(adb shell \"su -c 'iptables -t nat -L OUTPUT'\"), adb reverse tcp:%d tcp:%d" %
              (listen[1], listen[1]), flush=True)
        return False
    print("[DIAG] 3) 设备侧检查 (未执行, 需手动): MSYS_NO_PATHCONV=1 C:/leidian/LDPlayer14/adb.exe -s 127.0.0.1:5555 "
          "shell \"su -c 'netstat -tnp | grep 27990'\"  ← app 的监控连接应显示 ESTABLISHED", flush=True)
    return True


# ---------------------------------------------------------------- 自检

def selftest():
    print("[selftest] qPwC 往返 ...", flush=True)
    msg = json.dumps({"list": [{"action": "apk_sign", "params": "false"},
                               {"action": "vpn", "params": "true"}]},
                     separators=(",", ":")).encode()
    assert ch_decrypt(ch_encrypt(msg)) == msg, "round-trip fail"
    print("  [OK] 加解密往返")

    body = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT.5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT"
    for shape in ("payload", "list"):
        env = build_envelope(body, shape, DEFAULT_PATH)
        back = json.loads(ch_decrypt(ch_encrypt(env)))
        if shape == "payload":
            assert back["action"] == "api_decrypt"
            assert json.loads(back["payload"]["data"]).startswith("5iW7"), back
            assert back["payload"]["path"] == DEFAULT_PATH
        else:
            item = back["list"][0]
            assert item["action"] == "api_decrypt"
            p = json.loads(item["params"])
            assert p["path"] == DEFAULT_PATH and p["data"] == body
        print("  [OK] shape=%s 信封构造+往返 (与 device_doracle.build_input 同构)" % shape)

    f1 = ch_encrypt(json.dumps({"action": "get_record", "params": "{\"sta\":1}"})).encode()
    f2 = ch_encrypt(json.dumps({"action": "apk_sign", "params": "false"})).encode()
    d3 = {rnd16(): rnd16() for _ in range(12)}
    d3["action"] = "vpn"
    d3["params"] = "true"
    f3 = ch_encrypt(json.dumps(d3, separators=(",", ":"))).encode()
    stream = (b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n"  # 噪声前缀 (HTTP 头)
              + f1 + b"\n"                              # lf 定界帧
              + f2[:100] + b"#" + f2[100:] + b"\n"      # 半包: 帧内被拆但 # 处定界
              + f3 + f1 + f2)                           # 无定界三连发 (粘包)
    sc = FrameScanner()
    got = []
    pos = 0
    random.seed(7)
    while pos < len(stream):
        k = random.randint(1, 37)  # 随机半包
        got += sc.feed(stream[pos:pos + k])
        pos += k
    got += sc.feed(b"")  # flush no-op
    pts = [g[3] for g in got]
    exp = [ch_decrypt(f1.decode()).decode(), ch_decrypt(f2.decode()).decode(),
           ch_decrypt(f3.decode()).decode(), ch_decrypt(f1.decode()).decode(),
           ch_decrypt(f2.decode()).decode()]
    assert pts == exp, "帧恢复不符:\n got=%r\n exp=%r" % (pts, exp)
    assert all(g[4] or True for g in got)
    print("  [OK] 粘包/半包/无定界连发: 5/5 帧全部恢复 (噪声 HTTP 头被跳过)")

    bad = b"QQQQ" + base64.b64encode(b"x" * 33) + b"\n"  # len%4!=0 / pad-fail 噪声
    assert FrameScanner().feed(bad) == []
    print("  [OK] 噪声不误报")
    print("[selftest] 全部通过 (离线, 未触碰网络)", flush=True)


# ---------------------------------------------------------------- main

def main():
    global _frames_path
    ap = argparse.ArgumentParser(description="囧次元监控通道抓帧+注入 (qPwC, TCP 27990)")
    ap.add_argument("--listen", action="store_true", help="启动抓帧代理 (默认行为)")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=27990)
    ap.add_argument("--upstream", default="43.145.33.254:27990")
    ap.add_argument("--frames", default=DEFAULT_FRAMES, help="帧落盘 jsonl 路径")
    ap.add_argument("--inject-file", help="注入内容文件 (完整信封 JSON 或裸 P0.P1)")
    ap.add_argument("--body", help="直接给裸 P0.P1 (优先级低于 --inject-file 的信封形态)")
    ap.add_argument("--shape", choices=["payload", "list"], default="payload",
                    help="自动包信封形态: payload={action,payload{data,path}} (device_doracle 实证形态); list={list:[{action,params}]} (抓包实证形态)")
    ap.add_argument("--path", default=DEFAULT_PATH)
    ap.add_argument("--decoys", type=int, default=0, help="信封内诱饵键值对数 (默认 0)")
    ap.add_argument("--trailer", choices=["none", "lf", "crlf"], default="none",
                    help="注入帧尾部定界符 (帧边界未知, 默认 none; 可先 --listen 观察 post_hex)")
    ap.add_argument("--inject-after", type=float, default=8.0, help="等首个上行帧的超时秒")
    ap.add_argument("--inject-delay", type=float, default=0.2, help="看到上行帧后延迟秒再注入")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--no-diagnose", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    _frames_path = args.frames
    up_host, _, up_port = args.upstream.rpartition(":")
    upstream = (up_host or up_port, int(up_port))
    listen = (args.listen_host, args.listen_port)

    print("[*] channel_inject: key=%s iv=%s 帧=%s" % (MON_KEY.decode(), MON_IV.decode(), _frames_path), flush=True)
    if not args.no_diagnose:
        preflight(listen, upstream)

    plaintext = None
    if args.inject_file or args.body:
        plaintext, src = load_inject_plaintext(args)
        print("[INJECT] 内容来源: %s" % src, flush=True)
        injector_state["armed"] = True

    proxy = Proxy(listen, upstream)
    threading.Thread(target=proxy.serve, daemon=True).start()
    time.sleep(0.3)
    try:
        if plaintext is not None:
            inject_loop(proxy, args, plaintext)
        else:
            print("[*] 纯抓帧模式: 透传中, server→app 帧落盘 %s; Ctrl+C 退出" % _frames_path, flush=True)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[*] 退出", flush=True)


if __name__ == "__main__":
    main()
