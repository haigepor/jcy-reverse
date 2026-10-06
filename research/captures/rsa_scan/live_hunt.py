# -*- coding: utf-8 -*-
"""live_hunt.py — 实时抓包 → 内存猎取 (V12 f(K16) 设备轮)

流程:
  1. 读 research/captures/live/proxy_bodies.jsonl (刚抓的实时流量)
  2. 用 priv_from_go.pem 离线解每条响应的 P0 -> K16resp (16 位 ASCII 令牌)
  3. 把 K16resp / 请求 P1 原始密文 / 响应 P1 原始密文 作为 pattern,
     frida attach 到 app 进程, 扫 rw/rwx 匿名区间, dump 命中点 ±窗口 hex

用法:
  python live_hunt.py [--endpoint device-base] [--back 256] [--fwd 512] [--max 12]
"""
import argparse
import base64
import json
import os
import sys
import time

try:
    import frida
except ImportError:
    frida = None

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ALPHA = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

JS = r"""
'use strict';
var PATS = PATTERNS;      // [{h: hex, tag: str}]
var BACK = BACK_BYTES, FWD = FWD_BYTES, MAXH = MAX_HITS;
function h2s(u){ return Array.from(new Uint8Array(u)).map(function(b){return ('0'+b.toString(16)).slice(-2);}).join(''); }
function collectRanges(){
  var out=[];
  ['rw-','rwx'].forEach(function(p){
    try{ Process.enumerateRanges(p).forEach(function(r){
      var path=(r.file&&r.file.path)||'';
      if(/\.(so|apk|dex|jar|oat|art|vdex|ttf|db|bin)$/i.test(path)) return;
      if(r.size<4096) return;
      out.push(r);
    });}catch(e){}
  });
  return out;
}
var R=collectRanges();
send({ev:'ranges',n:R.length});
var hits=0;
for(var i=0;i<PATS.length && hits<MAXH;i++){
  var pat=PATS[i];
  for(var ri=0;ri<R.length && hits<MAXH;ri++){
    var r=R[ri], f;
    try{ f=Memory.scanSync(r.base,r.size,pat.h); }catch(e){ continue; }
    for(var m=0;m<f.length && hits<MAXH;m++){
      var addr=f[m].address;
      var lo=addr.sub(BACK), hi=addr.add(FWD);
      if(lo<r.base) lo=r.base;
      var len=hi.sub(lo).toInt32();
      var hex='';
      try{ hex=h2s(lo.readByteArray(len)); }catch(e){ hex=''; }
      hits++;
      send({ev:'hit', tag:pat.tag, addr:addr.toString(), lo:lo.toString(), hex:hex});
    }
  }
}
send({ev:'done', hits:hits});
"""


def cbd(s):
    s = s.strip().translate(str.maketrans(ALPHA, STD))
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def load_targets(endpoint, limit):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    priv = RSA.import_key(open(os.path.join(HERE, "priv_from_go.pem"), "rb").read())
    rows = []
    with open(os.path.join(ROOT, "research", "captures", "live", "proxy_bodies.jsonl"),
              encoding="utf-8") as f:
        for l in f:
            try:
                rows.append(json.loads(l))
            except Exception:
                pass
    out = []
    for r in rows:
        if endpoint and endpoint not in r.get("req", ""):
            continue
        rec = {"req": r.get("req", "")}
        rb = r.get("resp_body_ascii", "")
        qb = r.get("req_body_ascii", "")
        if rb.count(".") == 1:
            p0, p1 = cbd(rb.split(".", 1)[0]), cbd(rb.split(".", 1)[1])
            rec["resp_p1"] = p1.hex()
            try:
                k = PKCS1_v1_5.new(priv).decrypt(p0[:256], None)
                if k:
                    rec["k16resp"] = k.decode("latin1")
            except Exception:
                pass
        if qb.count(".") == 1:
            try:
                rec["req_p1"] = cbd(qb.split(".", 1)[1]).hex()
            except Exception:
                pass
        out.append(rec)
    return out[-limit:]


def get_device():
    mgr = frida.get_device_manager()
    for d in mgr.enumerate_devices():
        if d.type == "usb" or "emulator" in d.id or ":" in d.id:
            return d
    return mgr.add_remote_device("127.0.0.1:27042")


def find_pid(dev, pkg="com.tudou.tool"):
    names = {pkg, "囧次元"}
    for p in dev.enumerate_processes():
        if p.name in names:
            return p
    return None


def hunt(patterns, back=256, fwd=512, max_hits=12, timeout=180):
    dev = get_device()
    proc = find_pid(dev)
    if not proc:
        raise SystemExit("未找到 app 进程")
    print("[*] attach %s pid=%d, patterns=%d" % (proc.name, proc.pid, len(patterns)), file=sys.stderr)
    session = dev.attach(proc.pid)
    js = (JS.replace("PATTERNS", json.dumps(patterns))
            .replace("BACK_BYTES", str(back)).replace("FWD_BYTES", str(fwd))
            .replace("MAX_HITS", str(max_hits)))
    script = session.create_script(js)
    res = []
    st = {"done": False}

    def on_msg(m, data):
        if m["type"] == "send":
            ev = m["payload"]
            if ev.get("ev") == "hit":
                res.append(ev)
                print("[+] HIT tag=%s addr=%s" % (ev["tag"], ev["addr"]), file=sys.stderr)
            elif ev.get("ev") == "done":
                st["done"] = True
            else:
                print("[*]", ev, file=sys.stderr)
        elif m["type"] == "error":
            print("[ERR]", m.get("description", "")[:300], file=sys.stderr)

    script.on("message", on_msg)
    script.load()
    t0 = time.time()
    while not st["done"] and time.time() - t0 < timeout:
        time.sleep(0.3)
    return res, proc.pid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", default="device-base")
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--back", type=int, default=256)
    ap.add_argument("--fwd", type=int, default=512)
    ap.add_argument("--max", type=int, default=12)
    a = ap.parse_args()

    tg = load_targets(a.endpoint, a.limit)
    pats = []
    seen = set()
    for r in tg:
        if r.get("k16resp"):
            k = r["k16resp"]
            if k not in seen:
                seen.add(k)
                pats.append({"tag": "K16resp:" + k, "h": k.encode().hex()})
    print("[*] K16resp 目标 %d 个: %s" % (len(pats), [p["tag"][8:] for p in pats]), file=sys.stderr)

    # 先只扫 K16resp (便宜)
    hits, pid = hunt(pats, a.back, a.fwd, a.max)
    if not hits:
        print("[-] K16resp 未命中, 尝试 P1 密文 pattern", file=sys.stderr)
        p2 = []
        for r in tg[-4:]:
            if r.get("resp_p1"):
                p2.append({"tag": "RESP_P1:" + r["req"][-28:], "h": r["resp_p1"]})
            if r.get("req_p1"):
                p2.append({"tag": "REQ_P1:" + r["req"][-28:], "h": r["req_p1"]})
        if p2:
            hits, pid = hunt(p2, a.back, a.fwd, a.max)
    out = os.path.join(HERE, "live_hunt_out.json")
    json.dump({"pid": pid, "hits": hits, "targets": tg}, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("[*] 命中 %d, 结果 -> %s" % (len(hits), out), file=sys.stderr)
    for h in hits:
        print("=" * 70)
        print("TAG %s @ %s (base %s)" % (h["tag"], h["addr"], h["lo"]))
        b = bytes.fromhex(h["hex"]) if h["hex"] else b""
        for off in range(0, len(b), 16):
            chunk = b[off:off + 16]
            print("  +%04x  %-48s  %s" % (off, chunk.hex(" "),
                  "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))


if __name__ == "__main__":
    main()
