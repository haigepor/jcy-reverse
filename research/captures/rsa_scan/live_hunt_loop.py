# -*- coding: utf-8 -*-
"""live_hunt_loop.py — 低延迟内存猎取 (V12)

常驻 frida 会话 + 监听实时抓包文件; 一旦出现新的加密响应,
立刻解出 K16resp / P1 密文, 并马上在 app 内存里扫描 + dump 邻域。
避免"抓包后隔几十秒再扫"导致的缓冲区被回收问题。

用法:
  python live_hunt_loop.py [--endpoint device-base] [--seconds 90] [--passes 3]
"""
import argparse
import base64
import json
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
LIVE = os.path.join(ROOT, "research", "captures", "live", "proxy_bodies.jsonl")
ALPHA = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

JS = r"""
'use strict';
var cache = null;
function ranges(){
  if (cache) return cache;
  var out=[];
  ['rw-','rwx'].forEach(function(p){
    try{ Process.enumerateRanges(p).forEach(function(r){
      var path=(r.file&&r.file.path)||'';
      if(/\.(so|apk|dex|jar|oat|art|vdex|ttf|db|bin)$/i.test(path)) return;
      if(r.size<4096) return;
      out.push(r);
    });}catch(e){}
  });
  cache=out; return out;
}
function h2s(u){ return Array.from(new Uint8Array(u)).map(function(b){return ('0'+b.toString(16)).slice(-2);}).join(''); }
rpc.exports = {
  scan: function(patterns, back, fwd, maxhits){
    var R=ranges(), hits=[], n=0;
    for(var i=0;i<patterns.length && n<maxhits;i++){
      var pat=patterns[i];
      var bk=(pat.back!=null)?pat.back:back, fw=(pat.fwd!=null)?pat.fwd:fwd;
      for(var ri=0;ri<R.length && n<maxhits;ri++){
        var r=R[ri], f;
        try{ f=Memory.scanSync(r.base,r.size,pat.h); }catch(e){ continue; }
        for(var m=0;m<f.length && n<maxhits;m++){
          var addr=f[m].address;
          var lo=addr.sub(bk), hi=addr.add(fw);
          if(lo<r.base) lo=r.base;
          var hex='';
          try{ hex=h2s(lo.readByteArray(hi.sub(lo).toInt32())); }catch(e){}
          hits.push({tag:pat.tag, addr:addr.toString(), lo:lo.toString(),
                     patoff:addr.sub(lo).toInt32(), hex:hex});
          n++;
        }
      }
    }
    return hits;
  },
  invalidate: function(){ cache=null; return true; }
};
"""


def cbd(s):
    s = s.strip().translate(str.maketrans(ALPHA, STD))
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def get_device():
    mgr = frida.get_device_manager()
    for d in mgr.enumerate_devices():
        if d.type == "usb" or "emulator" in d.id or ":" in d.id:
            return d
    return mgr.add_remote_device("127.0.0.1:27042")


def find_pid(dev):
    for p in dev.enumerate_processes():
        if p.name in {"com.tudou.tool", "囧次元"}:
            return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", default="device-base")
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--passes", type=int, default=3)
    ap.add_argument("--back", type=int, default=192)
    ap.add_argument("--fwd", type=int, default=384)
    ap.add_argument("--max", type=int, default=6)
    ap.add_argument("--k16-back", type=int, default=4096)
    ap.add_argument("--k16-fwd", type=int, default=4096)
    ap.add_argument("--p1-back", type=int, default=512)
    ap.add_argument("--p1-fwd", type=int, default=1024)
    a = ap.parse_args()

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    priv = RSA.import_key(open(os.path.join(HERE, "priv_from_go.pem"), "rb").read())

    dev = get_device()

    def attach_now():
        proc = find_pid(dev)
        if not proc:
            return None, None, None
        print("[*] attach %s pid=%d" % (proc.name, proc.pid), flush=True)
        s = dev.attach(proc.pid)
        sc = s.create_script(JS)
        sc.load()
        return s, sc, proc.pid

    session, script, cur_pid = attach_now()
    if not script:
        sys.exit("未找到 app 进程")

    if not os.path.exists(LIVE):
        sys.exit("抓包文件不存在: " + LIVE)
    # 从文件末尾开始跟踪
    with open(LIVE, encoding="utf-8") as f:
        f.seek(0, 2)
        pos = f.tell()
    print("[*] 跟踪 %s (pos=%d), %ds" % (LIVE, pos, a.seconds), flush=True)

    all_hits = []
    t0 = time.time()
    seen = set()
    last_chk = 0.0
    while time.time() - t0 < a.seconds:
        time.sleep(0.15)
        # 主动健康检查: app 重启后立刻重挂, 避免错过重启后的首个请求
        if time.time() - last_chk > 1.0:
            last_chk = time.time()
            try:
                p = find_pid(dev)
                if p and p.pid != cur_pid:
                    print("[*] app 重启 (%d -> %d), 重挂" % (cur_pid, p.pid), flush=True)
                    session, script, cur_pid = attach_now()
            except Exception as e:
                print("[ERR] health:", repr(e), flush=True)
        try:
            sz = os.path.getsize(LIVE)
        except OSError:
            continue
        if sz <= pos:
            continue
        with open(LIVE, encoding="utf-8") as f:
            f.seek(pos)
            lines = f.read().splitlines()
            pos = f.tell()
        for l in lines:
            try:
                r = json.loads(l)
            except Exception:
                continue
            rb = r.get("resp_body_ascii", "")
            qb = r.get("req_body_ascii", "")
            if a.endpoint and a.endpoint not in r.get("req", ""):
                continue
            if rb.count(".") != 1:
                continue
            k16resp = None
            try:
                p0 = cbd(rb.split(".", 1)[0])
                kk = PKCS1_v1_5.new(priv).decrypt(p0[:256], None)
                k16resp = kk.decode("latin1") if kk else None
            except Exception:
                pass
            pats = []
            if k16resp:
                pats.append({"tag": "K16resp:" + k16resp, "h": k16resp.encode().hex(),
                             "back": a.k16_back, "fwd": a.k16_fwd})
            try:
                pats.append({"tag": "RESP_P1:" + r.get("req", "")[-30:],
                             "h": cbd(rb.split(".", 1)[1]).hex(),
                             "back": a.p1_back, "fwd": a.p1_fwd})
            except Exception:
                pass
            if qb.count(".") == 1:
                try:
                    pats.append({"tag": "REQ_P1", "h": cbd(qb.split(".", 1)[1]).hex(),
                                 "back": a.p1_back, "fwd": a.p1_fwd})
                except Exception:
                    pass
            key = (r.get("req", "")[:40], k16resp)
            if key in seen:
                continue
            seen.add(key)
            print("[*] 新响应 %s K16resp=%s -> 立刻扫描" % (r.get("req", "")[:40], k16resp), flush=True)
            for p in range(a.passes):
                if p:
                    time.sleep(0.6)
                try:
                    script.exports_sync.invalidate()
                    hits = script.exports_sync.scan(pats, a.back, a.fwd, a.max)
                except Exception as e:
                    print("[ERR] scan:", repr(e), flush=True)
                    try:
                        session, script, cur_pid = attach_now()
                    except Exception as e2:
                        print("[ERR] reattach:", repr(e2), flush=True)
                    break
                if hits:
                    for h in hits:
                        sig = (h["tag"], h["addr"])
                        if sig in {(x["tag"], x["addr"]) for x in all_hits}:
                            continue
                        all_hits.append(h)
                        print("[+] HIT pass%d %s @ %s" % (p, h["tag"], h["addr"]), flush=True)
                    # 增量落盘: 每次命中立刻写, 便于实时分析
                    try:
                        json.dump(all_hits, open(os.path.join(HERE, "live_hunt_loop_out.json"),
                                                 "w", encoding="utf-8"),
                                  ensure_ascii=False, indent=1)
                    except Exception:
                        pass
                    break
            if not all_hits:
                print("[-] 该响应未命中", flush=True)

    out = os.path.join(HERE, "live_hunt_loop_out.json")
    json.dump(all_hits, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("[*] 共命中 %d -> %s" % (len(all_hits), out), flush=True)
    for h in all_hits:
        print("=" * 70)
        print("TAG %s @ %s (base %s)" % (h["tag"], h["addr"], h["lo"]))
        b = bytes.fromhex(h["hex"]) if h["hex"] else b""
        for off in range(0, len(b), 16):
            chunk = b[off:off + 16]
            print("  +%04x  %-48s  %s" % (off, chunk.hex(" "),
                  "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))


if __name__ == "__main__":
    main()
