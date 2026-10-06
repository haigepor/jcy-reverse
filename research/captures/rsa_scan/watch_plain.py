# -*- coding: utf-8 -*-
"""常驻内存明文 watcher (watch_play.py 的 rsa_scan 改造版).

用途: 重放注入实验的取明文端 —— app native api_decrypt 解出的 GResponse JSON
在 Dart 堆仅存活 ~15s, 这里 attach 一次 + 0.6s/轮循环扫描, 命中即落盘.

用法:
  python watch_plain.py [秒数=180] [标记1 标记2 ...] [--keep]
默认标记: '"code":200' (GResponse 形态)。--keep = 同内容重复命中也记录(计数)。
"""
import json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
OUTD = os.path.join(HERE, "watch")
ROOT = r"C:\Users\haige\Desktop\instruct\囧次元"
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables", "decrypt_v5"))
import frida  # noqa: E402
from mem_plaintext import get_device, find_pid  # noqa: E402

DUR = int(sys.argv[1]) if len(sys.argv) and sys.argv[1].isdigit() else 180
KEEP = "--keep" in sys.argv
_argv_markers = [a for a in sys.argv[2:] if not a.startswith("--")]
MARKERS = _argv_markers or ['"code":200']

JS = r"""
'use strict';
function collectRanges() {
  var out = [];
  ['rw-', 'rwx'].forEach(function (p) {
    try {
      Process.enumerateRanges(p).forEach(function (r) {
        var path = (r.file && r.file.path) || '';
        if (/\.(so|apk|dex|jar|oat|art|vdex|ttf|db)$/i.test(path)) return;
        if (r.size < 8192) return;
        out.push(r);
      });
    } catch (e) {}
  });
  return out;
}
var R = collectRanges();
function extractJson(u8, pos) {
  var start = -1;
  for (var i = pos; i >= 0 && i > pos - 8192; i--) {
    if (u8[i] === 0x7b) { start = i; break; }
    if (u8[i] === 0x7d) break;
  }
  if (start < 0) return null;
  var depth = 0, inStr = false, esc = false;
  for (var j = start; j < u8.length; j++) {
    var c = u8[j];
    if (inStr) {
      if (esc) esc = false;
      else if (c === 0x5c) esc = true;
      else if (c === 0x22) inStr = false;
      continue;
    }
    if (c === 0x22) { inStr = true; continue; }
    if (c === 0x7b) depth++;
    else if (c === 0x7d) { depth--; if (depth === 0) {
      var s = '';
      for (var k = start; k <= j; k++) s += ('0' + u8[k].toString(16)).slice(-2);
      return s;
    } }
  }
  return null;
}
rpc.exports = {
  ranges: function () { return R.length; },
  scan: function (markerHex, back, fwd, maxh) {
    var hits = [];
    for (var i = 0; i < R.length && hits.length < maxh; i++) {
      var r = R[i];
      try {
        Memory.scanSync(r.base, r.size, markerHex).forEach(function (f) {
          if (hits.length >= maxh) return;
          var addr = f.address;
          var lo = addr.sub(back); if (lo < r.base) lo = r.base;
          var hi = addr.add(fwd);
          var len = hi.sub(lo).toInt32();
          var buf;
          try { buf = lo.readByteArray(len); } catch (e) { return; }
          var u8 = new Uint8Array(buf);
          var js = extractJson(u8, addr.sub(lo).toInt32());
          if (js && js.length > 80) hits.push({addr: addr.toString(), hex: js});
        });
      } catch (e) {}
    }
    return hits;
  }
};
"""

os.makedirs(OUTD, exist_ok=True)
dev = get_device()
proc = find_pid(dev)
if not proc:
    print("[!] app 未运行")
    sys.exit(2)
print("[*] attach %s pid=%d" % (proc.name, proc.pid), flush=True)
session = dev.attach(proc.pid)
script = session.create_script(JS)
script.load()
nr = script.exports_sync.ranges() if hasattr(script, "exports_sync") else script.exports.ranges()
print("[*] ranges=%d, watching %ds for %s" % (nr, DUR, MARKERS), flush=True)

mhex = [m.encode("utf-8").hex() for m in MARKERS]
t0 = time.time()
seen = {}   # hex -> count
idx = 0
while time.time() - t0 < DUR:
    for mi, m in enumerate(MARKERS):
        try:
            hits = (script.exports_sync.scan(mhex[mi], 4096, 16384, 5)
                    if hasattr(script, "exports_sync") else script.exports.scan(mhex[mi], 4096, 16384, 5))
        except Exception as e:
            print("[ERR scan] %s" % str(e)[:120], flush=True)
            time.sleep(1)
            continue
        for h in hits:
            seen[h["hex"]] = seen.get(h["hex"], 0) + 1
            if not KEEP and seen[h["hex"]] > 1:
                continue
            idx += 1
            text = bytes.fromhex(h["hex"]).decode("utf-8", "replace")
            fn = os.path.join(OUTD, "w%03d_%s.json" % (idx, time.strftime("%H%M%S")))
            with open(fn, "w", encoding="utf-8") as f:
                f.write(text)
            print("[HIT #%d] %s @%s len=%d -> %s" % (idx, m, h["addr"], len(text), fn), flush=True)
    time.sleep(0.6)
print("[done] 时限到; 独立内容=%d" % len(seen), flush=True)
