# -*- coding: utf-8 -*-
"""自动重挂内存明文 watcher: app 死→重启→自动 attach 新 pid 继续扫.

批量重放实验的取明文端。命中去重(同内容只记一次), 全部落盘 watch/ 目录。
用法: python watch_forever.py [总秒数=1800] [标记...]
"""
import os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
OUTD = os.path.join(HERE, "watch")
ROOT = r"C:\Users\haige\Desktop\instruct\囧次元"
sys.path.insert(0, os.path.join(ROOT, "research", "deliverables", "decrypt_v5"))
import frida  # noqa: E402
from mem_plaintext import get_device, find_pid  # noqa: E402

DUR = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 1800
MARKERS = [a for a in sys.argv[2:] if not a.startswith("--")] or ['"code":200']

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
seen = set()
idx = 0
t0 = time.time()
attached_pid = None
script = None

print("[*] watch_forever %ds markers=%s" % (DUR, MARKERS), flush=True)
while time.time() - t0 < DUR:
    # --- 保证 attach
    try:
        proc = find_pid(dev)
    except Exception as e:
        print("[ERR dev] %s" % str(e)[:100], flush=True)
        time.sleep(5)
        continue
    if not proc:
        time.sleep(3)
        continue
    if proc.pid != attached_pid:
        try:
            session = dev.attach(proc.pid)
            script = session.create_script(JS)
            script.load()
            attached_pid = proc.pid
            nr = (script.exports_sync.ranges() if hasattr(script, "exports_sync")
                  else script.exports.ranges())
            print("[*] attach pid=%d ranges=%d" % (proc.pid, nr), flush=True)
        except Exception as e:
            print("[ERR attach] %s" % str(e)[:120], flush=True)
            attached_pid = None
            script = None
            time.sleep(5)
            continue

    # --- 扫一轮
    dead = False
    for mi, m in enumerate(MARKERS):
        try:
            hits = (script.exports_sync.scan(m.encode("utf-8").hex(), 4096, 16384, 6)
                    if hasattr(script, "exports_sync") else script.exports.scan(m.encode("utf-8").hex(), 4096, 16384, 6))
        except Exception:
            dead = True
            break
        for h in hits:
            if h["hex"] in seen:
                continue
            seen.add(h["hex"])
            idx += 1
            text = bytes.fromhex(h["hex"]).decode("utf-8", "replace")
            fn = os.path.join(OUTD, "w%03d_%s.json" % (idx, time.strftime("%H%M%S")))
            with open(fn, "w", encoding="utf-8") as f:
                f.write(text)
            print("[HIT #%d] @%s len=%d -> %s" % (idx, h["addr"], len(text), fn), flush=True)
    if dead:
        try:
            session.detach()
        except Exception:
            pass
        attached_pid = None
        script = None
        time.sleep(2)
        continue
    time.sleep(0.6)
print("[done] 独立明文=%d" % len(seen), flush=True)
