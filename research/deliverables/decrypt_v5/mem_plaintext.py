# -*- coding: utf-8 -*-
"""从运行中的囧次元进程内存中提取**已解密**的业务 JSON。

原理: app 的 apiDecrypt @0x607518 解密响应后会得到明文 JSON 字符串, 该字符串
      以 Dart String 形式驻留堆内存。本工具用 frida attach 后按标记扫描堆区间,
      读取标记邻域并做花括号配平, 还原完整 JSON 对象。

为什么需要它: 通道 3 的会话密钥由服务端用 app 的 RSA-2048 公钥包裹 (P0), app 侧私钥
      为运行时生成、未内嵌, 且 ARM64 库在 houdini 转译层下不可 hook —— 无法离线解 P0。
      内存提取是已验证可行的替代路径 (实测取回 /app/video/list 的完整 items 列表)。

依赖: frida (pip install frida==17.8.2); 设备需 frida-server 运行 (adb 通道)。
用法:
    python mem_plaintext.py --marker '"items":[{"id":' [--json]
    python mem_plaintext.py --marker '"ename":"' --json
"""
import argparse
import json
import os
import sys
import time

try:
    import frida
except ImportError:
    frida = None

JS = r"""
'use strict';
var MARKER = MARKER_HEX;      // hex of marker bytes
var BACK = BACK_BYTES;        // bytes before marker to read
var FWD  = FWD_BYTES;         // bytes after marker to read
var MAXH = MAX_HITS;

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

// 在 buffer 中从 pos 起向左找最近的 '{', 再向右做花括号配平 (跳过字符串字面量)
function extractJson(u8, pos) {
  var start = -1;
  for (var i = pos; i >= 0; i--) {
    if (u8[i] === 0x7b) { start = i; break; }   // '{'
    if (u8[i] === 0x7d) break;                  // '}' 先遇到说明不在对象内
  }
  if (start < 0) return null;
  var depth = 0, inStr = false, esc = false;
  for (var j = start; j < u8.length; j++) {
    var c = u8[j];
    if (inStr) {
      if (esc) esc = false;
      else if (c === 0x5c) esc = true;          // '\'
      else if (c === 0x22) inStr = false;       // '"'
      continue;
    }
    if (c === 0x22) { inStr = true; continue; }
    if (c === 0x7b) depth++;
    else if (c === 0x7d) { depth--; if (depth === 0) {
      var s = '';
      for (var k = start; k <= j; k++) s += ('0' + u8[k].toString(16)).slice(-2);
      return s;   // 返回 hex, 由 Python 侧做 UTF-8 解码
    } }
  }
  return null;
}

var R = collectRanges();
send({ ev: 'ranges', n: R.length });
var found = {}, hits = 0;
for (var i = 0; i < R.length && hits < MAXH; i++) {
  var r = R[i];
  var f;
  try { f = Memory.scanSync(r.base, r.size, MARKER); } catch (e) { continue; }
  for (var m = 0; m < f.length && hits < MAXH; m++) {
    var addr = f[m].address;
    var lo = addr.sub(BACK), hi = addr.add(FWD);
    if (lo < r.base) lo = r.base;
    var len = hi.sub(lo).toInt32();
    var buf;
    try { buf = lo.readByteArray(len); } catch (e) { continue; }
    var u8 = new Uint8Array(buf);
    var markerOff = addr.sub(lo).toInt32();
    var js = extractJson(u8, markerOff);
    if (!js || js.length < 80) continue;
    if (found[js]) continue;
    found[js] = 1; hits++;
    send({ ev: 'json', addr: addr.toString(), hexlen: js.length, hex: js });
  }
}
send({ ev: 'done', hits: hits });
"""


def get_device():
    mgr = frida.get_device_manager()
    try:
        return mgr.get_device("emulator-5554")
    except Exception:
        pass
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


def extract(marker, back=65536, fwd=131072, max_hits=4, timeout=120):
    if frida is None:
        raise SystemExit("frida 未安装: pip install frida==17.8.2")
    dev = get_device()
    proc = find_pid(dev)
    if not proc:
        raise SystemExit("未找到 app 进程 (com.tudou.tool / 囧次元), 请先启动 app")
    print("[*] attach %s (pid=%d)" % (proc.name, proc.pid), file=sys.stderr)
    session = dev.attach(proc.pid)
    js = (JS.replace("MARKER_HEX", json.dumps(marker.encode("utf-8").hex()))
            .replace("BACK_BYTES", str(back))
            .replace("FWD_BYTES", str(fwd))
            .replace("MAX_HITS", str(max_hits)))
    script = session.create_script(js)
    results = []
    state = {"done": False}

    def on_msg(m, data):
        if m["type"] == "send":
            ev = m["payload"]
            if ev.get("ev") == "json":
                try:
                    text = bytes.fromhex(ev["hex"]).decode("utf-8", "replace")
                except Exception:
                    text = ""
                results.append({"addr": ev["addr"], "len": len(text), "text": text})
                print("[+] 命中 %s (%d bytes)" % (ev["addr"], len(text)), file=sys.stderr)
            elif ev.get("ev") == "done":
                state["done"] = True
            else:
                print("[*] " + json.dumps(ev, ensure_ascii=False), file=sys.stderr)
        elif m["type"] == "error":
            print("[ERR] " + m.get("description", "")[:300], file=sys.stderr)

    script.on("message", on_msg)
    script.load()
    t0 = time.time()
    while not state["done"] and time.time() - t0 < timeout:
        time.sleep(0.5)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--marker", required=True, help="明文标记 (字符串)")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    ap.add_argument("--max-hits", type=int, default=4)
    a = ap.parse_args()
    res = extract(a.marker, max_hits=a.max_hits)
    if not res:
        print("未命中", file=sys.stderr)
        sys.exit(2)
    best = max(res, key=lambda r: r["len"])
    if a.json:
        print(best["text"])
    else:
        print(best["text"][:4000])


if __name__ == "__main__":
    main()
