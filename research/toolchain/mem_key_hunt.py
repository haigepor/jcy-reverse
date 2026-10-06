# -*- coding: utf-8 -*-
"""mem_key_hunt.py - 阶段A: 扫描 app 内存中的响应密文体 "<P0_b64==.P1_b64>".

P0 恒 256B RSA -> b64 344 字符以 '==' 结尾, 后跟 '.' 分隔符, 特征 '==.' 极强.
输出: research/captures/rsa_scan/mem_bodies.jsonl  {addr, body}
"""
import json
import os
import sys
import time

import frida

PKG = "com.tudou.tool"
OUT = os.path.join(os.path.dirname(__file__), "..", "captures", "rsa_scan", "mem_bodies.jsonl")

JS = r"""
'use strict';
var found = 0;
function isB64Body(start, len) {
    // 读回验证: 可打印且含 '.'
    try {
        var s = Memory.readUtf8String(start, len);
        if (s && s.length === len && /^[A-Za-z0-9+\/]+==\.[A-Za-z0-9+\/]+$/.test(s)) return s;
    } catch (e) {}
    return null;
}

rpc.exports = {
  scan: function() {
    var results = [];
    var ranges = Process.enumerateRanges('rw-');
    for (var i = 0; i < ranges.length; i++) {
      var r = ranges[i];
      if (r.size > 400 * 1024 * 1024) continue;
      try {
        var matches = Memory.scanSync(r.base, r.size, '3d 3d 2e');  // '==.'
        for (var m = 0; m < matches.length; m++) {
          var addr = matches[m].address;
          // ==. 结束位置在 addr+2; P0 b64 长 344 -> 起点约 addr-341
          for (var back = 300; back <= 400; back += 2) {
            var cand = addr.sub(back);
            var body = null;
            try {
              var probe = Memory.readUtf8String(cand, back + 800);
              if (probe && /^[A-Za-z0-9+\/]+==\.[A-Za-z0-9+\/]+$/.test(probe.substring(0, back + 2) .length ? probe : '')) {}
            } catch (e) {}
          }
          // 更稳: 读 addr-400 起 1600 字节, 在 Python 端解析
          try {
            var raw = Memory.readByteArray(addr.sub(450), 2100);
            results.push({addr: addr.sub(450).toString(), b64: btoa(String.fromCharCode.apply(null, new Uint8Array(raw)))});
          } catch (e) {}
        }
      } catch (e) {}
    }
    return results;
  },
  scanAround: function(hexAddr, size) {
    // 读某地址附近内存
    var out = [];
    try {
      var raw = Memory.readByteArray(ptr(hexAddr).sub(size), size * 2);
      out.push({addr: ptr(hexAddr).sub(size).toString(), b64: btoa(String.fromCharCode.apply(null, new Uint8Array(raw)))});
    } catch (e) { out.push({err: '' + e}); }
    return out;
  },
  scanStr: function(hexNeedle) {
    // 在 rw- 区间搜索任意字节串(十六进制), 返回命中地址列表
    var hits = [];
    var ranges = Process.enumerateRanges('rw-');
    for (var i = 0; i < ranges.length; i++) {
      var r = ranges[i];
      if (r.size > 400 * 1024 * 1024) continue;
      try {
        var ms = Memory.scanSync(r.base, r.size, hexNeedle);
        for (var m = 0; m < ms.length; m++) hits.push(ms[m].address.toString());
      } catch (e) {}
    }
    return hits;
  }
};
"""


def main():
    dev = frida.get_device("emulator-5554")
    pid = None
    for a in dev.enumerate_applications():
        if a.identifier == PKG and a.pid:
            pid = a.pid
            break
    if pid is None:
        print("app 未运行"); sys.exit(1)
    session = dev.attach(pid)
    script = session.create_script(JS)
    script.load()
    api = script.exports_sync

    bodies = api.scan()
    print("扫到 %d 处 '==.' 现场候选" % len(bodies))
    seen = set()
    n_ok = 0
    with open(OUT, "w", encoding="utf-8") as f:
        for b in bodies:
            import base64 as b64
            raw = b64.b64decode(b["b64"])
            # 找 '==.' 前的 b64 起止
            txt = raw.decode("latin1")
            i = txt.find("==.")
            if i < 0:
                continue
            # 向前找非 b64 字符
            j = i
            while j > 0 and (txt[j-1].isalnum() or txt[j-1] in "+/"):
                j -= 1
            p0 = txt[j:i+2]
            p1 = txt[i+3:].split("\x00")[0]
            k = 0
            while k < len(p1) and (p1[k].isalnum() or p1[k] in "+/"):
                k += 1
            p1 = p1[:k]
            if len(p0) < 100 or len(p1) < 100:
                continue
            body = p0 + "." + p1
            if body in seen:
                continue
            seen.add(body)
            f.write(json.dumps({"addr": b["addr"], "p0": p0, "p1": p1}, ensure_ascii=False) + "\n")
            n_ok += 1
    print("提取 %d 条完整密文体 -> %s" % (n_ok, os.path.abspath(OUT)))
    session.detach()


if __name__ == "__main__":
    main()
