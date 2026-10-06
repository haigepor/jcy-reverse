# -*- coding: utf-8 -*-
"""mem_watch.py - 常驻 frida 扫描: 边操作 app 边抓内存中的密文体/明文/会话密钥.

用法: python mem_watch.py [秒数]
输出: research/captures/rsa_scan/mem_watch_hits.jsonl
"""
import base64 as b64lib
import binascii
import json
import os
import subprocess
import sys
import time

import frida

PKG = "com.tudou.tool"
OUT = os.path.join(os.path.dirname(__file__), "..", "captures", "rsa_scan", "mem_watch_hits.jsonl")
ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"

JS = r"""
'use strict';
function scanPat(pat) {
    var hits = [];
    var ranges = Process.enumerateRanges('rw-');
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        if (r.size > 400 * 1024 * 1024) continue;
        try {
            var ms = Memory.scanSync(r.base, r.size, pat);
            for (var m = 0; m < ms.length; m++) hits.push(ms[m].address.toString());
        } catch (e) {}
    }
    return hits;
}
rpc.exports = {
    scan: function(pats) {
        var out = {};
        for (var k = 0; k < pats.length; k++) {
            out[pats[k]] = scanPat(pats[k]).slice(0, 40);
        }
        return out;
    },
    read: function(hexAddr, size) {
        try {
            var raw = Memory.readByteArray(ptr(hexAddr), size);
            return btoa(String.fromCharCode.apply(null, new Uint8Array(raw)));
        } catch (e) { return ''; }
    }
};
"""


def adb(*args):
    subprocess.run([ADB] + list(args), capture_output=True, timeout=30,
                   env=dict(os.environ, MSYS_NO_PATHCONV="1"))


def main():
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 90
    dev = frida.get_device("emulator-5554")
    pid = None
    for a in dev.enumerate_applications():
        if a.identifier == PKG and a.pid:
            pid = a.pid
    if pid is None:
        print("app 未运行")
        sys.exit(1)
    session = dev.attach(pid)
    script = session.create_script(JS)
    script.load()
    api = script.exports_sync

    # P0-P1 分隔 '==.'(1B 串) / UTF16 形式; 明文 JSON 标记; 私钥 PEM 头
    pats = [
        binascii.hexlify(b"==.").decode(),
        binascii.hexlify(b"=\x00=\x00.\x00").decode(),
        binascii.hexlify(b'"status":true').decode(),
        binascii.hexlify(b'"code":200').decode(),
        binascii.hexlify(b"BEGIN RSA PRIVATE KEY").decode(),
    ]
    seen = set()
    fh = open(OUT, "w", encoding="utf-8")
    t0 = time.time()
    rnd = 0
    while time.time() - t0 < total:
        rnd += 1
        res = api.scan(pats)
        counts = {p[:12]: len(v) for p, v in res.items()}
        print("轮%d %s" % (rnd, counts), flush=True)
        for pat, addrs in res.items():
            for ad in addrs:
                key = pat + "@" + ad
                if key in seen:
                    continue
                seen.add(key)
                lo = int(ad, 16) - 1200
                raw = b64lib.b64decode(api.read(hex(lo), 3600))
                fh.write(json.dumps({"pat": pat, "addr": ad,
                                     "ctx_b64": b64lib.b64encode(raw).decode()}) + "\n")
                fh.flush()
                if pat == pats[0]:
                    print("  '==.' @", ad, flush=True)
        # 操作 app: 跳过广告/滑动刷新
        if rnd % 3 == 1:
            adb("shell", "input", "tap", "950", "180")     # 跳过按钮常见位
        elif rnd % 3 == 2:
            adb("shell", "input", "swipe", "540", "800", "540", "250", "150")
        else:
            adb("shell", "input", "tap", "540", "1500")    # 中央/分类
        time.sleep(4)
    fh.close()
    session.detach()
    print("完成, 命中写入", os.path.abspath(OUT))


if __name__ == "__main__":
    main()
