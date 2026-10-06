#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""watch_action.py - 抓 Dart->libcore FFI 信封原文: {"action"... 命中即落盘 8KB 上下文."""
import base64 as b64lib
import binascii
import json
import os
import subprocess
import sys
import time

import frida

PKG = "com.tudou.tool"
CAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "captures", "rsa_scan")
OUT = os.path.join(CAP, "watch_action")
ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
ENV = dict(os.environ, ANDROID_ADB_SERVER_PORT='5039', MSYS_NO_PATHCONV='1')

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
        for (var k = 0; k < pats.length; k++) out[pats[k]] = scanPat(pats[k]).slice(0, 40);
        return out;
    },
    read: function(hexAddr, size) {
        var base = ptr(hexAddr);
        var CHUNK = 4096;
        var parts = [];
        for (var off = 0; off < size; off += CHUNK) {
            var n = Math.min(CHUNK, size - off);
            var raw = base.add(off).readByteArray(n);
            if (raw === null) { raw = new Uint8Array(n).buffer; }
            parts.push(raw);
        }
        var total = 0;
        for (var j = 0; j < parts.length; j++) total += parts[j].byteLength;
        var outb = new Uint8Array(total);
        var pos = 0;
        for (var j2 = 0; j2 < parts.length; j2++) {
            outb.set(new Uint8Array(parts[j2]), pos);
            pos += parts[j2].byteLength;
        }
        return outb.buffer;
    }
};
"""


def adb(*args):
    return subprocess.run([ADB] + list(args), capture_output=True, timeout=60, env=ENV)


def main():
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    os.makedirs(OUT, exist_ok=True)
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    r = subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'pidof', PKG],
                       capture_output=True, env=ENV)
    pid = int(r.stdout.decode().split()[0])
    session = dev.attach(pid)
    script = session.create_script(JS)
    script.load()
    api = script.exports_sync

    pats = [
        binascii.hexlify(b'{"action"').decode(),
        binascii.hexlify(b'api_decrypt').decode(),
        binascii.hexlify(b'api_encrypt').decode(),
    ]
    seen = set()
    log = open(os.path.join(OUT, 'hits.jsonl'), 'w', encoding='utf-8')
    t0 = time.time()
    rnd = 0
    while time.time() - t0 < total:
        rnd += 1
        try:
            res = api.scan(pats)
        except Exception as e:
            print('scan err', e, flush=True)
            break
        newc = 0
        for pat, addrs in res.items():
            for ad in addrs:
                key = pat + '@' + ad
                if key in seen:
                    continue
                seen.add(key)
                newc += 1
                lo = int(ad, 16) - 2048
                try:
                    ctx = api.read(hex(lo), 8192)
                    if isinstance(ctx, str):
                        ctx = b64lib.b64decode(ctx)
                except Exception:
                    ctx = b''
                if len(ctx) == 0:
                    continue
                rec = {"pat": pat[:16], "addr": ad, "ctx_b64": b64lib.b64encode(ctx).decode()}
                log.write(json.dumps(rec) + "\n")
                log.flush()
        print('轮%d 新命中%d (总%d)' % (rnd, newc, len(seen)), flush=True)
        if rnd % 2 == 1:
            adb('-s', 'emulator-5554', 'shell', 'input', 'swipe', '540', '800', '540', '300', '150')
        time.sleep(4)
    log.close()
    session.detach()
    print('完成: hits=%d → %s' % (len(seen), os.path.abspath(OUT)), flush=True)


if __name__ == '__main__':
    main()
