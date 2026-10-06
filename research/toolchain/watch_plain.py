#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""watch_plain.py - 实时抓解密现场: 明文JSON命中即落盘周边内存快照+全量上下文.
配对验证离线完成(derive_check.py)"""
import base64 as b64lib
import binascii
import json
import os
import subprocess
import sys
import time

import frida

PKG = "com.tudou.tool"
CAP = os.path.join(os.path.dirname(__file__), "..", "captures", "rsa_scan")
OUT = os.path.join(CAP, "watch_plain")
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
        for (var k = 0; k < pats.length; k++) out[pats[k]] = scanPat(pats[k]).slice(0, 30);
        return out;
    },
    // 分块读, 直接返回 ArrayBuffer(frida 原生二进制通道)
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
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 150
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
        binascii.hexlify(b'{"code"').decode(),   # 明文 JSON
        binascii.hexlify(b'==.').decode(),        # P0.P1 密文串(解密输入)
    ]
    seen = set()
    log = open(os.path.join(OUT, 'hits.jsonl'), 'w', encoding='utf-8')
    t0 = time.time()
    rnd = 0
    n_snap = 0
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
                lo = int(ad, 16) - 4096
                try:
                    ctx = api.read(hex(lo), 16384)
                    if isinstance(ctx, str):
                        ctx = b64lib.b64decode(ctx)
                except Exception as e2:
                    ctx = b''
                if len(ctx) == 0:
                    continue
                rec = {"pat": pat[:12], "addr": ad, "ctx_b64": b64lib.b64encode(ctx).decode()}
                log.write(json.dumps(rec) + "\n")
                log.flush()
                # 明文命中: 快照周边 256KB 供离线调度扫描(前 12 次)
                if pat == pats[0] and n_snap < 12:
                    try:
                        big = api.read(hex(int(ad, 16) - 131072), 262144)
                        if isinstance(big, str):
                            big = b64lib.b64decode(big)
                        if len(big):
                            with open(os.path.join(OUT, 'snap_%02d.bin' % n_snap), 'wb') as f:
                                f.write(big)
                            n_snap += 1
                    except Exception:
                        pass
        print('轮%d 新命中%d (scan总数%d) snap=%d' % (rnd, newc, len(seen), n_snap), flush=True)
        # 触发: 切tab/滑动/点视频
        if rnd % 3 == 1:
            adb('-s', 'emulator-5554', 'shell', 'input', 'tap', '270', '920')
        elif rnd % 3 == 2:
            adb('-s', 'emulator-5554', 'shell', 'input', 'swipe', '540', '800', '540', '250', '150')
        else:
            adb('-s', 'emulator-5554', 'shell', 'input', 'tap', '450', '920')
        time.sleep(4)
    log.close()
    session.detach()
    print('完成: hits=%d snaps=%d → %s' % (len(seen), n_snap, os.path.abspath(OUT)), flush=True)


if __name__ == '__main__':
    main()
