# -*- coding: utf-8 -*-
"""Pure-JS needle scan driver: find PEM markers / appid / json needles in Dart heap."""
import frida, time, glob, json

BRIDGE = glob.glob(r"C:\Users\haige\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\site-packages\frida_tools\bridges\java.js")[0]

PROBE = r"""
'use strict';

function scanBuf(u8, needles, baseOff, baseAddr, hits) {
    const n = u8.length;
    for (let k = 0; k < needles.length; k++) {
        const nd = needles[k];
        const nl = nd.length;
        const first = nd[0];
        for (let i = 0; i + nl <= n; i++) {
            if (u8[i] !== first) { continue; }
            let ok = true;
            for (let j = 1; j < nl; j++) { if (u8[i + j] !== nd[j]) { ok = false; break; } }
            if (ok) {
                hits.push({ addr: baseAddr.add(baseOff + i).toString(), kind: 100 + k });
                if (hits.length > 200) return;
            }
        }
    }
}

rpc.exports = {
    pscan: function (needleSpecs) {
        const needles = needleSpecs.map(function (s) {
            const a = [];
            for (let i = 0; i < s.length; i++) a.push(s.charCodeAt(i) & 0xff);
            return a;
        });
        const ranges = Process.enumerateRanges('rw-');
        const hits = [];
        const CH = 262144;
        let total = 0;
        for (const r of ranges) {
            if (r.size > 512 * 1024 * 1024) continue;
            for (let off = 0; off < r.size && hits.length < 200; off += CH) {
                const len = Math.min(CH, r.size - off);
                let buf = null;
                try { buf = r.base.add(off).readByteArray(len); } catch (e) { continue; }
                if (!buf) continue;
                total += len;
                try { scanBuf(new Uint8Array(buf), needles, off, r.base, hits); } catch (e) {}
            }
        }
        return { scanned: total, hits: hits };
    },
    rdump: function (addr, n) {
        try {
            const b = ptr(addr).readByteArray(n);
            return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
        } catch (e) { return null; }
    }
};
console.log('[*] pure-JS needle scanner ready');
"""

def main():
    bridge = open(BRIDGE, encoding='utf-8').read()
    # bridge not needed but harmless; skip it — pure JS works without Java
    full = PROBE
    d = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    session = d.attach('Gadget')
    script = session.create_script(full)
    def on_msg(m, data):
        print('[MSG]', str(m)[:200], flush=True)
    script.on('message', on_msg)
    script.load()
    time.sleep(0.5)
    needles = ["-----BEGIN RSA PRIVATE KEY", "-----BEGIN PRIVATE KEY", "-----BEGIN PUBLIC KEY",
               "-----BEGIN RSA PUBLIC KEY", "-----BEGIN", "4150439554430529", '"ts":17',
               'raw_play_url', 'playAddr', 'm3u8FileDomain', '21901739f1aa6ed1']
    r = script.exports_sync.pscan(needles)
    print('scanned MB:', r['scanned'] // (1024 * 1024), 'hits:', len(r['hits']))
    for h in r['hits'][:80]:
        hx = script.exports_sync.rdump(h['addr'], 2048)
        print(f"KIND {h['kind']} ({needles[h['kind'] - 100][:30]!r}) @ {h['addr']}")
        if hx:
            b = bytes.fromhex(hx)
            print('   text:', b[:120])
    # save full dumps
    for i, h in enumerate(r['hits'][:80]):
        hx = script.exports_sync.rdump(h['addr'], 4096)
        if hx:
            open(f"out/pneedle_{i}_k{h['kind']}.hex", 'w').write(hx)
    print('DONE', flush=True)

if __name__ == '__main__':
    main()
