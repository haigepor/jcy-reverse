#!/usr/bin/env python3
"""dev_trace_dec.py - 真机 api_decrypt + Stalker 块轨迹 (与 emu tmp_decscan_blocks.txt 差分用).
用法: python dev_trace_dec.py replay
输出: research/tmp_dev_blocks.json {blocks:{off_hex:count}, result:...}
"""
import base64
import json
import sys

import frida
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

CH_KEY = b"qPwClBj7j7ZQraSm"
CH_IV = b"p3JdVQl3q7WQJIgG"
PATH = '/app/video/device-base'

JS = r"""
var coreBase = null;
function findCore() {
    if (coreBase) return coreBase;
    var f = new File('/proc/self/maps', 'r');
    var line; var first = null;
    while ((line = f.readLine()) !== null && line !== '' && line !== undefined) {
        if (line.indexOf('files/libcore.so') >= 0) {
            var b = parseInt(line.split('-')[0], 16);
            if (first === null || b < first) first = b;
        }
    }
    f.close();
    if (first !== null) coreBase = ptr(first);
    return coreBase;
}

var blocks = {};
var tracing = false;

rpc.exports.call = function (b64input) {
    var base = findCore();
    if (!base) return JSON.stringify({err: 'core not found'});
    var entry = new NativeFunction(base.add(0x307a38), 'pointer', ['pointer', 'pointer']);
    var resultStr = null;
    var cb = new NativeCallback(function (p) {
        try { resultStr = Memory.readUtf8String(p, 65536); } catch (e) { resultStr = 'ERR ' + e; }
    }, 'void', ['pointer']);
    var inp = Memory.allocUtf8String(b64input);
    var lo = base, hi = base.add(0x800000);
    var tid = Process.getCurrentThreadId();
    resultStr = null;
    blocks = {};
    tracing = true;
    Stalker.follow(tid, {
        events: { block: true },
        onReceive: function (events) {
            if (!tracing) return;
            var evs = Stalker.parse(events, {annotate: false, stringify: false});
            for (var i = 0; i < evs.length; i++) {
                var ev = evs[i];
                var a = ev[1];
                if (a.compare(lo) >= 0 && a.compare(hi) < 0) {
                    var off = a.sub(base).toInt32();
                    var bucket = (off >>> 8) << 8;
                    blocks[bucket] = (blocks[bucket] || 0) + 1;
                }
            }
        }
    });
    var ret = entry(inp, cb);
    tracing = false;
    Stalker.unfollow(tid);
    Stalker.flush();
    return JSON.stringify({ret: '' + ret, result: resultStr, blocks: blocks});
};
"""


def ch_encrypt(plain: bytes) -> str:
    return base64.b64encode(AES.new(CH_KEY, AES.MODE_CBC, CH_IV).encrypt(pad(plain, 16))).decode()


def ch_decrypt(b64text: str):
    return AES.new(CH_KEY, AES.MODE_CBC, CH_IV).decrypt(base64.b64decode(b64text))


def _find_pid(dev):
    for pr in dev.enumerate_processes():
        if '囧' in pr.name or 'tudou' in pr.name.lower():
            return pr.pid
    raise RuntimeError('target process not found')


def main():
    body = None
    for line in open('research/captures/rsa_scan/bodies_now.jsonl', encoding='utf-8', errors='replace'):
        try:
            o = json.loads(line)
        except Exception:
            continue
        if PATH in o.get('req', ''):
            r = o.get('resp_body_ascii', '')
            if r.count('.') == 1 and len(r) > 400:
                body = r.strip()
    assert body
    env = json.dumps({"action": "api_decrypt", "payload": {"data": json.dumps(body), "path": PATH}},
                     separators=(',', ':'))
    inp = ch_encrypt(env.encode())

    dev = frida.get_device('127.0.0.1:5555')
    sess = dev.attach(_find_pid(dev))
    sc = sess.create_script(JS)
    sc.load()
    out = sc.exports_sync.call(inp)
    o = json.loads(out)
    print('[*] blocks buckets:', len(o.get('blocks', {})))
    res = o.get('result')
    if res:
        try:
            raw = ch_decrypt(res)
            obj = json.loads(raw.split(b'\x00')[0])
            data = obj.get('payload', {}).get('data', '')
            print('[*] 真机解密 data[:300]:', str(data)[:300])
        except Exception as ex:
            print('[*] 结果解码失败:', ex)
    json.dump({'blocks': o.get('blocks', {}), 'result': res},
              open('research/tmp_dev_blocks.json', 'w'))
    print('[*] 已写 research/tmp_dev_blocks.json')
    sess.detach()


if __name__ == '__main__':
    main()
