#!/usr/bin/env python3
"""dev_doracle_new.py - 新构建真机直调 D-oracle:
扫描全内存定位新 libcore 执行副本 (入口字节 @0x2c3a14), NativeFunction 直调 replay."""
import base64
import json
import sys

import frida
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

CH_KEY = b"qPwClBj7j7ZQraSm"
CH_IV = b"p3JdVQl3q7WQJIgG"
CALL_OFF = 0x2C3A14          # 新构建 FFI 入口
PATH = '/app/video/device-base'

JS = r"""
function coreBase() {
    var f = new File('/proc/self/maps', 'r');
    var line; var first = null;
    while ((line = f.readLine()) !== null && line !== '' && line !== undefined) {
        if (line.indexOf('files/libcore.so') >= 0) {
            var b = parseInt(line.split('-')[0], 16);
            if (first === null || b < first) first = b;
        }
    }
    f.close();
    return first;
}
rpc.exports.findexec = function (pat) {
    var rs = Process.enumerateRanges('r-x');
    var out = [];
    for (var i = 0; i < rs.length; i++) {
        var r = rs[i];
        if (r.size > 0x2000000) continue;   // 跳过超大 JIT 区, 单独扫
        try {
            var m = Memory.scanSync(r.base, r.size, pat);
            for (var j = 0; j < m.length; j++) out.push(m[j].address.toString());
        } catch (e) {}
    }
    // 大 rwx 区单独扫
    for (var i = 0; i < rs.length; i++) {
        var r = rs[i];
        if (r.size <= 0x2000000) continue;
        try {
            var step = 0x1000000;
            for (var o = 0; o < r.size; o += step) {
                var sz = Math.min(step + 64, r.size - o);
                var m = Memory.scanSync(r.base.add(o), sz, pat);
                for (var j = 0; j < m.length; j++) out.push(m[j].address.toString());
            }
        } catch (e) {}
    }
    return out;
};
rpc.exports.call = function (addrStr, b64input) {
    var entry = new NativeFunction(ptr(addrStr), 'pointer', ['pointer', 'pointer']);
    var resultStr = null;
    var cb = new NativeCallback(function (p) {
        try { resultStr = Memory.readCString(p); }
        catch (e) { resultStr = 'ERR ' + e; }
    }, 'void', ['pointer']);
    var inp = Memory.allocUtf8String(b64input);
    resultStr = null;
    try {
        var ret = entry(inp, cb);
        return JSON.stringify({ ret: '' + ret, result: resultStr, base: coreBase() });
    } catch (e) {
        return JSON.stringify({ err: '' + e, result: resultStr, base: coreBase() });
    }
};
"""


def ch_encrypt(plain: bytes) -> str:
    return base64.b64encode(AES.new(CH_KEY, AES.MODE_CBC, CH_IV).encrypt(pad(plain, 16))).decode()


def ch_decrypt(b64text: str):
    return AES.new(CH_KEY, AES.MODE_CBC, CH_IV).decrypt(base64.b64decode(b64text))


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
    sess = dev.attach('囧次元')
    sc = sess.create_script(JS)
    sc.load()
    pat = 'fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9'
    hits = sc.exports_sync.findexec(pat)
    print('[*] 入口字节命中:', hits)
    if not hits:
        print('[!] 未定位执行副本')
        return
    # 每个命中 = 候选入口 (CALL@0x2c3a14)
    for h in hits:
        addr = int(h, 16)
        print('[*] 尝试入口 @0x%x (exec_base=0x%x)' % (addr, addr - CALL_OFF))
        out = sc.exports_sync.call(h, inp)
        o = json.loads(out)
        res = o.get('result')
        if res:
            try:
                raw = ch_decrypt(res)
                obj = json.loads(raw.split(b'\x00')[0])
                data = obj.get('payload', {}).get('data', '')
                echo = data.startswith('"i2sHJzS0')
                print('[*] action=%r code=%s echo=%s' % (obj.get('action'), obj.get('code'), echo))
                print('[*] data(%d): %s' % (len(data), str(data)[:400]))
                if not echo:
                    open('research/tmp_dev_doracle_plain.json', 'w', encoding='utf-8').write(str(data))
                    print('[!!] 真解密明文已存 research/tmp_dev_doracle_plain.json')
            except Exception as ex:
                print('[*] 结果解码失败:', ex, str(res)[:120])
        else:
            print('[*] 无结果:', out[:200])
        break  # 第一个命中先试
    sess.detach()


if __name__ == '__main__':
    main()
