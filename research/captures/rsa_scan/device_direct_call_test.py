#!/usr/bin/env python3
"""device_direct_call_test.py - 测 houdini 下 frida NativeFunction 直调 libcore 0x307a38 是否可行."""
import base64
import json
import sys

import frida
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

CH_KEY = b"qPwClBj7j7ZQraSm"
CH_IV = b"p3JdVQl3q7WQJIgG"
PID = 17386

JS = r"""
function findCoreBase() {
    var f = new File('/proc/self/maps', 'r');
    var line;
    var first = null;
    while ((line = f.readLine()) !== null && line !== '' && line !== undefined) {
        if (line.indexOf('files/libcore.so') >= 0) {
            var base = parseInt(line.split('-')[0], 16);
            if (first === null || base < first) first = base;
        }
    }
    f.close();
    return first;
}

var resultStr = null;
var called = false;

rpc.exports.info = function () {
    var b = findCoreBase();
    return b === null ? 'NOT_FOUND' : '0x' + b.toString(16);
};

rpc.exports.call = function (b64input) {
    var base = findCoreBase();
    if (base === null) return JSON.stringify({err: 'core not found'});
    var entry = new NativeFunction(ptr(base).add(0x307a38), 'pointer', ['pointer', 'pointer']);
    var cb = new NativeCallback(function (p) {
        called = true;
        try {
            resultStr = Memory.readCString(p);
        } catch (e) {
            resultStr = 'ERR: ' + e;
        }
    }, 'void', ['pointer']);
    var inp = Memory.allocUtf8String(b64input);
    resultStr = null;
    called = false;
    try {
        var ret = entry(inp, cb);
        return JSON.stringify({ret: '' + ret, called: called, result: resultStr});
    } catch (e) {
        return JSON.stringify({err: '' + e, called: called, result: resultStr});
    }
};
"""


def ch_encrypt(plain: bytes) -> str:
    return base64.b64encode(AES.new(CH_KEY, AES.MODE_CBC, CH_IV).encrypt(pad(plain, 16))).decode()


def ch_decrypt(b64text: str) -> bytes:
    raw = base64.b64decode(b64text)
    return AES.new(CH_KEY, AES.MODE_CBC, CH_IV).decrypt(raw)


def main():
    dev = frida.get_device('127.0.0.1:5555')
    sess = dev.attach(PID)
    sc = sess.create_script(JS)
    sc.load()
    print('[*] libcore base =', sc.exports_sync.info())

    env = {"action": "check", "payload": {}}
    inp = ch_encrypt(json.dumps(env, separators=(',', ':')).encode())
    print('[*] 发送 check, 输入 %dB' % len(inp))
    out = sc.exports_sync.call(inp)
    print('[*] 返回:', out[:400] if out else out)
    try:
        o = json.loads(out)
        if o.get('result'):
            raw = ch_decrypt(o['result'])
            print('[*] 通道解出 %dB: %r' % (len(raw), raw.split(b'\x00')[0][:300]))
    except Exception as ex:
        print('[*] 解码失败:', ex)
    sess.detach()


if __name__ == '__main__':
    main()
