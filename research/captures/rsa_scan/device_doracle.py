#!/usr/bin/env python3
"""device_doracle.py - 设备在环 D-oracle: frida 直调 libcore 0x307a38 喂构造信封.
用法:
  python device_doracle.py mods          # 列模块
  python device_doracle.py replay        # 测试A: 重放 device-base 响应体
  python device_doracle.py chosen        # 测试B: 自造 P0(K')+裸C 块
"""
import base64
import json
import sys

import frida
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

CH_KEY = b"qPwClBj7j7ZQraSm"
CH_IV = b"p3JdVQl3q7WQJIgG"
CALL_OFF = 0x307a38
PATH = '/app/video/device-base'

JS = r"""
var coreBase = null;
var coreName = null;
function findCore() {
    if (coreBase) return coreBase;
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        var n = mods[i].name.toLowerCase();
        if (n.indexOf('core') >= 0 && n.indexOf('.so') >= 0 && n.indexOf('libc') !== 0) {
            coreBase = mods[i].base;
            coreName = mods[i].name;
            return coreBase;
        }
    }
    return null;
}

var resultStr = null;

rpc.exports.mods = function () {
    return Process.enumerateModules().map(function (m) { return m.name + '@' + m.base; });
};

rpc.exports.call = function (b64input) {
    var base = findCore();
    if (!base) return 'ERR: core module not found';
    var entry = new NativeFunction(base.add(0x307a38), 'pointer', ['pointer', 'pointer']);
    var cb = new NativeCallback(function (p) {
        try {
            resultStr = Memory.readUtf8String(p, 65536);
            if (resultStr === null) resultStr = Memory.readCString(p);
        } catch (e) {
            resultStr = 'ERR reading: ' + e;
        }
    }, 'void', ['pointer']);
    var inp = Memory.allocUtf8String(b64input);
    resultStr = null;
    var ret = entry(inp, cb);
    return JSON.stringify({ ret: '' + ret, result: resultStr });
};
"""


def ch_encrypt(plain: bytes) -> str:
    return base64.b64encode(AES.new(CH_KEY, AES.MODE_CBC, CH_IV).encrypt(pad(plain, 16))).decode()


def ch_decrypt(b64text: str):
    raw = base64.b64decode(b64text)
    return AES.new(CH_KEY, AES.MODE_CBC, CH_IV).decrypt(raw)


def build_input(action, data_field, path=PATH):
    env = {"action": action, "payload": {"data": data_field, "path": path}}
    return ch_encrypt(json.dumps(env, separators=(',', ':')).encode())


def show_result(tag, raw_json):
    print('[%s] 通道解出 %dB' % (tag, len(raw_json)))
    txt = raw_json.split(b'\x00')[0]
    try:
        obj = json.loads(txt)
        data = obj.get('payload', {}).get('data', '')
        print('[%s] action=%r code=%s status=%s' % (
            tag, obj.get('action'), obj.get('code'), obj.get('payload', {}).get('status')))
        print('[%s] data(%d): %s' % (tag, len(data), data[:400]))
    except Exception as ex:
        print('[%s] JSON 解析失败 %s: %r' % (tag, ex, txt[:300]))


def get_session():
    dev = frida.get_device('127.0.0.1:5555')
    sess = dev.attach(17386)
    sc = sess.create_script(JS)
    sc.load()
    return sess, sc


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'mods'
    sess, sc = get_session()

    if cmd == 'mods':
        for m in sc.exports_sync.mods():
            if 'core' in m.lower() or 'loader' in m.lower() or 'app.so' in m.lower():
                print(m)
        return

    if cmd == 'replay':
        body = None
        for line in open('research/captures/rsa_scan/bodies_now.jsonl',
                         encoding='utf-8', errors='replace'):
            try:
                o = json.loads(line)
            except Exception:
                continue
            if PATH in o.get('req', ''):
                r = o.get('resp_body_ascii', '')
                if r.count('.') == 1 and len(r) > 400:
                    body = r.strip()
        assert body, '未找到响应体'
        print('[replay] body %dB head=%s...' % (len(body), body[:40]))
        inp = build_input('api_decrypt', json.dumps(body))
        out = sc.exports_sync.call(inp)
        handle(out, 'replay')
        return

    if cmd == 'chosen':
        from Crypto.PublicKey import RSA
        # 1) 自选 K16', 构造 P0' = RSA(pub_from_go, K16')
        K16 = 'HWE2HYC3QRJNEVKS'  # 先用已 unwrap 过的键做对照
        priv = RSA.import_key(open('research/captures/rsa_scan/priv_from_go.pem', 'rb').read())
        pub = RSA.construct((priv.n, priv.e))
        from Crypto.Cipher import PKCS1_v1_5
        P0 = PKCS1_v1_5.new(pub).encrypt(K16.encode(), None)
        assert len(P0) == 256
        # 2) C = 已知明文的 E 加密密文: 用 emu e_oracle 在线产 (此处先拿历史 P1 的 C)
        #    首轮验证用 P1 = 2 块固定模式; 若 native 校验 PKCS7 会报错也算信息
        C = bytes(range(0x10)) * 2 + bytes(range(0x10, 0x20))
        ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
        STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        tb = base64.b64encode(P0).decode().translate(str.maketrans(STD, ALPHA)).rstrip('=')
        cb = base64.b64encode(C).decode().translate(str.maketrans(STD, ALPHA)).rstrip('=')
        body2 = tb + '.' + cb
        print('[chosen] P0=%dB C=%dB body2=%dB' % (len(P0), len(C), len(body2)))
        inp = build_input('api_decrypt', json.dumps(body2))
        out = sc.exports_sync.call(inp)
        handle(out, 'chosen')
        return


def handle(out, tag):
    o = json.loads(out)
    if o['result'] is None:
        print('[%s] 回调未触发, ret=%s' % (tag, o['ret']))
        return
    raw = ch_decrypt(o['result'])
    show_result(tag, raw)


if __name__ == '__main__':
    main()
