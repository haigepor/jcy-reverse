// live_hook.js — 囧次元 com.tudou.tool libcore.so 活体 hook
// 目标: ①真服务端公钥(RSA* → n) ②会话 key/iv(RAND_bytes/EVP) ③请求 P0(RSA 输出)
//      ④api_decrypt 输入信封(=响应体) → 全闭环
'use strict';

function rd(p, n) {
    try { return p.isNull() ? null : p.readByteArray(n); } catch (e) { return null; }
}

function hexOf(buf) {
    if (!buf) return null;
    var u = new Uint8Array(buf), s = '';
    for (var i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
    return s;
}

var LIBCORE_BASE = ptr('__LIBCORE_BASE__');

function hookCore() {
    var base = LIBCORE_BASE;
    send({ t: 'module', base: base.toString() });

    function exp(name) { return null; }

    // 1) FFI 入口 call(in, cb) — in = 传输信封(请求出参/响应入参)
    var pCall = base.add(0x307a38);
    if (pCall) Interceptor.attach(pCall, {
        onEnter: function (args) {
            var s = rd(args[0], 16384);
            send({ t: 'call_in', ptr: args[0].toString(), hex: hexOf(s) });
        },
        onLeave: function (ret) {
            var s = rd(ret.returnValue, 16384);
            send({ t: 'call_out', ptr: ret.returnValue.toString(), hex: hexOf(s) });
        }
    });

    // 2) RAND_bytes — key/iv 生成点
    Interceptor.attach(base.add(0x438d18), {
        onEnter: function (a) { this.buf = a[0]; this.num = a[1].toInt32(); },
        onLeave: function (r) {
            if (this.num <= 0 || this.num > 512) return;
            send({ t: 'rand', num: this.num, hex: hexOf(rd(this.buf, this.num)) });
        }
    });

    // 3) RSA_public_encrypt(flen, from, to, rsa, pad) — 请求 P0 + 真公钥
    Interceptor.attach(base.add(0x43e30c), {
        onEnter: function (a) {
            this.flen = a[0].toInt32(); this.from = a[1]; this.to = a[2]; this.rsa = a[3];
            this.pad = a[4].toInt32();
            send({ t: 'rsa_in', flen: this.flen, pad: this.pad, from: hexOf(rd(this.from, this.flen)) });
            try {
                for (var off = 0; off < 0x140; off += 8) {
                    var p = this.rsa.add(off).readPointer();
                    var top = p.add(8).readS32(), dmax = p.add(12).readS32();
                    if (top === 32 && dmax >= 32 && dmax <= 64) {
                        var d = p.readPointer();
                        send({ t: 'rsa_n', off: off, n: hexOf(rd(d, 256)) });
                        break;
                    }
                }
            } catch (e) { send({ t: 'rsa_n_err', e: String(e) }); }
        },
        onLeave: function (r) {
            if (this.flen > 0 && this.flen <= 4096 && !this.to.isNull())
                send({ t: 'rsa_out', ret: r.toInt32(), ct: hexOf(rd(this.to, 256)) });
        }
    });

    // 4) EVP 初始化 — 业务 key/iv (vaddr 来自 libcore.so 导出表)
    var EVP_OFF = { EVP_EncryptInit_ex: 0x387da4, EVP_CipherInit_ex: 0x387368 };
    Object.keys(EVP_OFF).forEach(function (nm) {
        Interceptor.attach(base.add(EVP_OFF[nm]), {
            onEnter: function (a) {
                send({ t: 'evp', nm: nm, key: hexOf(rd(a[3], 32)), iv: hexOf(rd(a[4], 16)) });
            }
        });
    });

    // 5) AES 低层 — 直接看 key 位长与 key 值
    { var p = base.add(0x3842ac);
      Interceptor.attach(p, { onEnter: function (a) {
          send({ t: 'aes_key', nm: 'set_enc', bits: a[1].toInt32(), key: hexOf(rd(a[0], 32)) });
      } }); }
    { var p2 = base.add(0x3845e0);
      Interceptor.attach(p2, { onEnter: function (a) {
          send({ t: 'aes_key', nm: 'set_dec', bits: a[1].toInt32(), key: hexOf(rd(a[0], 32)) });
      } }); }

    return true;
}

// ---- rpc: 从 python 直接驱动 call() ----
var g_call = null, g_cb = null, g_lastResult = null;
rpc.exports = {
    start: function () { return hookCore(); },
    callenv: function (b64) {
        if (g_call === null) {
            var base = LIBCORE_BASE;
            g_call = new NativeFunction(base.add(0x307a38), 'pointer', ['pointer', 'pointer']);
            g_cb = new NativeCallback(function (res) {
                send({ t: 'cb_ptr', v: res.toString() });
            }, 'void', ['pointer']);
        }
        var bytes = b64ToBytes(b64);
        var buf = Memory.alloc(bytes.length + 1);
        buf.writeByteArray(bytes);
        buf.add(bytes.length).writeU8(0);
        g_lastResult = null;
        var ret = g_call(buf, g_cb);
        var out = hexOf(rd(ret, 16384));
        return JSON.stringify({ ret: out, cb: g_lastResult });
    }
};

function b64ToBytes(b64) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var clean = b64.replace(/[^A-Za-z0-9+\/]/g, '');
    var out = [], bits = 0, acc = 0;
    for (var j = 0; j < clean.length; j++) {
        acc = (acc << 6) | chars.indexOf(clean.charAt(j));
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xFF); }
    }
    return out;
}

if (!hookCore()) {
    send({ t: 'waiting_libcore' });
    var dlopen = Module.findGlobalExportByName('android_dlopen_ext') ||
                 Module.findGlobalExportByName('dlopen');
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function (a) { this.p = a[0]; },
            onLeave: function () {
                try {
                    var n = this.p.readCString();
                    if (n && n.indexOf('libcore.so') >= 0) {
                        send({ t: 'dlopen', name: n });
                        hookCore();
                    }
                } catch (e) {}
            }
        });
    }
}
