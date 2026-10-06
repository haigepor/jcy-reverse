// gg_crypto_hook.js — dump crypto material from 囧次元 (frida gadget, no root)
// Targets: libloader.so OpenSSL exports (AES/RSA), Java MethodChannel bridge
'use strict';

function hex(p, n) {
    try { return Memory.readByteArray(p, n); } catch (e) { return '(unreadable)'; }
}
function hx(p, n) {
    try {
        const b = Memory.readByteArray(p, n);
        return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
    } catch (e) { return '(unreadable)'; }
}
function asciiz(p, n) {
    try {
        let s = '';
        for (let i = 0; i < n; i++) {
            const c = Memory.readU8(p.add(i));
            if (c >= 32 && c < 127) s += String.fromCharCode(c); else s += '.';
        }
        return s;
    } catch (e) { return '(unreadable)'; }
}

const LOADED = {};
function hookLib(name) {
    if (LOADED[name]) return;
    let m = null;
    try { m = Process.findModuleByName(name); } catch (e) {}
    if (!m) return;
    LOADED[name] = true;
    console.log('[*] hooking ' + name + ' base=' + m.base);
    function exp(fn) {
        try { return m.findExportByName(fn); } catch (e) {
            try { return m.getExportByName(fn); } catch (e2) { return null; }
        }
    }

    const setkey = exp('AES_set_encrypt_key');
    if (setkey) {
        Interceptor.attach(setkey, {
            onEnter(a) {
                const bits = a[1].toInt32();
                console.log('[AES_set_encrypt_key] bits=' + bits + ' key=' + hx(a[0], bits / 8));
            }
        });
    }
    const setdkey = exp('AES_set_decrypt_key');
    if (setdkey) {
        Interceptor.attach(setdkey, {
            onEnter(a) {
                const bits = a[1].toInt32();
                console.log('[AES_set_decrypt_key] bits=' + bits + ' key=' + hx(a[0], bits / 8));
            }
        });
    }
    const cbc = exp('AES_cbc_encrypt');
    if (cbc) {
        Interceptor.attach(cbc, {
            onEnter(a) {
                const len = a[2].toInt32();
                const enc = a[5].toInt32();
                console.log('[AES_cbc_encrypt] enc=' + enc + ' len=' + len + ' ivec=' + hx(a[4], 16));
                if (enc === 1 && len > 0 && len < 8192) {
                    console.log('    PT(ascii): ' + asciiz(a[0], Math.min(len, 400)));
                } else {
                    console.log('    IN: ' + hx(a[0], 32));
                }
            }
        });
    }
    const ecb = exp('AES_encrypt');
    if (ecb) {
        Interceptor.attach(ecb, {
            onEnter(a) { console.log('[AES_encrypt] in=' + hx(a[0], 16)); }
        });
    }
    ['RSA_public_encrypt', 'RSA_private_encrypt'].forEach(fn => {
        const p = exp(fn);
        if (p) {
            Interceptor.attach(p, {
                onEnter(a) {
                    const flen = a[0].toInt32();
                    console.log('[' + fn + '] flen=' + flen);
                    console.log('    DATA(ascii): ' + asciiz(a[1], Math.min(flen, 200)));
                    console.log('    DATA(hex): ' + hx(a[1], Math.min(flen, 64)));
                }
            });
        }
    });
    ['RSA_public_decrypt', 'RSA_private_decrypt'].forEach(fn => {
        const p = exp(fn);
        if (p) {
            Interceptor.attach(p, {
                onEnter(a) {
                    const flen = a[0].toInt32();
                    console.log('[' + fn + '] flen=' + flen + ' IN=' + hx(a[1], Math.min(flen, 48)));
                }
            });
        }
    });
}

hookLib('libloader.so');
hookLib('libcore.so');
hookLib('liblua-core.so');
// late-loaded libs
Java.perform(function () {
    try {
        const Application = Java.use('android.app.Application');
        const System_ = Java.use('java.lang.System');
        const origLoad = System_.loadLibrary.overload('java.lang.String');
        origLoad.implementation = function (name) {
            console.log('[System.loadLibrary] ' + name);
            const r = origLoad.call(this, name);
            if (name === 'loader' || name === 'core') {
                setTimeout(function () {
                    hookLib('lib' + name + '.so');
                }, 100);
            }
            return r;
        };
    } catch (e) { console.log('loadLibrary hook err: ' + e); }

    try {
        const MC = Java.use('io.flutter.plugin.common.MethodChannel');
        MC.invokeMethod.overload('java.lang.String', 'java.lang.Object').implementation = function (method, args) {
            let a = '?';
            try { a = args !== null ? args.toString() : 'null'; } catch (e) {}
            console.log('[VMPLUGIN-out] ' + method + ' ' + a.substring(0, 600));
            return this.invokeMethod(method, args);
        };
        MC.invokeMethod.overload('java.lang.String', 'java.lang.Object', 'io.flutter.plugin.common.MethodChannel$Result').implementation = function (method, args, res) {
            let a = '?';
            try { a = args !== null ? args.toString() : 'null'; } catch (e) {}
            console.log('[VMPLUGIN-out3] ' + method + ' ' + a.substring(0, 600));
            return this.invokeMethod(method, args, res);
        };
    } catch (e) { console.log('MethodChannel hook err: ' + e); }
});
console.log('[*] gg_crypto_hook installed');
