// out/gg_ffi_hook.js v2 — hook FFI native layer; args packed into payload (no 2nd send arg)
'use strict';

var hooked = false;

function toHex(b) {
    if (!b) return null;
    return Array.from(new Uint8Array(b)).map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join('');
}
function safeHex(p, n) {
    try { return toHex(p.readByteArray(n)); } catch (e) { return null; }
}
function safeStr(p, max) {
    try {
        var s = p.readCString(max);
        if (s && s.length > 0 && /[\x20-\x7e]{4,}/.test(s.substring(0, 40))) return s;
        return null;
    } catch (e) { return null; }
}
function describeArgs(args, n) {
    var out = [];
    for (var i = 0; i < n; i++) {
        var a = args[i];
        var rec = { i: i, v: a.toString() };
        try {
            if (!a.isNull()) {
                var s = safeStr(a, 256);
                if (s) rec.str = s.substring(0, 256);
                rec.hex = safeHex(a, 128);
            }
        } catch (e) { rec.err = '' + e; }
        out.push(rec);
    }
    return out;
}

function hookModule(mname, exports) {
    var m = Process.findModuleByName(mname);
    if (!m) return false;
    exports.forEach(function (name) {
        var a = m.findExportByName(name);
        if (!a) { send({ t: 'INFO', msg: mname + '!' + name + ' not found' }); return; }
        Interceptor.attach(a, {
            onEnter: function (args) {
                send({ t: mname + '!' + name + '.enter', tid: Process.getCurrentThreadId(), args: describeArgs(args, 4) });
            },
            onLeave: function (retval) {
                var rec = { t: mname + '!' + name + '.leave', ret: retval.toString(), rethex: null, retstr: null };
                try {
                    if (!retval.isNull()) {
                        rec.rethex = safeHex(retval, 128);
                        var s = safeStr(retval, 128);
                        if (s) rec.retstr = s.substring(0, 128);
                    }
                } catch (e) {}
                send(rec);
            }
        });
        send({ t: 'INFO', msg: 'hooked ' + mname + '!' + name + ' @ ' + a.toString() + ' (base ' + m.base.toString() + ')' });
    });
    return true;
}

function hookAesKeySetup() {
    var m = Process.findModuleByName('libcore.so');
    if (!m) return false;
    ['aes_v8_set_encrypt_key', 'aes_v8_set_decrypt_key', 'vpaes_set_encrypt_key', 'vpaes_set_decrypt_key'].forEach(function (name) {
        var a = m.findExportByName(name);
        if (!a) return;
        Interceptor.attach(a, {
            onEnter: function (args) {
                var bits = args[1].toInt32();
                var kb = null;
                try { kb = toHex(args[0].readByteArray(bits / 8)); } catch (e) {}
                send({ t: 'AES_KEY_SETUP', fn: name, bits: bits, key: kb });
            }
        });
        send({ t: 'INFO', msg: 'hooked ' + name + ' @ ' + a.toString() });
    });
    return true;
}

function doHook() {
    if (hooked) return;
    var core = Process.findModuleByName('libcore.so');
    var loader = Process.findModuleByName('libloader.so');
    if (!core && !loader) return;
    hooked = true;
    hookModule('libcore.so', ['init', 'call']);
    hookModule('libloader.so', ['call', 'reload']);
    hookAesKeySetup();
    send({ t: 'INFO', msg: 'all native hooks installed; libcore=' + (core ? core.base.toString() : 'absent') + ' libloader=' + (loader ? loader.base.toString() : 'absent') });
}

doHook();
var poller = setInterval(function () { if (hooked) { clearInterval(poller); return; } doHook(); }, 50);

['dlopen', 'android_dlopen_ext'].forEach(function (fn) {
    var a = Module.findExportByName(null, fn);
    if (!a) return;
    Interceptor.attach(a, {
        onEnter: function (args) {
            try { this.n = args[0].readCString(); } catch (e) { this.n = null; }
        },
        onLeave: function (r) {
            if (this.n && (this.n.indexOf('libcore') >= 0 || this.n.indexOf('libloader') >= 0)) {
                send({ t: 'INFO', msg: fn + '(' + this.n + ') -> ' + r.toString() });
                doHook();
            }
        }
    });
});
send({ t: 'INFO', msg: 'gg_ffi_hook.js v2 loaded, pid=' + Process.id });
