// out/gg_dart_hook4.js — decode Dart OneByteString args properly
// layout at reg: +0..7 tags(uword), +8..15 length (Smi, 8B), +16 data
'use strict';

var INSN_ST_VALUE = 0x4b6b40;
var hookedAny = false;

function toHex(b) {
    if (!b) return null;
    return Array.from(new Uint8Array(b)).map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join('');
}

function dartStr(p) {
    try {
        if (p.isNull()) return null;
        var lenSmi = p.add(8).readULong();
        var len = Number(lenSmi) >> 1;
        if (len < 2 || len > 65536) return null;
        // plausibility: tags word small
        var tags = p.readULong();
        if (Number(tags) > 0x100000) return null;
        var b = p.add(16).readByteArray(Math.min(len, 1024));
        var u8 = new Uint8Array(b);
        var ok = true, s = '';
        for (var i = 0; i < u8.length; i++) {
            var c = u8[i];
            if (c === 10 || c === 13 || c === 9) { s += '\\n'; }
            else if (c >= 32 && c < 127) { s += String.fromCharCode(c); }
            else if (c >= 0x80) { s += '?'; }
            else { ok = false; break; }
        }
        if (!ok || s.length < 2) return null;
        return { len: len, s: s };
    } catch (e) { return null; }
}

function dumpRegs(cpu) {
    var out = [];
    for (var i = 0; i < 8; i++) {
        try {
            var r = cpu['x' + i];
            var rec = { r: 'x' + i, v: r.toString() };
            var ds = dartStr(r);
            if (ds) { rec.str = ds.s; rec.dlen = ds.len; }
            else if (!r.isNull()) {
                try { rec.hex = toHex(r.readByteArray(512)); } catch (e) {}
            }
            out.push(rec);
        } catch (e) {}
    }
    return out;
}

function hookInsn(libapp, off, label) {
    var a = libapp.base.add(INSN_ST_VALUE).add(off);
    try {
        Interceptor.attach(a, {
            onEnter: function (args) { send({ t: label + '.enter', args: dumpRegs(this.context) }); },
            onLeave: function (retval) { send({ t: label + '.leave', ret: retval.toString(), args: dumpRegs(this.context) }); }
        });
        send({ t: 'INFO', msg: 'hooked ' + label + ' @ ' + a.toString() });
        hookedAny = true;
    } catch (e) {
        send({ t: 'INFO', msg: 'FAILED ' + label + ': ' + e });
    }
}

function doHook() {
    var libapp = Process.findModuleByName('libapp.so');
    if (!libapp) return false;
    if (hookedAny) return true;
    [
        ['0x238e6c', 'Encrypter.encrypt'],
        ['0x238ef8', 'Encrypter.encryptBytes'],
        ['0x60383c', 'AES.encrypt'],
        ['0x58507c', 'TokenInterceptor.onRequest'],
        ['0x585914', 'TokenInterceptor.onResponse'],
        ['0x3382cc', 'FFIUtils.apiEncrypt'],
        ['0x607518', 'FFIUtils.apiDecrypt'],
        ['0x213634', 'HttpClient.post'],
        ['0x213110', 'UserToken.updateToken']
    ].forEach(function (t) { hookInsn(libapp, parseInt(t[0]), t[1]); });
    return true;
}

doHook();
var poller = setInterval(function () { if (doHook()) clearInterval(poller); }, 100);
send({ t: 'INFO', msg: 'gg_dart_hook7.js loaded pid=' + Process.id });
