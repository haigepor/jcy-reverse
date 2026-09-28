// out/gg_dart_hook.js — hook Dart AOT functions via reFlutter dump offsets
// addr = libapp.so base + 0x4b6b40 (isolate instructions st_value) + dump offset
'use strict';

var INSN_ST_VALUE = 0x4b6b40;
var hookedAny = false;

function toHex(b) {
    if (!b) return null;
    return Array.from(new Uint8Array(b)).map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join('');
}

// Dart OneByteString (compressed ptrs): +0 tags(4B) +4 hash(4B) +8 length Smi(4B) +C data
// TwoByteString: data is UTF-16LE at +C
function dartString(p) {
    try {
        if (p.isNull()) return null;
        var addr = p.toString(16);
        // heap objects live at 0x71xxxxxxxx range (compressed base 0x7100000000)
        if (parseInt(addr.substring(0, 4), 16) !== 0x71) return null;
        var lenSmi = p.add(8).readU32();
        var len = lenSmi >>> 1;
        if (len === 0 || len > 8192) return null;
        var tags = p.readU32();
        var cid = (tags >>> 12) & 0xFFF;
        if (cid === 85 || cid === 84 || cid === 86 || cid === 83) { // one/two-byte string cids vary; try utf8 read
            var b = p.add(12).readByteArray(len);
            var u8 = new Uint8Array(b);
            var printable = true;
            var s = '';
            for (var i = 0; i < u8.length && i < 300; i++) {
                if (u8[i] >= 32 && u8[i] < 127 || u8[i] >= 0x80) s += String.fromCharCode(u8[i]);
                else { printable = false; break; }
            }
            return { kind: cid, len: len, s: s, printable: printable };
        }
        return null;
    } catch (e) { return null; }
}

function dumpRegs(cpu) {
    var out = [];
    for (var i = 0; i < 8; i++) {
        try {
            var r = cpu['x' + i];
            var rec = { r: 'x' + i, v: r.toString() };
            var ds = dartString(r);
            if (ds && ds.printable) { rec.str = ds.s; rec.len = ds.len; }
            else if (!r.isNull()) {
                try { rec.hex = toHex(r.readByteArray(384)); } catch (e) {}
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
        send({ t: 'INFO', msg: 'FAILED ' + label + ' @ ' + a.toString() + ': ' + e });
    }
}

function doHook() {
    var libapp = Process.findModuleByName('libapp.so');
    if (!libapp) return false;
    if (hookedAny) return true;
    var targets = [
        ['0x238e6c', 'Encrypter.encrypt'],
        ['0x60383c', 'AES.encrypt'],
        ['0x603968', 'RSA.encrypt'],
        ['0x58507c', 'TokenInterceptor.onRequest'],
        ['0x5850a0', 'TokenInterceptor.onRequest2'],
        ['0x5850e0', 'TokenInterceptor.onRequest3'],
        ['0x585914', 'TokenInterceptor.onResponse'],
        ['0x3382cc', 'FFIUtils.apiEncrypt'],
        ['0x607518', 'FFIUtils.apiDecrypt'],
        ['0x213634', 'HttpClient.post'],
        ['0x213110', 'UserToken.updateToken']
    ];
    targets.forEach(function (t) { hookInsn(libapp, parseInt(t[0]), t[1]); });
    return true;
}

doHook();
var poller = setInterval(function () { if (doHook()) clearInterval(poller); }, 100);
send({ t: 'INFO', msg: 'gg_dart_hook.js loaded pid=' + Process.id });
