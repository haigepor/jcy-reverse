// out/gg_dart_hook8.js — chase pointers inside argument objects, decode all Dart strings found
'use strict';

var INSN_ST_VALUE = 0x4b6b40;
var hookedAny = false;

function toHex(b) {
    if (!b) return null;
    return Array.from(new Uint8Array(b)).map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join('');
}

function dartStrAt(p) {
    // p points at a candidate object header: tags(4B) hash(4B) lenSmi(4B) [pad(4B)] data(+12 or +16)
    try {
        if (p.isNull()) return null;
        var addr = parseInt(p.toString(16).slice(0,4), 16);
        if (addr !== 0x7100) return null;
        var tags = p.readU32();
        if (tags > 0x100000) return null;
        var lenSmi = p.add(8).readU32();
        var len = lenSmi >>> 1;
        if (len < 2 || len > 65536) return null;
        var best = null;
        for (var off = 12; off <= 16; off += 4) {
            try {
                var b = p.add(off).readByteArray(Math.min(len, 900));
                var u8 = new Uint8Array(b);
                var ok = true, s = '';
                for (var i = 0; i < u8.length; i++) {
                    var c = u8[i];
                    if (c >= 32 && c < 127) s += String.fromCharCode(c);
                    else if (c === 10 || c === 13) s += ' ';
                    else if (c >= 0x80) s += '?';
                    else { ok = false; break; }
                }
                if (ok && s.length >= 2) { best = { off: off, len: len, s: s }; break; }
            } catch (e) {}
        }
        return best;
    } catch (e) { return null; }
}

function chase(p, label, out) {
    try {
        if (p.isNull()) return;
        var a = parseInt(p.toString(16).slice(0,4), 16);
        if (a !== 0x7100 && a !== 0x7101) return;
        var block = p.readByteArray(768);
        var u8 = new Uint8Array(block);
        for (var off = 0; off + 8 <= u8.length; off += 4) {
            var lo = u8[off] | (u8[off+1]<<8) | (u8[off+2]<<16) | (u8[off+3]<<24);
            var hi = (u8[off+4] | (u8[off+5]<<8) | (u8[off+6]<<16) | (u8[off+7]<<24));
            // compressed heap pointer: 32-bit low word, high word ~ 0 or 0x7100 region raw 64-bit
            var cand = null;
            if (lo >>> 0 >= 0x01000000 && (hi === 0)) cand = ptr('0x7100000000').add(lo >>> 0);
            else if (lo >>> 0 >= 0x01000000 && (hi === 0x71)) cand = ptr('0x7100000000').add(lo >>> 0);
            if (!cand) continue;
            var ds = dartStrAt(cand);
            if (ds) out.push({ via: label + '+' + off, off: ds.off, len: ds.len, s: ds.s.substring(0, 500) });
        }
    } catch (e) {}
}

function dumpRegs(cpu) {
    var out = [];
    for (var i = 0; i < 8; i++) {
        try {
            var r = cpu['x' + i];
            var rec = { r: 'x' + i, v: r.toString() };
            var ds = dartStrAt(r);
            if (ds) { rec.str = ds.s.substring(0, 900); rec.dlen = ds.len; rec.doff = ds.off; }
            out.push(rec);
        } catch (e) {}
    }
    return out;
}

function hookInsn(libapp, off, label) {
    var a = libapp.base.add(INSN_ST_VALUE).add(off);
    try {
        Interceptor.attach(a, {
            onEnter: function (args) {
                var rec = { t: label + '.enter', args: dumpRegs(this.context) };
                var chaseOut = [];
                for (var i = 0; i < 8; i++) { try { chase(this.context['x' + i], 'x' + i, chaseOut); } catch (e) {} }
                if (chaseOut.length) rec.chase = chaseOut.slice(0, 40);
                send(rec);
            },
            onLeave: function (retval) {
                send({ t: label + '.leave', ret: retval.toString(), args: dumpRegs(this.context) });
            }
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
        ['0x58507c', 'TokenInterceptor.onRequest'],
        ['0x585914', 'TokenInterceptor.onResponse'],
        ['0x3382cc', 'FFIUtils.apiEncrypt'],
        ['0x607518', 'FFIUtils.apiDecrypt'],
        ['0x213634', 'HttpClient.post']
    ].forEach(function (t) { hookInsn(libapp, parseInt(t[0]), t[1]); });
    return true;
}

doHook();
var poller = setInterval(function () { if (doHook()) clearInterval(poller); }, 100);
send({ t: 'INFO', msg: 'gg_dart_hook8.js loaded pid=' + Process.id });
