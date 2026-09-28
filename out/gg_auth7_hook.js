'use strict';
// 第七轮: dump RSA* 私钥 BIGNUM + 修 flen/len (toInt32) + CB 分段全量 + cbc 明密文对
var MAXSEND = 12000;
var SENT = 0;
function send0(o){ if (SENT < MAXSEND){ SENT++; send(o); } }

function toHex(b){ if(!b) return null; try { return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }catch(e){ return null; } }
function dump(p, n){ try{ if(!p || p.isNull() || n <= 0) return null; return toHex(p.readByteArray(n)); }catch(e){ return null; } }
function cstr(p, max){ try{ if(!p || p.isNull()) return null; return p.readCString(max || 4096); }catch(e){ return null; } }
function num(p){
    try{ return p.toInt32(); }
    catch(e){ try{ return parseInt(p.toString(16), 16); }catch(e2){ return 0; } }
}
function heapOk(p){ try{ if(!p || p.isNull()) return false; var s=p.toString(16); var pfx=parseInt(s.slice(0,4),16); return pfx>=0x7100 && pfx<=0x712f; }catch(e){ return false; } }
function dartStrText(p, max){
    try{
        if(!heapOk(p)) return null;
        var u8 = new Uint8Array(p.readByteArray(16));
        var len = ((u8[7] | (u8[8]<<8) | (u8[9]<<16)) >>> 0) >>> 1;
        if (len < 0 || len > 16384) return null;
        if (len > (max||4096)) len = max||4096;
        var d = new Uint8Array(p.add(15).readByteArray(len));
        var s = '';
        for (var i=0;i<d.length;i++) s += String.fromCharCode(d[i]);
        return s;
    }catch(e){ return null; }
}
// 分段读取 (绕过 1024 停止问题): 每次 512B
function dumpChunks(p, total){
    var parts = [];
    var got = 0;
    while (got < total){
        var n = Math.min(512, total - got);
        var h = null;
        try { h = toHex(p.add(got).readByteArray(n)); } catch(e){ break; }
        if (!h) break;
        parts.push(h);
        got += n;
    }
    return parts.length ? parts.join('') : null;
}

var done=false;
var poll=setInterval(function(){
    if(done) return;
    var m = Process.findModuleByName('libapp.so');
    var cm = Process.findModuleByName('libcore.so');
    if(!m || !cm) return;
    done=true; clearInterval(poll);
    var A = function(v){ return m.base.add(v); };

    function hookExp(name, handlers){
        try{
            var a = cm.findExportByName(name);
            if(!a){ send0({t:'INFO', msg:'NOEXP '+name}); return; }
            Interceptor.attach(a, handlers);
            send0({t:'INFO', msg:'hooked '+name});
        }catch(e){ send0({t:'INFO', msg:'FAIL '+name+': '+e}); }
    }

    // ---------- BIGNUM dump ----------
    function bnHex(bnPtr){
        try{
            if (!bnPtr || bnPtr.isNull()) return null;
            var d = bnPtr.readPointer();
            var top = bnPtr.add(8).readInt();
            if (top <= 0 || top > 4096) return null;
            return dump(d, top * 8);
        }catch(e){ return null; }
    }

    // ---------- RSA: (flen, from, to, rsa, pad) — dump rsa key + from/to ----------
    ['RSA_public_encrypt','RSA_private_encrypt','RSA_private_decrypt','RSA_public_decrypt'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.outp = args[2]; this.fn = name; this.rsa = args[3];
                var flen = num(args[0]);
                var n = (flen > 0 && flen <= 1024) ? flen : 0;
                var o = {t:'rsa', fn:name, flen:flen, fromHex: n ? dump(args[1], n) : null};
                // RSA struct: n@0x18 e@0x20 d@0x28 p@0x30 q@0x38 (OpenSSL 1.1 arm64)
                try{
                    var rsap = args[3];
                    if (rsap && !rsap.isNull()){
                        o.bn_n = bnHex(rsap.add(0x18).readPointer());
                        o.bn_e = bnHex(rsap.add(0x20).readPointer());
                        o.bn_d = bnHex(rsap.add(0x28).readPointer());
                        o.bn_p = bnHex(rsap.add(0x30).readPointer());
                        o.bn_q = bnHex(rsap.add(0x38).readPointer());
                        o.bn_dmp1 = bnHex(rsap.add(0x40).readPointer());
                        o.bn_dmq1 = bnHex(rsap.add(0x48).readPointer());
                        o.bn_iqmp = bnHex(rsap.add(0x50).readPointer());
                    }
                }catch(e){ o.bnerr = ''+e; }
                send0(o);
            },
            onLeave: function(ret){
                var outl = num(ret);
                var n = (outl > 0 && outl <= 1024) ? outl : 0;
                send0({t:'rsa.out', fn:this.fn, outl:outl, toHex: n ? dump(this.outp, n) : null});
            }
        });
    });

    // ---------- key setup ----------
    ['AES_set_encrypt_key','AES_set_decrypt_key','aes_v8_set_encrypt_key','aes_v8_set_decrypt_key','vpaes_set_encrypt_key','vpaes_set_decrypt_key'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                var bits = num(args[1]);
                var n = (bits===128||bits===192||bits===256) ? bits/8 : 16;
                send0({t:'ks', fn:name, bits:bits, key:dump(args[0], n)});
            }
        });
    });

    // ---------- EVP init ----------
    ['EVP_CipherInit_ex','EVP_EncryptInit_ex','EVP_DecryptInit_ex'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                var o = {t:'evp.init', fn:name, enc:num(args[5])};
                try{
                    var c = args[1];
                    if (c && !c.isNull()){
                        o.nid = c.readU32(); o.keylen = c.add(8).readU32(); o.ivlen = c.add(12).readU32();
                    }
                }catch(e){}
                o.key = (args[3] && !args[3].isNull()) ? dump(args[3], (o.keylen && o.keylen<=64) ? o.keylen : 32) : null;
                o.iv  = (args[4] && !args[4].isNull()) ? dump(args[4], 16) : null;
                send0(o);
            }
        });
    });

    // ---------- one-shot cbc: (in, out, len, KEY*, ivec, enc) ----------
    ['AES_cbc_encrypt','aes_v8_cbc_encrypt','vpaes_cbc_encrypt'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.outp = args[1]; this.len = num(args[2]); this.fn = name; this.keyp = args[3]; this.ivp = args[4];
                var n = (this.len > 0 && this.len <= 2048) ? this.len : 0;
                send0({t:'cbc', fn:name, len:this.len, enc:num(args[5]), inHex: n ? dump(args[0], n) : null, iv:dump(args[4],16)});
            },
            onLeave: function(){
                var n = (this.len > 0 && this.len <= 2048) ? this.len : 0;
                send0({t:'cbc.out', fn:this.fn, len:this.len, outHex: n ? dump(this.outp, n) : null, iv:dump(this.ivp,16)});
            }
        });
    });

    // ---------- RAND ----------
    hookExp('RAND_bytes', {
        onEnter: function(args){ this.buf = args[0]; this.num = num(args[1]); },
        onLeave: function(){
            var n = (this.num > 0 && this.num <= 128) ? this.num : 0;
            send0({t:'rand', num:this.num, val: n ? dump(this.buf, n) : null});
        }
    });

    // ---------- hashes ----------
    ['MD5','SHA1','SHA256'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.md = args[2]; this.fn = name;
                var n = num(args[1]);
                var capn = (n > 0 && n <= 512) ? n : 0;
                send0({t:'hash', fn:name, len:n, dataHex: capn ? dump(args[0], capn) : null});
            },
            onLeave: function(){
                var hl = this.fn==='SHA256' ? 32 : (this.fn==='SHA1' ? 20 : 16);
                send0({t:'hash.out', fn:this.fn, md:dump(this.md, hl)});
            }
        });
    });

    // ---------- libcore!call ----------
    try{
        var ca = cm.findExportByName('call');
        if (ca){
            Interceptor.attach(ca,{
                onEnter:function(args){ send0({t:'core.call', s0:cstr(args[0], 16384)}); }
            });
            send0({t:'INFO',msg:'hooked libcore!call'});
        }
    }catch(e){}

    // ---------- dartCallback: 分段全量 dump ----------
    try{
        Interceptor.attach(A(0x715844),{
            onEnter:function(){
                var x1 = this.context.x1, x2 = this.context.x2;
                var o = {t:'cb'};
                try{
                    var p = x1.add(7).readPointer();
                    var len = num(x2);
                    if (len > 262144) len = 262144;
                    o.lenRaw = len;
                    var cap = len && len > 0 ? Math.min(len, 32768) : 512;
                    var total = cap;
                    // 先探 NUL 位置: 分段读 1024
                    var found = 0;
                    var stop = -1;
                    var chunks = [];
                    while (found < total){
                        var n2 = Math.min(1024, total - found);
                        var u8 = null;
                        try { u8 = new Uint8Array(p.add(found).readByteArray(n2)); } catch(e){ break; }
                        if (!u8) break;
                        var z = -1;
                        for (var i=0;i<u8.length;i++){ if (u8[i]===0){ z=i; break; } }
                        if (z >= 0){ chunks.push(toHex(u8.subarray(0, z))); stop = found + z; break; }
                        chunks.push(toHex(u8));
                        found += n2;
                    }
                    o.use = (stop >= 0) ? stop : found;
                    o.hex = chunks.length ? chunks.join('') : null;
                }catch(e){ o.err = ''+e; }
                send0(o);
            }
        });
        send0({t:'INFO',msg:'hooked dartCallback chunked'});
    }catch(e){ send0({t:'INFO',msg:'FAIL dartCallback:'+e}); }

    // ---------- markers + url ----------
    try{
        Interceptor.attach(A(0x7eee0c),{ onEnter:function(){ send0({t:'mark', fn:'apiEncrypt'}); } });
        Interceptor.attach(A(0xabe058),{ onEnter:function(){ send0({t:'mark', fn:'apiDecrypt'}); } });
        Interceptor.attach(A(0x6ca174),{
            onEnter:function(){
                var s = dartStrText(this.context.x2, 2048);
                send0({t:'http.post', url:(s ? s.substring(0,512) : null)});
            }
        });
    }catch(e){}

    send0({t:'INFO',msg:'auth7 hooks installed pid='+Process.id});
}, 150);
send0({t:'INFO',msg:'auth7 hook js loaded pid='+Process.id});
