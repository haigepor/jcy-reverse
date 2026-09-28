'use strict';
// 第六轮: 修复 toInt (num() helper) — 抓 evp.init key/iv, ks key, cbc key-usage, rand, rsa
var MAXSEND = 12000;
var SENT = 0;
function send0(o){ if (SENT < MAXSEND){ SENT++; send(o); } }

function toHex(b){ if(!b) return null; try { return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }catch(e){ return null; } }
function dump(p, n){ try{ if(!p || p.isNull()) return null; return toHex(p.readByteArray(n)); }catch(e){ return null; } }
function cstr(p, max){ try{ if(!p || p.isNull()) return null; return p.readCString(max || 4096); }catch(e){ return null; } }
function num(p){ try{ return p.toInt(); }catch(e){ try{ return parseInt(p.toString(),10); }catch(e2){ return 0; } } }
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

    // ---- key setup: (userKey, bits, KEY*) — dump key AND resulting schedule
    ['AES_set_encrypt_key','AES_set_decrypt_key','aes_v8_set_encrypt_key','aes_v8_set_decrypt_key','vpaes_set_encrypt_key','vpaes_set_decrypt_key'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                var bits = num(args[1]);
                var n = (bits===128||bits===192||bits===256) ? bits/8 : 16;
                send0({t:'ks', fn:name, bits:bits, key:dump(args[0], n), keyptr:(''+args[0])});
            }
        });
    });

    // ---- EVP init: (ctx, cipher, impl, key, iv, enc)
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

    // ---- one-shot cbc: (in, out, len, KEY*, ivec, enc) — KEY* schedule reverse
    ['AES_cbc_encrypt','aes_v8_cbc_encrypt','vpaes_cbc_encrypt'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.outp = args[1]; this.len = num(args[2]); this.fn = name; this.keyp = args[3];
                var n = (this.len > 0 && this.len <= 1024) ? this.len : 0;
                send0({t:'cbc', fn:name, len:this.len, enc:num(args[5]), inHex: n ? dump(args[0], n) : null, iv:dump(args[4],16), keyptr:(''+args[3])});
            },
            onLeave: function(){
                var n = (this.len > 0 && this.len <= 1024) ? this.len : 0;
                send0({t:'cbc.out', fn:this.fn, outHex: n ? dump(this.outp, n) : null, keyptr:(''+this.keyp)});
            }
        });
    });

    // ---- RSA
    ['RSA_public_encrypt','RSA_private_encrypt','RSA_private_decrypt','RSA_public_decrypt'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.outp = args[2]; this.fn = name;
                var flen = num(args[0]);
                var n = (flen > 0 && flen <= 512) ? flen : 0;
                send0({t:'rsa', fn:name, flen:flen, fromHex: n ? dump(args[1], n) : null});
            },
            onLeave: function(ret){
                var outl = num(ret);
                var n = (outl > 0 && outl <= 512) ? outl : 0;
                send0({t:'rsa.out', fn:this.fn, outl:outl, toHex: n ? dump(this.outp, n) : null});
            }
        });
    });

    // ---- RAND_bytes
    hookExp('RAND_bytes', {
        onEnter: function(args){ this.buf = args[0]; this.num = num(args[1]); },
        onLeave: function(){
            var n = (this.num > 0 && this.num <= 128) ? this.num : 0;
            send0({t:'rand', num:this.num, val: n ? dump(this.buf, n) : null});
        }
    });

    // ---- MD5/SHA1/SHA256
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

    // ---- HMAC
    hookExp('HMAC', {
        onEnter: function(args){
            this.md = args[5];
            var klen = num(args[2]);
            var kn = (klen > 0 && klen <= 64) ? klen : 0;
            var n = num(args[4]);
            var dn = (n > 0 && n <= 512) ? n : 0;
            send0({t:'hmac', klen:klen, keyHex: kn ? dump(args[1], kn) : null, dlen:n, dataHex: dn ? dump(args[3], dn) : null});
        },
        onLeave: function(){ send0({t:'hmac.out', md:dump(this.md, 32)}); }
    });

    // ---- libcore!call enter (qPwC b64 request)
    try{
        var ca = cm.findExportByName('call');
        if (ca){
            Interceptor.attach(ca,{
                onEnter:function(args){ send0({t:'core.call', s0:cstr(args[0], 8192)}); }
            });
            send0({t:'INFO',msg:'hooked libcore!call'});
        }
    }catch(e){}

    // ---- dartCallback full dump
    try{
        Interceptor.attach(A(0x715844),{
            onEnter:function(){
                var x1 = this.context.x1, x2 = this.context.x2;
                var o = {t:'cb'};
                try{
                    var p = x1.add(7).readPointer();
                    var len = parseInt(''+x2, 16) >>> 0;
                    o.lenRaw = len;
                    var cap = 8192;
                    var buf = new Uint8Array(p.readByteArray(Math.min(len || 512, cap)));
                    var z = -1;
                    for (var i=0;i<buf.length;i++){ if (buf[i]===0){ z=i; break; } }
                    o.use = (z >= 0 ? z : buf.length);
                    var h = '';
                    for (var j=0;j<o.use;j++) h += ('0'+buf[j].toString(16)).slice(-2);
                    o.hex = h;
                }catch(e){ o.err = ''+e; }
                send0(o);
            }
        });
        send0({t:'INFO',msg:'hooked dartCallback'});
    }catch(e){ send0({t:'INFO',msg:'FAIL dartCallback:'+e}); }

    // ---- markers + URL
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

    send0({t:'INFO',msg:'auth6 hooks installed pid='+Process.id});
}, 150);
send0({t:'INFO',msg:'auth6 hook js loaded pid='+Process.id});
