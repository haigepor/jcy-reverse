'use strict';
// 第五轮: 修复 native crypto hook (实例 findExportByName) + CB 全量 dump + 时间函数
var MAXSEND = 12000;
var SENT = 0;
function send0(o){ if (SENT < MAXSEND){ SENT++; send(o); } }

function toHex(b){ if(!b) return null; try { return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }catch(e){ return null; } }
function dump(p, n){ try{ if(!p || p.isNull()) return null; return toHex(p.readByteArray(n)); }catch(e){ return null; } }
function cstr(p, max){ try{ if(!p || p.isNull()) return null; return p.readCString(max || 4096); }catch(e){ return null; } }
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

    // ============ native crypto (实例方法, round2 已验证可用) ============
    function hookExp(name, handlers){
        try{
            var a = cm.findExportByName(name);
            if(!a){ send0({t:'INFO', msg:'NOEXP '+name}); return; }
            Interceptor.attach(a, handlers);
            send0({t:'INFO', msg:'hooked '+name});
        }catch(e){ send0({t:'INFO', msg:'FAIL '+name+': '+e}); }
    }

    // key setup: (userKey, bits, KEY*)
    ['AES_set_encrypt_key','AES_set_decrypt_key','aes_v8_set_encrypt_key','aes_v8_set_decrypt_key','vpaes_set_encrypt_key','vpaes_set_decrypt_key'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                var bits = args[1].toInt();
                var n = (bits===128||bits===192||bits===256) ? bits/8 : 16;
                send0({t:'ks', fn:name, bits:bits, key:dump(args[0], n)});
            }
        });
    });

    // raw block: AES_encrypt(in, out, KEY*)
    ['AES_encrypt','AES_decrypt'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){ this.outp = args[1]; this.fn = name; this.inHex = dump(args[0],16); },
            onLeave: function(){ send0({t:'blk', fn:this.fn, inHex:this.inHex, outHex:dump(this.outp,16)}); }
        });
    });

    // EVP inits: (ctx, cipher, impl, key, iv, enc)
    ['EVP_CipherInit_ex','EVP_EncryptInit_ex','EVP_DecryptInit_ex'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                var o = {t:'evp.init', fn:name, enc:args[5].toInt()};
                try{
                    var c = args[1];
                    if (c && !c.isNull()){
                        o.nid = c.readU32(); o.block = c.add(4).readU32();
                        o.keylen = c.add(8).readU32(); o.ivlen = c.add(12).readU32();
                    }
                }catch(e){}
                o.key = (args[3] && !args[3].isNull()) ? dump(args[3], (o.keylen && o.keylen<=64) ? o.keylen : 32) : null;
                o.iv  = (args[4] && !args[4].isNull()) ? dump(args[4], 16) : null;
                send0(o);
            }
        });
    });

    // EVP update: (ctx, out, outl, in, inl)
    ['EVP_EncryptUpdate','EVP_DecryptUpdate'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.outp = args[1]; this.outlp = args[2]; this.fn = name;
                this.inl = args[4].toInt();
                var n = (this.inl > 0 && this.inl <= 2048) ? this.inl : (this.inl > 2048 ? 2048 : 0);
                send0({t:'evp.up', fn:name, inl:this.inl, inHex: n ? dump(args[3], n) : null});
            },
            onLeave: function(ret){
                try{
                    var outl = this.outlp.readU32();
                    var n = (outl > 0 && outl <= 2048) ? outl : 0;
                    send0({t:'evp.up.out', fn:this.fn, outl:outl, outHex: n ? dump(this.outp, n) : null});
                }catch(e){}
            }
        });
    });

    // one-shot cbc: (in, out, len, KEY*, ivec, enc)
    ['AES_cbc_encrypt','aes_v8_cbc_encrypt','vpaes_cbc_encrypt'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.outp = args[1]; this.len = args[2].toInt(); this.fn = name;
                var n = (this.len > 0 && this.len <= 2048) ? this.len : 0;
                send0({t:'cbc', fn:name, len:this.len, enc:args[5].toInt(), inHex: n ? dump(args[0], n) : null, iv:dump(args[4],16)});
            },
            onLeave: function(){
                var n = (this.len > 0 && this.len <= 2048) ? this.len : 0;
                send0({t:'cbc.out', fn:this.fn, outHex: n ? dump(this.outp, n) : null});
            }
        });
    });

    // RSA: (flen, from, to, rsa, pad)
    ['RSA_public_encrypt','RSA_private_encrypt','RSA_private_decrypt','RSA_public_decrypt'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.outp = args[2]; this.fn = name;
                var flen = args[0].toInt();
                var n = (flen > 0 && flen <= 512) ? flen : 0;
                send0({t:'rsa', fn:name, flen:flen, fromHex: n ? dump(args[1], n) : null});
            },
            onLeave: function(ret){
                var outl = ret.toInt();
                var n = (outl > 0 && outl <= 512) ? outl : 0;
                send0({t:'rsa.out', fn:this.fn, outl:outl, toHex: n ? dump(this.outp, n) : null});
            }
        });
    });

    // RAND_bytes(buf, num)
    hookExp('RAND_bytes', {
        onEnter: function(args){ this.buf = args[0]; this.num = args[1].toInt(); },
        onLeave: function(){
            var n = (this.num > 0 && this.num <= 128) ? this.num : 0;
            send0({t:'rand', num:this.num, val: n ? dump(this.buf, n) : null});
        }
    });

    // MD5(d, n, md) / SHA1 / SHA256
    ['MD5','SHA1','SHA256'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.md = args[2]; this.fn = name;
                var n = args[1].toInt();
                var capn = (n > 0 && n <= 1024) ? n : 0;
                send0({t:'hash', fn:name, len:n, dataHex: capn ? dump(args[0], capn) : null});
            },
            onLeave: function(){
                var hl = this.fn==='SHA256' ? 32 : (this.fn==='SHA1' ? 20 : 16);
                send0({t:'hash.out', fn:this.fn, md:dump(this.md, hl)});
            }
        });
    });

    // HMAC(evp_md, key, keylen, d, n, md, mdlen)
    hookExp('HMAC', {
        onEnter: function(args){
            this.md = args[5];
            var klen = args[2].toInt();
            var kn = (klen > 0 && klen <= 64) ? klen : 0;
            var n = args[4].toInt();
            var dn = (n > 0 && n <= 1024) ? n : 0;
            send0({t:'hmac', klen:klen, keyHex: kn ? dump(args[1], kn) : null, dlen:n, dataHex: dn ? dump(args[3], dn) : null});
        },
        onLeave: function(){ send0({t:'hmac.out', md:dump(this.md, 32)}); }
    });

    // RC4 (if exported)
    hookExp('RC4', {
        onEnter: function(args){
            // RC4(RC4_KEY *key, size_t len, const unsigned char *indata, unsigned char *outdata)
            this.outp = args[3];
            var len = args[1].toInt();
            this.len = len;
            var n = (len > 0 && len <= 512) ? len : 0;
            send0({t:'rc4', len:len, inHex: n ? dump(args[2], n) : null});
        },
        onLeave: function(){
            var n = (this.len > 0 && this.len <= 512) ? this.len : 0;
            send0({t:'rc4.out', outHex: n ? dump(this.outp, n) : null});
        }
    });

    // libcore!init
    hookExp('init', {
        onEnter: function(args){
            send0({t:'core.init', a0:cstr(args[0],512), a1:cstr(args[1],512), a2:cstr(args[2],512)});
        }
    });

    // ============ dartCallback — 全量 dump (找 NUL, 最多 8192) ============
    try{
        Interceptor.attach(A(0x715844),{
            onEnter:function(){
                var x1 = this.context.x1, x2 = this.context.x2;
                var o = {t:'cb', x2:(''+x2)};
                try{
                    var p = x1.add(7).readPointer();
                    o.ptr = '' + p;
                    var len = parseInt(''+x2, 16) >>> 0;
                    o.lenRaw = len;
                    // NUL 扫描: 先读 512, 若无 NUL 且更长再扩
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
        send0({t:'INFO',msg:'hooked dartCallback full-dump'});
    }catch(e){ send0({t:'INFO',msg:'FAIL dartCallback:'+e}); }

    // ============ _rawCall — action 摘要 ============
    try{
        Interceptor.attach(A(0x6eeca8),{
            onEnter:function(){
                var s = dartStrText(this.context.x1, 8192);
                if (s === null) return;
                var m = s.indexOf('"action":"');
                var act = m >= 0 ? s.substring(m+10, s.indexOf('"', m+10)) : '?';
                if (act === 'api_encrypt' || act === 'api_decrypt' || act.indexOf('token')>=0 || act.indexOf('auth')>=0 || act.indexOf('login')>=0 || act.indexOf('key')>=0){
                    send0({t:'raw.full', act:act, text:s.substring(0, 4096)});
                } else {
                    send0({t:'raw.act', act:act});
                }
            }
        });
        send0({t:'INFO',msg:'hooked _rawCall'});
    }catch(e){ send0({t:'INFO',msg:'FAIL rawCall:'+e}); }

    // markers
    try{
        Interceptor.attach(A(0x7eee0c),{ onEnter:function(){ send0({t:'mark', fn:'apiEncrypt'}); } });
        Interceptor.attach(A(0xabe058),{ onEnter:function(){ send0({t:'mark', fn:'apiDecrypt'}); } });
    }catch(e){}

    // HttpClient.post — URL
    try{
        Interceptor.attach(A(0x6ca174),{
            onEnter:function(){
                var s = dartStrText(this.context.x2, 2048);
                send0({t:'http.post', url:(s ? s.substring(0,512) : null)});
            }
        });
    }catch(e){}

    send0({t:'INFO',msg:'auth5 hooks installed pid='+Process.id});
}, 150);
send0({t:'INFO',msg:'auth5 hook js loaded pid='+Process.id});
