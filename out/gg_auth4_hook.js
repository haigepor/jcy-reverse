'use strict';
// 第四轮: libcore.so native 加密原语全量 hook (密钥捕获) + dartCallback 修正偏移(x1+7)
// 目标: 拿到 native 层真实 AES key/IV (auth 生成 / P0.P1 响应解密 / 会话密钥) + 响应明文
var MAXSEND = 6000;
var SENT = 0;
function send0(o){ if (SENT < MAXSEND){ SENT++; send(o); } }

function toHex(b){ if(!b) return null; try { return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }catch(e){ return null; } }
function dump(p, n){ try{ if(!p || p.isNull()) return null; return toHex(p.readByteArray(n)); }catch(e){ return null; } }
function cstr(p, max){ try{ if(!p || p.isNull()) return null; return p.readCString(max || 4096); }catch(e){ return null; } }
function u32(p, off){ try{ return p.add(off).readU32(); }catch(e){ return null; } }
function u64(p, off){ try{ return p.add(off).readU64(); }catch(e){ return null; } }

function heapOk(p){ try{ if(!p || p.isNull()) return false; var s=p.toString(16); var pfx=parseInt(s.slice(0,4),16); return pfx>=0x7100 && pfx<=0x712f; }catch(e){ return false; } }
// OneByteString: len Smi u32 @ tagged+7, data @ tagged+15
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
            var a = Module.getExportByName('libcore.so', name);
            Interceptor.attach(a, handlers);
            send0({t:'INFO', msg:'hooked '+name});
        }catch(e){ send0({t:'INFO', msg:'SKIP '+name+': '+e}); }
    }

    // ============ A. key setup: (userKey, bits, KEY*) ============
    ['AES_set_encrypt_key','AES_set_decrypt_key','aes_v8_set_encrypt_key','aes_v8_set_decrypt_key','vpaes_set_encrypt_key','vpaes_set_decrypt_key'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                var bits = args[1].toInt();
                var n = (bits === 128 || bits === 192 || bits === 256) ? bits/8 : 16;
                send0({t:'ks', fn:name, bits:bits, key:dump(args[0], n)});
            }
        });
    });

    // ============ B. EVP_CipherInit_ex(ctx, cipher, impl, key, iv, enc) ============
    hookExp('EVP_CipherInit_ex', {
        onEnter: function(args){
            var o = {t:'evp.init', enc:args[5].toInt()};
            try{
                var c = args[1];
                if (c && !c.isNull()){
                    o.nid = c.readU32 ? null : null;
                    o.nid = u32(c, 0);
                    o.block = u32(c, 4);
                    o.keylen = u32(c, 8);
                    o.ivlen = u32(c, 12);
                }
            }catch(e){}
            o.key = args[3].isNull() ? null : dump(args[3], (o.keylen && o.keylen<=32) ? o.keylen : 16);
            o.iv  = args[4].isNull() ? null : dump(args[4], (o.ivlen && o.ivlen<=16) ? o.ivlen : 16);
            send0(o);
        }
    });

    // ============ C. EVP *_Update(ctx, out, outl, in, inl) ============
    ['EVP_EncryptUpdate','EVP_DecryptUpdate'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.outp = args[1]; this.outlp = args[2];
                this.inl = args[4].toInt();
                var n = (this.inl > 0 && this.inl <= 4096) ? this.inl : (this.inl > 4096 ? 4096 : 0);
                send0({t:'evp.update', fn:name, inl:this.inl, inHex: n ? dump(args[3], n) : null});
            },
            onLeave: function(ret){
                try{
                    var outl = this.outlp.readU32();
                    var n = (outl > 0 && outl <= 4096) ? outl : 0;
                    send0({t:'evp.update.out', fn:this.fn || '', outl:outl, outHex: n ? dump(this.outp, n) : null});
                }catch(e){}
            }
        });
    });

    // ============ D. one-shot CBC: (in, out, len, KEY*, ivec, enc) ============
    ['AES_cbc_encrypt','aes_v8_cbc_encrypt','vpaes_cbc_encrypt'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.outp = args[1]; this.len = args[2].toInt();
                this.fn = name;
                var n = (this.len > 0 && this.len <= 4096) ? this.len : 0;
                send0({t:'cbc', fn:name, len:this.len, enc:args[5].toInt(), inHex: n ? dump(args[0], n) : null, iv0:dump(args[4],16)});
            },
            onLeave: function(){
                var n = (this.len > 0 && this.len <= 4096) ? this.len : 0;
                send0({t:'cbc.out', fn:this.fn, outHex: n ? dump(this.outp, n) : null});
            }
        });
    });

    // ============ E. RSA: (flen, from, to, rsa, pad) ============
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

    // ============ F. RAND_bytes(buf, num) ============
    hookExp('RAND_bytes', {
        onEnter: function(args){ this.buf = args[0]; this.num = args[1].toInt(); },
        onLeave: function(){
            var n = (this.num > 0 && this.num <= 64) ? this.num : 0;
            send0({t:'rand', num:this.num, val: n ? dump(this.buf, n) : null});
        }
    });

    // ============ G. 摘要 ============
    ['MD5','SHA1','SHA256'].forEach(function(name){
        hookExp(name, {
            onEnter: function(args){
                this.md = args[2]; this.fn = name;
                var n = args[1].toInt();
                var capn = (n > 0 && n <= 512) ? n : 0;
                send0({t:'hash', fn:name, len:n, dataHex: capn ? dump(args[0], capn) : null});
            },
            onLeave: function(){
                var hl = this.fn === 'SHA256' ? 32 : (this.fn === 'SHA1' ? 20 : 16);
                send0({t:'hash.out', fn:this.fn, md:dump(this.md, hl)});
            }
        });
    });

    // ============ H. HMAC(evp_md, key, key_len, d, n, md, md_len) ============
    hookExp('HMAC', {
        onEnter: function(args){
            this.md = args[5]; this.fn = 'HMAC';
            var klen = args[2].toInt();
            var kn = (klen > 0 && klen <= 64) ? klen : 0;
            var n = args[4].toInt();
            var dn = (n > 0 && n <= 512) ? n : 0;
            send0({t:'hmac', klen:klen, keyHex: kn ? dump(args[1], kn) : null, dlen:n, dataHex: dn ? dump(args[3], dn) : null});
        },
        onLeave: function(){
            send0({t:'hmac.out', md:dump(this.md, 32)});
        }
    });

    // ============ I. libcore init / call ============
    hookExp('init', {
        onEnter: function(args){
            send0({t:'core.init', a0:cstr(args[0],512), a1:cstr(args[1],512), a2:cstr(args[2],512)});
        }
    });

    // ============ J. dartCallback @0x715844 — 修正: native ptr @ x1+7, len 疑似 x2 ============
    try{
        Interceptor.attach(A(0x715844),{
            onEnter:function(){
                var x0 = this.context.x0, x1 = this.context.x1, x2 = this.context.x2;
                var o = {t:'cb', x0:(''+x0), x2:(''+x2)};
                try{
                    var p = x1.add(7).readPointer();
                    o.ptr = '' + p;
                    var len = x2.toUInt32 ? x2.toUInt32() : parseInt(''+x2);
                    o.lenRaw = len;
                    var smi = (len & 1) ? (len - 1) >>> 1 : (len >>> 1);
                    o.lenSmi = smi;
                    var use = (len > 0 && len <= 65536) ? len : (smi > 0 && smi <= 65536 ? smi : 256);
                    o.use = use;
                    o.hex = dump(p, Math.min(use, 8192));
                }catch(e){ o.err = ''+e; }
                send0(o);
            }
        });
        send0({t:'INFO',msg:'hooked dartCallback @0x715844 (offset x1+7)'});
    }catch(e){ send0({t:'INFO',msg:'FAIL dartCallback:'+e}); }

    // ============ K. _rawCall @0x6eeca8 — 仅 action 摘要 (api_* 帧全量) ============
    try{
        Interceptor.attach(A(0x6eeca8),{
            onEnter:function(){
                var s = dartStrText(this.context.x1, 8192);
                if (s === null) return;
                var m = s.indexOf('"action":"');
                var act = m >= 0 ? s.substring(m+10, s.indexOf('"', m+10)) : '?';
                if (act === 'api_encrypt' || act === 'api_decrypt' || act.indexOf('token') >= 0 || act.indexOf('key') >= 0 || act.indexOf('auth') >= 0 || act.indexOf('login') >= 0 || act.indexOf('session') >= 0){
                    send0({t:'raw.full', act:act, text:s.substring(0, 4096)});
                } else {
                    send0({t:'raw.act', act:act});
                }
            }
        });
        send0({t:'INFO',msg:'hooked _rawCall @0x6eeca8 (compact)'});
    }catch(e){ send0({t:'INFO',msg:'FAIL rawCall:'+e}); }

    // ============ L. apiEncrypt/apiDecrypt/api 标记 ============
    try{
        Interceptor.attach(A(0x7eee0c),{ onEnter:function(){ send0({t:'mark', fn:'apiEncrypt'}); } });
        Interceptor.attach(A(0xabe058),{ onEnter:function(){ send0({t:'mark', fn:'apiDecrypt'}); } });
        send0({t:'INFO',msg:'hooked apiEncrypt/apiDecrypt markers'});
    }catch(e){ send0({t:'INFO',msg:'FAIL markers:'+e}); }

    // ============ M. HttpClient.post — URL 关联 ============
    try{
        Interceptor.attach(A(0x6ca174),{
            onEnter:function(){
                var s = dartStrText(this.context.x2, 2048);
                send0({t:'http.post', url:(s ? s.substring(0, 512) : null), x2hex:dump(this.context.x2, 512)});
            }
        });
        send0({t:'INFO',msg:'hooked HttpClient.post @0x6ca174'});
    }catch(e){ send0({t:'INFO',msg:'FAIL httppost:'+e}); }

    send0({t:'INFO',msg:'auth4 hooks installed pid='+Process.id});
}, 150);
send0({t:'INFO',msg:'auth4 hook js loaded pid='+Process.id});
