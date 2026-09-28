'use strict';
// auth 生成链运行时抓取: Encrypter/RSA/AES/getRandomString/HeadersInterceptor
// 地址 = libapp.base + vaddr (asm/blutter 约定, 已用 dart_log 校准 base+INSN+dump=vaddr)
function toHex(b){ if(!b) return null; return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }
function hexDump(p, n){ try{ if(!p || p.isNull()) return null; return toHex(p.readByteArray(n)); }catch(e){ return null; } }
function heapOk(p){ try{ if(!p || p.isNull()) return false; var s = p.toString(16); var pfx = parseInt(s.slice(0,4),16); return pfx >= 0x7100 && pfx <= 0x712f; }catch(e){ return false; } }
// OneByteString: 完整读 (len Smi@+8 -> data@+16)
function dartStrFull(p){
    try{
        if(!heapOk(p)) return null;
        var u8 = new Uint8Array(p.readByteArray(24));
        var len = (u8[8] | (u8[9]<<8) | (u8[10]<<16)) >>> 0;   // len Smi 低 3 字节足够 (len<<1)
        len = len >> 1;
        if(len < 0 || len > 8192) return null;
        var data = p.add(16).readByteArray(Math.min(len, 4096));
        return { len: len, hex: toHex(data) };
    }catch(e){ return null; }
}
var done=false;
var poll=setInterval(function(){
    if(done) return; done=true; clearInterval(poll);
    var m=Process.findModuleByName('libapp.so');
    if(!m){ done=false; return; }
    var A = function(v){ return m.base.add(v); };

    // 1) getRandomString onLeave — 会话 key/iv 原文
    try{
        Interceptor.attach(A(0x715cb0),{
            onLeave:function(ret){
                var r = dartStrFull(ret);
                send({t:'grs.leave', ret:(''+ret), len:(r?r.len:null), hex:(r?r.hex:null)});
            }
        });
        send({t:'INFO',msg:'hooked getRandomString @0x715cb0'});
    }catch(e){ send({t:'INFO',msg:'FAIL grs:'+e}); }

    // 2) Encrypter.encrypt onEnter — (this=Encrypter, plaintext, iv?) 深dump
    try{
        Interceptor.attach(A(0x6ef9ac),{
            onEnter:function(){
                send({t:'Enc.encrypt.enter', args:[
                    {r:'x0', v:(''+this.context.x0), hex:hexDump(this.context.x0, 640)},
                    {r:'x1', v:(''+this.context.x1), hex:hexDump(this.context.x1, 320)},
                    {r:'x2', v:(''+this.context.x2), hex:hexDump(this.context.x2, 2048)},
                    {r:'x3', v:(''+this.context.x3), hex:hexDump(this.context.x3, 320)}
                ]});
            },
            onLeave:function(ret){
                var r = dartStrFull(ret);
                send({t:'Enc.encrypt.leave', ret:(''+ret), len:(r?r.len:null), hex:(r?r.hex:null)});
            }
        });
        send({t:'INFO',msg:'hooked Encrypter.encrypt @0x6ef9ac'});
    }catch(e){ send({t:'INFO',msg:'FAIL enc:'+e}); }

    // 3) RSA.encrypt — P0 明文 (key+iv) 直接可见
    try{
        Interceptor.attach(A(0xaba4a8),{
            onEnter:function(){
                send({t:'RSA.encrypt.enter', args:[
                    {r:'x0', v:(''+this.context.x0), hex:hexDump(this.context.x0, 640)},
                    {r:'x1', v:(''+this.context.x1), hex:hexDump(this.context.x1, 2048)},
                    {r:'x2', v:(''+this.context.x2), hex:hexDump(this.context.x2, 2048)}
                ]});
            }
        });
        send({t:'INFO',msg:'hooked RSA.encrypt @0xaba4a8'});
    }catch(e){ send({t:'INFO',msg:'FAIL rsa:'+e}); }

    // 4) AES.encrypt.enter — 密钥参数对象
    try{
        Interceptor.attach(A(0xaba37c),{
            onEnter:function(){
                send({t:'AES.encrypt.enter', args:[
                    {r:'x0', v:(''+this.context.x0), hex:hexDump(this.context.x0, 640)},
                    {r:'x1', v:(''+this.context.x1), hex:hexDump(this.context.x1, 2048)}
                ]});
            }
        });
        send({t:'INFO',msg:'hooked AES.encrypt @0xaba37c'});
    }catch(e){ send({t:'INFO',msg:'FAIL aes:'+e}); }

    // 5) HeadersInterceptor.onRequest(async) — 最终 headers (authentication 值)
    try{
        Interceptor.attach(A(0xa3bdc8),{
            onEnter:function(){
                send({t:'Hdr.onRequest.enter', args:[
                    {r:'x1', v:(''+this.context.x1), hex:hexDump(this.context.x1, 1024)},
                    {r:'x2', v:(''+this.context.x2), hex:hexDump(this.context.x2, 2048)}
                ]});
            },
            onLeave:function(ret){
                send({t:'Hdr.onRequest.leave', ret:(''+ret)});
            }
        });
        send({t:'INFO',msg:'hooked HeadersInterceptor @0xa3bdc8'});
    }catch(e){ send({t:'INFO',msg:'FAIL hdr:'+e}); }

    // 6) apiEncrypt enter/leave — async 上下文深dump (闭包里可能有数据)
    try{
        Interceptor.attach(A(0x7eee0c),{
            onEnter:function(){
                send({t:'apiEncrypt.enter', args:[
                    {r:'x1', v:(''+this.context.x1), hex:hexDump(this.context.x1, 2048)},
                    {r:'x2', v:(''+this.context.x2), hex:hexDump(this.context.x2, 2048)}
                ]});
            },
            onLeave:function(ret){
                send({t:'apiEncrypt.leave', ret:(''+ret)});
            }
        });
        send({t:'INFO',msg:'hooked apiEncrypt @0x7eee0c'});
    }catch(e){ send({t:'INFO',msg:'FAIL apien:'+e}); }

    send({t:'INFO',msg:'auth hooks installed pid='+Process.id});
},200);
send({t:'INFO',msg:'auth hook js loaded pid='+Process.id});
