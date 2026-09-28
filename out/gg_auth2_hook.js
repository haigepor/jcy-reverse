'use strict';
// 第二轮: libcore!call(请求) + dartCallback(响应) + _rawCall + HeadersInterceptor + apiEncrypt
// 字符串解析已修正: tagged指针, len u32@+7, data@+15
function toHex(b){ if(!b) return null; return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }
function heapOk(p){ try{ if(!p || p.isNull()) return false; var s=p.toString(16); var pfx=parseInt(s.slice(0,4),16); return pfx>=0x7100 && pfx<=0x712f; }catch(e){ return false; } }
function dartStrFull(p){
    try{
        if(!heapOk(p)) return null;
        var u8 = new Uint8Array(p.readByteArray(16));
        var len = (u8[7] | (u8[8]<<8) | (u8[9]<<16)) >>> 0;   // len Smi u32 @ tagged+7
        len = len >>> 1;
        if(len < 0 || len > 16384) return { len: -1, hex: null, raw: toHex(p.readByteArray(64)) };
        var data = p.add(15).readByteArray(Math.min(len, 8192));
        return { len: len, hex: toHex(data) };
    }catch(e){ return null; }
}
function hexDump(p, n){ try{ if(!p || p.isNull()) return null; return toHex(p.readByteArray(n)); }catch(e){ return null; } }
function cstr(p, max){ try{ if(!p || p.isNull()) return null; return p.readCString(max || 4096); }catch(e){ return null; } }

var done=false;
var poll=setInterval(function(){
    if(done) return;
    var m=Process.findModuleByName('libapp.so');
    if(!m) return;
    done=true; clearInterval(poll);
    var A=function(v){ return m.base.add(v); };

    // 1) libcore!call — 请求 (b64/qPwC)
    var cm = Process.findModuleByName('libcore.so');
    if(cm){
        var ca = cm.findExportByName('call');
        if(ca){
            Interceptor.attach(ca,{
                onEnter:function(args){
                    send({t:'core.call.enter', s0:cstr(args[0], 4096), a1:(''+args[1])});
                },
                onLeave:function(retval){
                    send({t:'core.call.leave', ret:(''+retval), retstr:cstr(retval, 4096)});
                }
            });
            send({t:'INFO',msg:'hooked libcore!call'});
        }
    }
    // 2) dartCallback @0x715844 — 响应 (x1 = char*)
    try{
        Interceptor.attach(A(0x715844),{
            onEnter:function(args){
                send({t:'dartCallback.enter', x1hex:hexDump(this.context.x1, 2048), x1str:cstr(this.context.x1, 4096)});
            }
        });
        send({t:'INFO',msg:'hooked dartCallback @0x715844'});
    }catch(e){ send({t:'INFO',msg:'FAIL dartCallback:'+e}); }

    // 3) _rawCall @0x6eeca8 — Dart 侧请求字符串 (x1)
    try{
        Interceptor.attach(A(0x6eeca8),{
            onEnter:function(){
                var r = dartStrFull(this.context.x1);
                send({t:'rawCall.enter', x1v:(''+this.context.x1), len:(r?r.len:null), hex:(r?r.hex:null), raw:(r?r.raw:null)});
            }
        });
        send({t:'INFO',msg:'hooked _rawCall @0x6eeca8'});
    }catch(e){ send({t:'INFO',msg:'FAIL rawCall:'+e}); }

    // 4) HeadersInterceptor async onRequest — 深dump x2 (RequestOptions, headers map)
    try{
        Interceptor.attach(A(0xa3bdc8),{
            onEnter:function(){
                send({t:'Hdr.onRequest.enter', x1hex:hexDump(this.context.x1, 4096), x2hex:hexDump(this.context.x2, 4096)});
            },
            onLeave:function(ret){
                send({t:'Hdr.onRequest.leave', ret:(''+ret)});
            }
        });
        send({t:'INFO',msg:'hooked HeadersInterceptor @0xa3bdc8'});
    }catch(e){ send({t:'INFO',msg:'FAIL hdr:'+e}); }

    // 5) apiEncrypt/apiDecrypt — 返回值用修正解析
    try{
        Interceptor.attach(A(0x7eee0c),{
            onEnter:function(){ send({t:'apiEncrypt.enter'}); },
            onLeave:function(ret){
                var r = dartStrFull(ret);
                send({t:'apiEncrypt.leave', retv:(''+ret), len:(r?r.len:null), hex:(r?r.hex:null), raw:(r?r.raw:null)});
            }
        });
        send({t:'INFO',msg:'hooked apiEncrypt @0x7eee0c'});
    }catch(e){ send({t:'INFO',msg:'FAIL apien:'+e}); }
    try{
        Interceptor.attach(A(0xabe058),{
            onEnter:function(){ send({t:'apiDecrypt.enter'}); },
            onLeave:function(ret){
                var r = dartStrFull(ret);
                send({t:'apiDecrypt.leave', retv:(''+ret), len:(r?r.len:null), hex:(r?r.hex:null), raw:(r?r.raw:null)});
            }
        });
        send({t:'INFO',msg:'hooked apiDecrypt @0xabe058'});
    }catch(e){ send({t:'INFO',msg:'FAIL apidec:'+e}); }

    // 6) HttpClient.post — 最终请求 (URL/body)
    try{
        Interceptor.attach(A(0x6ca174),{
            onEnter:function(){
                send({t:'http.post.enter', x1hex:hexDump(this.context.x1, 2048), x2hex:hexDump(this.context.x2, 2048)});
            }
        });
        send({t:'INFO',msg:'hooked HttpClient.post @0x6ca174'});
    }catch(e){ send({t:'INFO',msg:'FAIL httppost:'+e}); }

    send({t:'INFO',msg:'auth2 hooks installed pid='+Process.id});
},200);
send({t:'INFO',msg:'auth2 hook js loaded pid='+Process.id});
