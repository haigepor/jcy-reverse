'use strict';
// 第三轮: dartCallback x1 = FFI Pointer 对象, +8 = native 地址 -> 响应 C 字符串
function toHex(b){ if(!b) return null; return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }
function heapOk(p){ try{ if(!p || p.isNull()) return false; var s=p.toString(16); var pfx=parseInt(s.slice(0,4),16); return pfx>=0x7100 && pfx<=0x712f; }catch(e){ return false; } }
function dartStrFull(p){
    try{
        if(!heapOk(p)) return null;
        var u8 = new Uint8Array(p.readByteArray(16));
        var len = (u8[7] | (u8[8]<<8) | (u8[9]<<16)) >>> 0;
        len = len >>> 1;
        if(len < 0 || len > 16384) return null;
        return { len: len, hex: toHex(p.add(15).readByteArray(Math.min(len, 8192))) };
    }catch(e){ return null; }
}
function hexDump(p, n){ try{ if(!p || p.isNull()) return null; return toHex(p.readByteArray(n)); }catch(e){ return null; } }
function cstr(p, max){ try{ if(!p || p.isNull()) return null; return p.readCString(max || 8192); }catch(e){ return null; } }

var done=false;
var poll=setInterval(function(){
    if(done) return;
    var m=Process.findModuleByName('libapp.so');
    if(!m) return;
    done=true; clearInterval(poll);
    var A=function(v){ return m.base.add(v); };

    // 1) dartCallback — x1 Pointer 对象: native addr = u64 @ +8 (也兼容 +0x10/+0x18)
    try{
        Interceptor.attach(A(0x715844),{
            onEnter:function(args){
                var out = { t:'dartCallback.enter', x1v:(''+this.context.x1) };
                try{
                    var p = this.context.x1;
                    var dump = p.readByteArray(32);
                    var u8 = new Uint8Array(dump);
                    var ptrs = [];
                    for(var off=8; off<=24; off+=8){
                        var lo = u8[off]|(u8[off+1]<<8)|(u8[off+2]<<16)|(u8[off+3]<<24);
                        var hi = u8[off+4]|(u8[off+5]<<8)|(u8[off+6]<<16)|(u8[off+7]<<24);
                        if((hi>>>0) >= 0x70 && (hi>>>0) <= 0x7f){
                            var addr = ptr(lo + (hi*4294967296));
                            var s = cstr(addr, 16384);
                            if(s && s.length > 3){
                                ptrs.push({off:off, addr:(''+addr), str:s.substring(0, 16384)});
                            }
                        }
                    }
                    out.ptrs = ptrs;
                    out.x1head = toHex(dump);
                }catch(e){ out.err = ''+e; }
                send(out);
            }
        });
        send({t:'INFO',msg:'hooked dartCallback (pointer deref)'});
    }catch(e){ send({t:'INFO',msg:'FAIL dartCallback:'+e}); }

    // 2) _rawCall — 明文请求
    try{
        Interceptor.attach(A(0x6eeca8),{
            onEnter:function(){
                var r = dartStrFull(this.context.x1);
                send({t:'rawCall.enter', len:(r?r.len:null), hex:(r?r.hex:null)});
            }
        });
        send({t:'INFO',msg:'hooked _rawCall'});
    }catch(e){ send({t:'INFO',msg:'FAIL rawCall:'+e}); }

    // 3) libcore!call — 请求密文
    var cm = Process.findModuleByName('libcore.so');
    if(cm){
        var ca = cm.findExportByName('call');
        if(ca){
            Interceptor.attach(ca,{
                onEnter:function(args){
                    send({t:'core.call.enter', s0:cstr(args[0], 8192)});
                }
            });
            send({t:'INFO',msg:'hooked libcore!call'});
        }
    }

    // 4) apiEncrypt/apiDecrypt leave — 返回值 (Map) dump 深一点
    try{
        Interceptor.attach(A(0x7eee0c),{
            onEnter:function(){ send({t:'apiEncrypt.enter'}); },
            onLeave:function(ret){
                send({t:'apiEncrypt.leave', retv:(''+ret), retHex:hexDump(ret, 1024)});
            }
        });
        send({t:'INFO',msg:'hooked apiEncrypt'});
    }catch(e){ send({t:'INFO',msg:'FAIL apien:'+e}); }

    send({t:'INFO',msg:'auth3 hooks installed pid='+Process.id});
},200);
send({t:'INFO',msg:'auth3 hook js loaded pid='+Process.id});
