'use strict';
var INSN = 0x4b6b40;
function toHex(b){ if(!b) return null; return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }
// read Dart OneByteString/TwoByteString data starting at +16 until end of object data
function dartStrFull(p){
    try{
        if(p.isNull()) return null;
        var pfx = parseInt(p.toString(16).slice(0,4),16);
        if(!(pfx >= 0x7100 && pfx <= 0x712f)) return null;
        var b = p.readByteArray(40);
        var u8 = new Uint8Array(b);
        // OneByteString: tags@0-3, hash@4-7, len Smi32@8-11, pad, data@16
        var len1 = u8[8] | (u8[9]<<8) | (u8[10]<<16) | (u8[11]<<24);
        var start = 16;
        var s = '', n = 0;
        for(var i = start; i < start + Math.min((len1>>1), 200) && i < u8.length; i++){
            var c = u8[i];
            if(c >= 32 && c < 127){ s += String.fromCharCode(c); n++; }
            else if(c === 0 && n > 0){ /* two-byte gap */ }
            else { break; }
        }
        return { len: (len1>>1), s: s };
    }catch(e){ return null; }
}
function hexDump(a){
    try{ return toHex(a.readByteArray(1600)); }catch(e){ return null; }
}
var done=false;
var poll=setInterval(function(){
    if(done){clearInterval(poll);return;}
    var m=Process.findModuleByName('libapp.so');
    if(!m) return;
    done=true; clearInterval(poll);
    // 1) getRandomString leave — returns the random key/iv string
    try{
        Interceptor.attach(m.base.add(INSN).add(0x715cb0),{
            onLeave:function(ret){
                var r = dartStrFull(ret);
                send({t:'getRandomString.leave', ret:(''+ret), str:(r?r.s:null), len:(r?r.len:null)});
            }
        });
        send({t:'INFO',msg:'hooked getRandomString'});
    }catch(e){ send({t:'INFO',msg:'FAIL grs:'+e}); }
    // 2) apiDecrypt.enter — response ciphertext + url (hex dumps)
    try{
        Interceptor.attach(m.base.add(INSN).add(0x607518),{
            onEnter:function(){
                send({t:'apiDecrypt.enter', args:[
                    {r:'x1', hex:hexDump(this.context.x1)},
                    {r:'x2', hex:hexDump(this.context.x2)}
                ]});
            }
        });
        send({t:'INFO',msg:'hooked apiDecrypt'});
    }catch(e){ send({t:'INFO',msg:'FAIL apidec:'+e}); }
    // 3) libloader call — full request/response frames
    var lm = Process.findModuleByName('libloader.so');
    if(lm){
        var ca = lm.findExportByName('call');
        if(ca){
            Interceptor.attach(ca,{
                onEnter:function(args){ var s=null; try{s=args[0].readCString(3000);}catch(e){} send({t:'sig.call.enter', s0:s}); },
                onLeave:function(ret){ var s=null; try{s=ret.readCString(3000);}catch(e){} send({t:'sig.call.leave', retstr:s}); }
            });
            send({t:'INFO',msg:'hooked libloader!call'});
        }
    }
    send({t:'INFO',msg:'key hooks installed pid='+Process.id});
},200);
send({t:'INFO',msg:'key hook js loaded pid='+Process.id});
