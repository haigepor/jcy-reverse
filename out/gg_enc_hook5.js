'use strict';
var INSN = 0x4b6b40;
function toHex(b){ if(!b) return null; return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }
function dartStr(p){
    try{
        if(p.isNull()) return null;
        if(parseInt(p.toString(16).slice(0,4),16)!==0x7100) return null;
        var len = p.add(8).readU32() >>> 1;
        if(len<2||len>65536) return null;
        var b = p.add(16).readByteArray(Math.min(len,800));
        var u8=new Uint8Array(b), s='';
        for(var i=0;i<u8.length;i++){var c=u8[i];
            if(c>=32&&c<127)s+=String.fromCharCode(c);
            else if(c===10||c===13)s+=' ';
            else if(c>=0x80)s+='?';
            else return null;}
        return s;
    }catch(e){return null;}
}
function chase(p, depth, out, seen){
    try{
        if(p.isNull()||depth>2) return;
        if(parseInt(p.toString(16).slice(0,4),16)!==0x7100) return;
        var key = p.toString();
        if(seen.indexOf(key)>=0) return; seen.push(key);
        var blk = p.readByteArray(560);
        var u8 = new Uint8Array(blk);
        for(var off=0; off+8<=u8.length; off+=4){
            var lo = (u8[off]|(u8[off+1]<<8)|(u8[off+2]<<16)|(u8[off+3]<<24))>>>0;
            var hi = (u8[off+4]|(u8[off+5]<<8)|(u8[off+6]<<16)|(u8[off+7]<<24))>>>0;
            if(lo >= 0x01000000 && hi === 0){
                var cand = ptr('0x7100000000').add(lo);
                var s = dartStr(cand);
                if(s && out.indexOf(s)<0) out.push(s);
            }
        }
        // recurse into first few pointers
        if(depth<2){
            for(var off2=0; off2+8<=u8.length && depth+1<=2; off2+=4){
                var lo2 = (u8[off2]|(u8[off2+1]<<8)|(u8[off2+2]<<16)|(u8[off2+3]<<24))>>>0;
                var hi2 = (u8[off2+4]|(u8[off2+5]<<8)|(u8[off2+6]<<16)|(u8[off2+7]<<24))>>>0;
                if(lo2 >= 0x01000000 && hi2 === 0 && lo2 < 0x2000000){
                    chase(ptr('0x7100000000').add(lo2), depth+1, out, seen);
                }
            }
        }
    }catch(e){}
}
var libapp=null;
function hookFn(off,label){
    var a=libapp.base.add(INSN).add(off);
    try{ Interceptor.attach(a,{
        onEnter:function(){
            var out=[];
            for(var i=0;i<8;i++){ try{ chase(this.context['x'+i], 0, out, []); }catch(e){} }
            send({t:label+'.enter', strs: out.slice(0,30)});
        },
        onLeave:function(){
            var out=[];
            for(var i=0;i<8;i++){ try{ chase(this.context['x'+i], 0, out, []); }catch(e){} }
            send({t:label+'.leave', strs: out.slice(0,30)});
        }
    }); send({t:'INFO',msg:'hooked '+label+' @'+a});
    }catch(e){ send({t:'INFO',msg:'CANNOT hook '+label+': '+e}); }
}
var dartInstalled = false;
function installDartHooks(){
    if(dartInstalled) return true;
    libapp = Process.findModuleByName('libapp.so');
    if(!libapp) return false;
    dartInstalled = true;
    hookFn(0xbb4600,'encClosure');
    hookFn(0xbb4998,'decClosure');
    hookFn(0x603968,'RSA.encrypt');
    hookFn(0x58507c,'TokenInterceptor.onRequest');
    hookFn(0x213634,'HttpClient.post');
    return true;
}
var dartPoll = setInterval(installDartHooks, 300);
var btHookDone=false;
var btPoll = setInterval(function(){
    var m = Process.findModuleByName('libapp.so');
    if(!m) return;
    clearInterval(btPoll);
    Interceptor.attach(m.base.add(INSN).add(0x238e6c), {
        onEnter: function(){
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0,6).map(function(a){
                var rel = a.sub(m.base);
                return a.toString()+'(libapp+'+rel.toString(16)+')';
            });
            send({t:'Encrypter.encrypt.enter', bt: bt});
        }
    });
    send({t:'INFO',msg:'backtrace hook installed'});
}, 80);
