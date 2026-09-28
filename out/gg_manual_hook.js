'use strict';
var INSN = 0x4b6b40;
function toHex(b){ if(!b) return null; return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }
function dartStr(p){
    try{
        if(p.isNull()) return null;
        if(parseInt(p.toString(16).slice(0,4),16)!==0x7100) return null;
        var len = p.add(8).readU32() >>> 1;
        if(len<2||len>65536) return null;
        var b = p.add(16).readByteArray(Math.min(len,900));
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
        if(seen.indexOf(p.toString())>=0) return; seen.push(p.toString());
        var blk = p.readByteArray(600);
        var u8 = new Uint8Array(blk);
        for(var off=0; off+8<=u8.length; off+=4){
            var lo = (u8[off]|(u8[off+1]<<8)|(u8[off+2]<<16)|(u8[off+3]<<24))>>>0;
            var hi = (u8[off+4]|(u8[off+5]<<8)|(u8[off+6]<<16)|(u8[off+7]<<24))>>>0;
            if(lo >= 0x01000000 && hi === 0){
                var s = dartStr(ptr('0x7100000000').add(lo));
                if(s && out.indexOf(s)<0) out.push(s);
            }
        }
        if(depth<2){
            for(var o2=0; o2+8<=u8.length; o2+=4){
                var lo2 = (u8[o2]|(u8[o2+1]<<8)|(u8[o2+2]<<16)|(u8[o2+3]<<24))>>>0;
                var hi2 = (u8[o2+4]|(u8[o2+5]<<8)|(u8[o2+6]<<16)|(u8[o2+7]<<24))>>>0;
                if(lo2 >= 0x01000000 && hi2 === 0 && lo2 < 0x3000000){
                    chase(ptr('0x7100000000').add(lo2), depth+1, out, seen);
                }
            }
        }
    }catch(e){}
}
function chaseArgs(ctx){
    var out=[];
    for(var i=0;i<8;i++){ try{ chase(ctx['x'+i], 0, out, []); }catch(e){} }
    return out.slice(0,40);
}
var libapp=null;
function hookDart(off,label,useChase){
    var m=Process.findModuleByName('libapp.so');
    if(!m){ return false; }
    var a=m.base.add(INSN).add(off);
    try{
        Interceptor.attach(a,{
            onEnter:function(){ send({t:label+'.enter', strs: useChase?chaseArgs(this.context):null, direct:(function(){var o=[];for(var i=0;i<8;i++){try{var s=dartStr(this.context['x'+i]);if(s)o.push(s);}catch(e){}}return o.slice(0,10);}).call(this)}); },
            onLeave:function(){ send({t:label+'.leave', strs: useChase?chaseArgs(this.context):null}); }
        });
        send({t:'INFO',msg:'hooked '+label});
        return true;
    }catch(e){ send({t:'INFO',msg:'CANNOT '+label+': '+e}); return true; }
}
var dartDone=false;
var poll=setInterval(function(){
    if(dartDone) { clearInterval(poll); return; }
    if(!Process.findModuleByName('libapp.so')) return;
    dartDone=true; clearInterval(poll);
    hookDart(0xbb4600,'encClosure',true);
    hookDart(0xbb4998,'decClosure',true);
    hookDart(0x603968,'RSA.encrypt',true);
    hookDart(0x58507c,'TokenInterceptor.onRequest',true);
    hookDart(0x213634,'HttpClient.post',true);
    hookDart(0x3382cc,'apiEncrypt',true);
    hookDart(0x607518,'apiDecrypt',true);
    var m=Process.findModuleByName('libapp.so');
    Interceptor.attach(m.base.add(INSN).add(0x238e6c),{
        onEnter:function(){ send({t:'Encrypter.encrypt.enter'}); }
    });
    send({t:'INFO',msg:'all dart hooks installed'});
},200);
['libloader.so'].forEach(function(ln){
    var poll2=setInterval(function(){
        var m=Process.findModuleByName(ln);
        if(!m) return;
        clearInterval(poll2);
        ['call','reload'].forEach(function(fn){
            var a=m.findExportByName(fn);
            if(!a) return;
            Interceptor.attach(a,{
                onEnter:function(args){
                    var s0=null;
                    try{s0=args[0].readCString(2000);}catch(e){}
                    send({t:ln+'!'+fn+'.enter', a0:(''+args[0]), s0:s0});
                },
                onLeave:function(ret){
                    var s=null;
                    try{s=ret.readCString(2000);}catch(e){}
                    send({t:ln+'!'+fn+'.leave', ret:(''+ret), retstr:s});
                }
            });
            send({t:'INFO',msg:'hooked '+ln+'!'+fn});
        });
    },200);
});
send({t:'INFO',msg:'manual hook js loaded pid='+Process.id});
