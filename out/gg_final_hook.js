'use strict';
var INSN = 0x4b6b40;

function toHex(b){ if(!b) return null; return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }
function dartStr(p){
    try{
        if(p.isNull()) return null;
        if(parseInt(p.toString(16).slice(0,4),16)!==0x7100) return null;
        var len = p.add(8).readU32() >>> 1;
        if(len<2||len>65536) return null;
        var b = p.add(16).readByteArray(Math.min(len,700));
        var u8=new Uint8Array(b), s='';
        for(var i=0;i<u8.length;i++){var c=u8[i];
            if(c>=32&&c<127)s+=String.fromCharCode(c);
            else if(c===10||c===13)s+=' ';
            else if(c>=0x80)s+='?';
            else return null;}
        return s;
    }catch(e){return null;}
}
function dumpStrs(cpu){
    var out={};
    for(var i=0;i<8;i++){
        try{var r=cpu['x'+i];var s=dartStr(r);if(s)out['x'+i]=s.substring(0,500);}catch(e){}
    }
    return out;
}
var libapp=Process.findModuleByName('libapp.so');
function hookDart(off,label){
    var a=libapp.base.add(INSN).add(off);
    try{
        Interceptor.attach(a,{onEnter:function(){send({t:label+'.enter',strs:dumpStrs(this.context)});}});
        send({t:'INFO',msg:'hooked '+label+' @'+a});
    }catch(e){send({t:'INFO',msg:'FAIL '+label+':'+e});}
}
hookDart(0x3382cc,'FFIUtils.apiEncrypt');
hookDart(0x607518,'FFIUtils.apiDecrypt');
hookDart(0x58507c,'TokenInterceptor.onRequest');
hookDart(0x213634,'HttpClient.post');

function hookNative(libname,fnames){
    var m=Process.findModuleByName(libname);
    if(!m){send({t:'INFO',msg:libname+' absent'});return;}
    fnames.forEach(function(fn){
        var a=m.findExportByName(fn);
        if(!a)return;
        Interceptor.attach(a,{
            onEnter:function(args){
                this.tid=Process.getCurrentThreadId();
                var rec={t:libname+'!'+fn+'.enter',tid:this.tid,a0:args[0].toString(),a1:args[1].toString(),a2:args[2].toString(),a3:args[3].toString()};
                var s0=null,s1=null;
                try{s0=args[0].readCString(600);}catch(e){}
                if(!s0||!/[\x20-\x7e]{6,}/.test(s0.substring(0,20))){try{s0=toHex(args[0].readByteArray(64));}catch(e){}}
                try{s1=args[1].readCString(300);}catch(e){}
                if(s0)rec.s0=s0.substring(0,600);
                if(s1&&/[\x20-\x7e]{4,}/.test(s1.substring(0,10)))rec.s1=s1.substring(0,200);
                send(rec);
            },
            onLeave:function(ret){
                var s=null;
                try{s=ret.readCString(200);}catch(e){}
                send({t:libname+'!'+fn+'.leave',tid:this.tid,ret:ret.toString(),retstr:s?s.substring(0,200):null});
            }
        });
        send({t:'INFO',msg:'hooked '+libname+'!'+fn+' @'+a});
    });
}
hookNative('libcore.so',['init','call']);
hookNative('libloader.so',['call','reload']);
