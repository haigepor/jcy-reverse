// raw hex dumps, python-side parse
'use strict';
var INSN = 0x4b6b40;
function toHex(b){ if(!b) return null; return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }
function dumpRegs(cpu){
    var out=[];
    for(var i=0;i<8;i++){
        try{
            var r=cpu['x'+i];
            var rec={r:'x'+i, v:r.toString()};
            try{ rec.hex=toHex(r.readByteArray(640)); }catch(e){}
            out.push(rec);
        }catch(e){}
    }
    return out;
}
var libapp=null, done=false;
var poll=setInterval(function(){
    if(done){clearInterval(poll);return;}
    libapp=Process.findModuleByName('libapp.so');
    if(!libapp) return;
    done=true; clearInterval(poll);
    [[0x213634,'HttpClient.post'],[0xa3bdc8,'HeadersInterceptor.onRequest'],[0x58507c,'TokenInterceptor.onRequest'],[0x607518,'apiDecrypt'],[0x3382cc,'apiEncrypt']].forEach(function(t){
        var a=libapp.base.add(INSN).add(t[0]);
        try{
            Interceptor.attach(a,{
                onEnter:function(args){ send({t:t[1]+'.enter', args:dumpRegs(this.context)}); }
            });
            send({t:'INFO',msg:'hooked '+t[1]});
        }catch(e){ send({t:'INFO',msg:'FAIL '+t[1]+':'+e}); }
    });
},200);
send({t:'INFO',msg:'hook3 loaded pid='+Process.id});
