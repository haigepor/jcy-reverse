'use strict';
var INSN = 0x4b6b40;
function toHex(b){ if(!b) return null; return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join(''); }
function dumpRegs(cpu){
    var out=[];
    for(var i=0;i<4;i++){
        try{
            var r=cpu['x'+i];
            var rec={r:'x'+i, v:r.toString()};
            try{ rec.hex=toHex(r.readByteArray(1600)); }catch(e){}
            out.push(rec);
        }catch(e){}
    }
    return out;
}
var done=false;
var poll=setInterval(function(){
    if(done){clearInterval(poll);return;}
    var m=Process.findModuleByName('libapp.so');
    if(!m) return;
    done=true; clearInterval(poll);
    [[0x607518,'apiDecrypt'],[0x3382cc,'apiEncrypt'],[0x213634,'HttpClient.post'],[0xa3bdc8,'HeadersInterceptor']].forEach(function(t){
        try{
            Interceptor.attach(m.base.add(INSN).add(t[0]),{
                onEnter:function(){ send({t:t[1]+'.enter', args:dumpRegs(this.context)}); }
            });
            send({t:'INFO',msg:'hooked '+t[1]});
        }catch(e){ send({t:'INFO',msg:'FAIL '+t[1]+':'+e}); }
    });
},200);
send({t:'INFO',msg:'hex hook loaded pid='+Process.id});
