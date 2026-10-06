'use strict';
/* hook_call.js - 挂 libcore.so!call 入口/出口, 抓 FFI 信封原文 */
var m = Process.findModuleByName ? Process.findModuleByName('libcore.so') : null;
if (!m && Process.getModuleByName) { try { m = Process.getModuleByName('libcore.so'); } catch (e) {} }
var base = m ? m.base : (typeof Module.findBaseAddress === 'function' ? Module.findBaseAddress('libcore.so') : null);
if (!base) { send({type:'err', msg:'libcore.so not found'}); } else {
    send({type:'info', msg:'libcore base=' + base});
    var callf = base.add(0x307a38);
    Interceptor.attach(callf, {
        onEnter: function(args) {
            try {
                var s = args[0].readCString(65536);
                send({type:'call_in', s: s});
            } catch (e) { send({type:'err', msg:'in:' + e}); }
        },
        onLeave: function(retval) {
            try {
                var p = this.context.x0;
                var s = p.readCString(262144);
                send({type:'call_out', s: s});
            } catch (e) { send({type:'err', msg:'out:' + e}); }
        }
    });
    send({type:'info', msg:'hooked call@' + callf});
}
