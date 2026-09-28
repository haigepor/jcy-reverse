# -*- coding: utf-8 -*-
# houdini 下 native hook 触发实验 (第三节步骤1)
# 目的: 在 x86_64+houdini 模拟器上, 对 ARM64 libcore.so 的导出 AES_set_encrypt_key
#       挂 Interceptor, 观察 onEnter 是否触发; 同时验证 Memory.readByteArray 直读 ARM 段.
# 对照组: x86_64 原生库 (libc.so malloc) 挂 Interceptor 必须触发, 用于区分
#         "Interceptor 在本进程整体失效" vs "仅 ARM 转译函数不触发".
# 用法: python out/fs_hook1.py
import sys, time, json
import frida

PKG = 'com.tudou.tool'
RUN_SECONDS = 75

JS = r'''
var log = [];
function rec(m){ log.push(m); send(m); }

var state = { libcoreBase: null, hooked: false, armHits: 0, x86Hits: 0,
              armAttachErr: null, memReadOk: null, dlopenSeen: 0, armAddr: null };

// ---- 对照 A: x86_64 原生 libc.so malloc ----
try {
  var libc = Process.findModuleByName('libc.so');
  rec('[libc] ' + (libc ? (libc.base + ' size=' + libc.size) : 'null'));
  var mp = libc ? libc.findExportByName('malloc') : null;
  rec('[libc] malloc=' + mp);
  if (mp) { Interceptor.attach(mp, { onEnter: function(a){ state.x86Hits++; } }); rec('[libc] malloc interceptor OK'); }
} catch(e){ rec('[libc] ERR ' + e); }

// ---- 记录 android_dlopen_ext (linker64 原生 x86_64) ----
try {
  var ade = Module.findExportByName(null, 'android_dlopen_ext');
  rec('[dlopen_ext] ' + ade);
  if (ade) {
    Interceptor.attach(ade, {
      onEnter: function(args){ try { this.p = args[0].readCString(); } catch(e){ this.p = '?'; } },
      onLeave: function(ret){
        if (this.p && this.p.indexOf('core') >= 0) { state.dlopenSeen++; rec('[dlopen_ext] ret=' + ret + ' path=' + this.p); }
      }
    });
  }
} catch(e){ rec('[dlopen_ext] ERR ' + e); }

// ---- 主目标: ARM64 libcore.so ----
function tryArm(){
  if (state.hooked) return;
  var m = Process.findModuleByName('libcore.so');
  if (!m) return;
  state.hooked = true;
  state.libcoreBase = m.base.toString();
  rec('[libcore] base=' + m.base + ' size=' + m.size + ' path=' + m.path);
  var sym = null, cnt = -1;
  try {
    var exps = m.enumerateExports();
    cnt = exps.length;
    for (var i = 0; i < exps.length; i++) {
      if (exps[i].name === 'AES_set_encrypt_key') { sym = exps[i].address; break; }
    }
  } catch(e){ rec('[libcore] enumerateExports ERR ' + e); }
  rec('[libcore] export count=' + cnt + ' AES_set_encrypt_key=' + sym);
  var target = sym || m.base.add(0x3842ac);
  state.armAddr = target.toString();
  rec('[libcore] hook target=' + target + ' via=' + (sym ? 'export' : 'base+0x3842ac'));

  // 直读 ARM 段 (内存 dump 兜底价值)
  try {
    var buf = Memory.readByteArray(m.base.add(0x3842ac), 64);
    var u8 = new Uint8Array(buf), s = '';
    for (var i = 0; i < u8.length; i++) s += ('0' + u8[i].toString(16)).slice(-2);
    state.memReadOk = s;
    rec('[memread] base+0x3842ac[64]=' + s);
  } catch(e){ state.memReadOk = 'ERR:' + e; rec('[memread] ERR ' + e); }

  // 挂 ARM64 导出
  try {
    Interceptor.attach(target, {
      onEnter: function(args){ state.armHits++; if (state.armHits <= 5) rec('[ARM HIT] AES_set_encrypt_key #' + state.armHits + ' keyptr=' + args[0]); },
      onLeave: function(){ }
    });
    rec('[libcore] ARM Interceptor.attach returned OK (no throw)');
  } catch(e){ state.armAttachErr = String(e); rec('[libcore] ARM attach ERR ' + e); }
}

var iv = setInterval(tryArm, 400);
setTimeout(function(){ clearInterval(iv); rec('[poll] stopped'); }, 90000);

rpc.exports = {
  stat: function(){ var o = {}; for (var k in state) o[k] = state[k]; o.logCount = log.length; return o; },
  tail: function(n){ return log.slice(-n); }
};
'''

def main():
    dev = frida.get_remote_device()
    print('device:', dev.id)
    apps = [a for a in dev.enumerate_applications() if a.identifier == PKG]
    print('app found:', [(a.identifier, a.pid, a.name) for a in apps])

    pid = dev.spawn([PKG])
    print('SPAWN pid =', pid)
    session = dev.attach(pid)
    script = session.create_script(JS)
    script.on('message', lambda m, d: print('  [msg]', m.get('payload', m)))

    script.load()
    print('script loaded; resuming...')
    dev.resume(pid)

    t0 = time.time()
    last = None
    while time.time() - t0 < RUN_SECONDS:
        time.sleep(5)
        try:
            st = script.exports_sync.stat()
        except Exception as e:
            print('stat ERR %s: %s' % (type(e).__name__, e))
            break
        line = 't=%4.1fs %s' % (time.time() - t0, json.dumps(st, ensure_ascii=False))
        if line != last:
            print(line)
            last = line

    print('=== FINAL STAT ===')
    try:
        print(json.dumps(script.exports_sync.stat(), ensure_ascii=False, indent=2))
        for l in script.exports_sync.tail(40):
            print('  |', l)
    except Exception as e:
        print('final stat ERR %s: %s' % (type(e).__name__, e))

if __name__ == '__main__':
    main()
