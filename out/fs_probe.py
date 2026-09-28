# -*- coding: utf-8 -*-
# frida-server 17.8.2 x86_64 @ LDPlayer14 (Android 14 x86_64 + houdini) 能力探针
# 目的: 区分 attach 超时是 frida-server 普遍问题还是 houdini 转译(arm64 app)特有问题
# 用法: python out/fs_probe.py
import sys, time
import frida

dev = frida.get_remote_device()
print('device:', dev.id)

procs = dev.enumerate_processes()
print('total procs:', len(procs))

# 找正在运行的系统进程做 attach 对照
sys_cands = [p for p in procs if p.name in
             ('com.android.systemui', 'com.android.launcher3', 'com.android.settings',
              'com.android.incallui')]
print('running system procs:', [(p.pid, p.name) for p in sys_cands])

for p in sys_cands[:2]:
    try:
        s = dev.attach(p.pid)
        print('ATTACH[pid=%d %s]: OK' % (p.pid, p.name))
        s.detach()
    except Exception as e:
        print('ATTACH[pid=%d %s]: FAIL %s: %s' % (p.pid, p.name, type(e).__name__, e))

# spawn 对照组1: 系统 app (纯 x86_64 语境)
for pkg in ('com.android.settings',):
    try:
        pid = dev.spawn([pkg])
        print('SPAWN[%s]: pid=%d' % (pkg, pid))
        s = dev.attach(pid)
        sc = s.create_script('rpc.exports.ping = function(){ return Process.arch + " " + Process.platform; };')
        sc.load()
        print('  script load OK, ping =', sc.exports_sync.ping())
        dev.resume(pid)
        time.sleep(2)
        s.detach()
        try: dev.kill(pid)
        except Exception: pass
        print('SPAWN[%s]: FULL OK (attach+script+resume)' % pkg)
    except Exception as e:
        print('SPAWN[%s]: FAIL %s: %s' % (pkg, type(e).__name__, e))

# spawn 对照组2: 目标 app (arm64 lib 走 houdini 转译)
try:
    pid = dev.spawn(['com.tudou.tool'])
    print('SPAWN[com.tudou.tool]: pid=%d' % pid)
    s = dev.attach(pid)
    sc = s.create_script(
        'rpc.exports.info = function(){'
        '  var r = {arch: Process.arch, platform: Process.platform, ptr: Process.pointerSize};'
        '  var m = Process.findModuleByName("libcore.so");'
        '  r.libcore = m ? (m.base.toString() + " size=" + m.size) : null;'
        '  try { r.java_ok = !!Java.available; } catch(e) { r.java_ok = "err:" + e; }'
        '  return r; };')
    sc.load()
    print('  script load OK, info =', sc.exports_sync.info())
    dev.resume(pid)
    time.sleep(5)
    print('SPAWN[com.tudou.tool]: FULL OK (attach+script+resume)')
except Exception as e:
    print('SPAWN[com.tudou.tool]: FAIL %s: %s' % (type(e).__name__, e))
