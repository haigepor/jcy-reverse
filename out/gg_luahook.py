# -*- coding: utf-8 -*-
"""Lua-bridge capture driver.

Architecture (verified from smali + liblua-core.so):
  Dart --MethodChannel("com.github.tgarm.luavm")/eval--> LuavmPlugin$b.run()
    -> LuaJNI.eval(stateId, luaSource)      [Lua business logic loaded here]
  Lua --vmplugin.invoke_method(name,json)--> JNI upcall
    -> LuavmPlugin.invoke_method(name, jsonArg)   [crypto calls: key/iv in arg]
    -> MethodChannel.invokeMethod(name, arg) -> Dart executes AES etc.
    -> LuavmPlugin$a$a.success(ret)                [result back to Lua]

Hooks: LuaJNI.eval/load/open/set_dirs, LuavmPlugin.invoke_method,
       LuavmPlugin$a$a.success. Everything written to out/lua_dump/.
"""
import frida, time, sys, glob, os, json, re, threading

BRIDGE = glob.glob(r"C:\Users\haige\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\site-packages\frida_tools\bridges\java.js")[0]
DUMP = os.path.abspath('out/lua_dump')
os.makedirs(DUMP, exist_ok=True)

HOOK = r"""
var seq = 0;
function ts() { return new Date().toISOString().slice(11, 23); }

Java.perform(function () {
    // 1. Lua source loading
    try {
        const LuaJNI = Java.use('com.github.tgarm.luavm.LuaJNI');
        LuaJNI.eval.implementation = function (id, src) {
            send({ k: 'lua', tag: 'eval#' + id, data: src === null ? null : src.toString() });
            return this.eval(id, src);
        };
        LuaJNI.load.implementation = function (id, name) {
            send({ k: 'log', line: ts() + ' LuaJNI.load(' + id + ', ' + name + ')' });
            return this.load(id, name);
        };
        LuaJNI.set_dirs.overloads.forEach(function (ov) {
            ov.implementation = function () {
                send({ k: 'log', line: ts() + ' LuaJNI.set_dirs(' + Array.prototype.join.call(arguments, ', ') + ')' });
                return ov.apply(this, arguments);
            };
        });
        send({ k: 'log', line: ts() + ' [+] LuaJNI hooked' });
    } catch (e) { send({ k: 'log', line: ts() + ' [!] LuaJNI: ' + e }); }

    // 2. Lua -> Dart method calls (crypto!)
    try {
        const Plugin = Java.use('com.github.tgarm.luavm.LuavmPlugin');
        Plugin.invoke_method.implementation = function (name, arg) {
            const ret = this.invoke_method(name, arg);
            send({ k: 'im', method: name === null ? null : name.toString(),
                   arg: arg === null ? null : arg.toString(),
                   ret: ret === null ? null : ret.toString() });
            return ret;
        };
        // Dart -> Java channel requests (eval source, open, close)
        Plugin.onMethodCall.implementation = function (call, result) {
            let s = '';
            try {
                const m = call.method.value;
                let a = '';
                try { a = call.arguments === null ? 'null' : call.arguments.toString().substring(0, 400); } catch (e2) { a = '(arg?)'; }
                s = 'onMethodCall ' + m + ' args=' + a;
            } catch (e) { s = 'onMethodCall (fmt ' + e + ')'; }
            send({ k: 'log', line: ts() + ' [CH] ' + s });
            return this.onMethodCall(call, result);
        };
        send({ k: 'log', line: ts() + ' [+] LuavmPlugin hooked' });
    } catch (e) { send({ k: 'log', line: ts() + ' [!] Plugin: ' + e }); }

    // 3. results returned to Lua
    try {
        const Res = Java.use('com.github.tgarm.luavm.LuavmPlugin$a$a');
        Res.success.implementation = function (v) {
            if (v !== null && v !== undefined) {
                let s;
                try { s = v.toString(); } catch (e) { s = '(' + e + ')'; }
                if (s.length < 8192) send({ k: 'res', val: s });
                else send({ k: 'res', val: s.substring(0, 4096) + '...[trunc ' + s.length + ']' });
            }
            return this.success(v);
        };
        send({ k: 'log', line: ts() + ' [+] $a$a.success hooked' });
    } catch (e) { send({ k: 'log', line: ts() + ' [!] $a$a: ' + e }); }
});

rpc.exports = {
    listdir: function (p) {
        var out = [];
        Java.perform(function () {
            var F = Java.use('java.io.File').$new(p);
            var arr = F.listFiles();
            if (arr !== null) {
                for (var i = 0; i < arr.length; i++) {
                    out.push((arr[i].isDirectory() ? 'D ' : 'F ') + arr[i].getName() + ' ' + arr[i].length());
                }
            }
        });
        return out;
    },
    readfile: function (p) {
        var s = '';
        Java.perform(function () {
            var FIS = Java.use('java.io.FileInputStream');
            var fis = FIS.$new(p);
            try {
                var BAOS = Java.use('java.io.ByteArrayOutputStream');
                var baos = BAOS.$new();
                var buf = Java.array('byte', new Array(4096).fill(0));
                var n;
                while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
                var B64 = Java.use('android.util.Base64');
                s = B64.encodeToString(baos.toByteArray(), 2);
            } finally { fis.close(); }
        });
        return s;
    }
};
"""

state = {'files': 0, 'ims': 0, 'res': 0}

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[FRIDA-ERR]', msg.get('description', '')[:300]); return
    p = msg.get('payload')
    if not isinstance(p, dict): return
    k = p.get('k')
    if k == 'log':
        print('[LOG]', p['line'])
    elif k == 'lua':
        n = state['files']; state['files'] += 1
        name = os.path.join(DUMP, 'lua_%03d_%s.lua' % (n, re.sub(r'[^A-Za-z0-9#_=-]', '_', p.get('tag') or 'chunk')))
        with open(name, 'w', encoding='utf-8', errors='replace') as f:
            f.write(p.get('data') or '')
        print('[LUA] saved %s (%d bytes)' % (name, len(p.get('data') or '')))
    elif k == 'im':
        state['ims'] += 1
        name = os.path.join(DUMP, 'im_%04d_%s.json' % (state['ims'], p.get('method') or 'call'))
        with open(name, 'w', encoding='utf-8') as f:
            json.dump({'method': p.get('method'), 'arg': p.get('arg'), 'ret': p.get('ret')}, f, ensure_ascii=False, indent=1)
        arg = (p.get('arg') or '')
        ret = (p.get('ret') or '')
        print('[IM#%d] %s arg=%s ret=%s' % (state['ims'], p.get('method'), arg[:160], ret[:100]))
    elif k == 'res':
        state['res'] += 1
        print('[RES#%d] %s' % (state['res'], p['val'][:140]))

def attach_with_retry(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            return frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        except Exception as e:
            time.sleep(1.5)
    raise RuntimeError('attach timeout')

print('[*] attaching...')
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
session = attach_with_retry()
print('[*] attached, loading bridge + hooks')
bridge = open(BRIDGE, encoding='utf-8').read()
full = "(function(){\n" + bridge + "\nObject.defineProperty(globalThis, 'Java', { value: bridge });\n})();\n" + HOOK
script2 = session.create_script(full)
script2.on('message', on_message)
script2.load()
print('[*] hooks live. driving UI...')

import subprocess
ADB = './tools/platform-tools/adb.exe'
def sh(cmd):
    return subprocess.run(cmd, shell=True, cwd=os.path.dirname(os.path.abspath('out/gg_luahook.py')), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60).stdout.strip()

def tap(x, y, wait=1.2):
    sh(ADB + ' shell input tap %d %d' % (x, y)); time.sleep(wait)

# fresh start
sh(ADB + ' shell am force-stop com.tudou.tool')
time.sleep(2)
sh(ADB + ' shell monkey -p com.tudou.tool -c android.intent.category.LAUNCHER 1')
print('[*] app launched, waiting for consent page')
time.sleep(14)
# consent (agree)
tap(540, 2144, wait=8)
# maybe privacy dialog again
tap(540, 2144, wait=6)
# home page: wait for channel/video load
time.sleep(10)
# tap a video card
tap(530, 1285, wait=6)
# play button
tap(551, 405, wait=15)
# let playback + danmu run
time.sleep(25)
print('[*] capture done: lua files=%d invoke_method=%d res=%d' % (state['files'], state['ims'], state['res']))
# dump lua dirs from app data
try:
    for d in ['/data/user/0/com.tudou.tool/cache', '/data/user/0/com.tudou.tool/files', '/data/user/0/com.tudou.tool/files/lua']:
        try:
            lst = script2.exports_sync.listdir(d)
            print('[DIR] %s -> %s' % (d, lst[:40]))
        except Exception as e:
            print('[DIR] %s err %s' % (d, e))
except Exception as e:
    print('[!] dir dump: ' + str(e))
print('[*] done')
