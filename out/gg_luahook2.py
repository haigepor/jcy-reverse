# -*- coding: utf-8 -*-
"""Driver v2: persistent hooks + deep UI walk into video playback.
Captures every LuaJNI.eval (business lua) + invoke_method (crypto key/iv)."""
import frida, time, sys, glob, os, json, re, subprocess

BRIDGE = glob.glob(r"C:\Users\haige\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\site-packages\frida_tools\bridges\java.js")[0]
DUMP = os.path.abspath('out/lua_dump')
os.makedirs(DUMP, exist_ok=True)
CWD = os.path.dirname(os.path.abspath('out/gg_luahook2.py'))
ADB = './tools/platform-tools/adb.exe'

HOOK = r"""
var seq = 0;
function ts() { return new Date().toISOString().slice(11, 23); }
Java.perform(function () {
    try {
        const LuaJNI = Java.use('com.github.tgarm.luavm.LuaJNI');
        LuaJNI.eval.implementation = function (id, src) {
            send({ k: 'lua', tag: 'eval#' + id, data: src === null ? null : src.toString() });
            return this.eval(id, src);
        };
        LuaJNI.load.implementation = function (id, name) {
            send({ k: 'log', line: ts() + ' LuaJNI.load(' + id + ', ' + name + ')' });
            const r = this.load(id, name);
            send({ k: 'log', line: ts() + ' load ret=' + r });
            return r;
        };
        send({ k: 'log', line: ts() + ' [+] LuaJNI hooked' });
    } catch (e) { send({ k: 'log', line: ts() + ' [!] LuaJNI: ' + e }); }
    try {
        const Plugin = Java.use('com.github.tgarm.luavm.LuavmPlugin');
        Plugin.invoke_method.implementation = function (name, arg) {
            const ret = this.invoke_method(name, arg);
            send({ k: 'im', method: name === null ? null : name.toString(),
                   arg: arg === null ? null : arg.toString(),
                   ret: ret === null ? null : ret.toString() });
            return ret;
        };
        send({ k: 'log', line: ts() + ' [+] invoke_method hooked' });
    } catch (e) { send({ k: 'log', line: ts() + ' [!] Plugin: ' + e }); }
    try {
        const Res = Java.use('com.github.tgarm.luavm.LuavmPlugin$a$a');
        Res.success.implementation = function (v) {
            if (v !== null && v !== undefined) {
                let s; try { s = v.toString(); } catch (e) { s = '(' + e + ')'; }
                send({ k: 'res', val: s.length < 16384 ? s : s.substring(0, 8192) + '...[trunc ' + s.length + ']' });
            }
            return this.success(v);
        };
        send({ k: 'log', line: ts() + ' [+] $a$a hooked' });
    } catch (e) { send({ k: 'log', line: ts() + ' [!] $a$a: ' + e }); }
});
"""

LIB_HASHES = set()
state = {'files': 0, 'ims': 0}

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[FRIDA-ERR]', msg.get('description', '')[:300]); return
    p = msg.get('payload')
    if not isinstance(p, dict): return
    k = p.get('k')
    if k == 'log':
        print('[LOG]', p['line'], flush=True)
    elif k == 'lua':
        import hashlib
        src = p.get('data') or ''
        h = hashlib.md5(src.encode('utf-8', 'replace')).hexdigest()
        if h in LIB_HASHES: return
        n = state['files']; state['files'] += 1
        name = os.path.join(DUMP, 'biz_%03d_%s.lua' % (n, re.sub(r'[^A-Za-z0-9#_=-]', '_', p.get('tag') or 'chunk')))
        with open(name, 'w', encoding='utf-8', errors='replace') as f: f.write(src)
        print('[BIZ-LUA] %s (%d B) md5=%s' % (name, len(src), h[:10]), flush=True)
    elif k == 'im':
        state['ims'] += 1
        name = os.path.join(DUMP, 'im_%04d_%s.json' % (state['ims'], p.get('method') or 'call'))
        with open(name, 'w', encoding='utf-8') as f:
            json.dump({'method': p.get('method'), 'arg': p.get('arg'), 'ret': p.get('ret')}, f, ensure_ascii=False, indent=1)
        print('[IM#%d] %s arg=%s ret=%s' % (state['ims'], p.get('method'), (p.get('arg') or '')[:200], (p.get('ret') or '')[:120]), flush=True)
    elif k == 'res':
        print('[RES] %s' % p['val'][:160], flush=True)

def sh(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, cwd=CWD, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout).stdout.strip()

def tap(x, y, wait=1.5):
    sh(ADB + ' shell input tap %d %d' % (x, y)); time.sleep(wait)

print('[*] attaching...', flush=True)
t0 = time.time(); session = None
while time.time() - t0 < 60:
    try:
        session = frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget'); break
    except Exception: time.sleep(1.5)
if not session: raise SystemExit('attach fail')

# pre-mark the 14 known-lib hashes so only business lua prints
import hashlib
for f in glob.glob(DUMP + '/uniq_*.lua'):
    LIB_HASHES.add(hashlib.md5(open(f, 'rb').read()).hexdigest())

bridge = open(BRIDGE, encoding='utf-8').read()
full = "(function(){\n" + bridge + "\nObject.defineProperty(globalThis, 'Java', { value: bridge });\n})();\n" + HOOK
script = session.create_script(full)
script.on('message', on_message)
script.load()
print('[*] hooks live', flush=True)

# fresh app start
sh(ADB + ' shell am force-stop com.tudou.tool'); time.sleep(2)
sh(ADB + ' shell monkey -p com.tudou.tool -c android.intent.category.LAUNCHER 1')
print('[*] launched; home wait', flush=True)
time.sleep(16)
# consent if shown
tap(540, 2144, 8)
# home: swipe up a bit to ensure content
sh(ADB + ' shell input swipe 540 1600 540 1000 300'); time.sleep(3)
# tap first video card
tap(530, 1285, 8)
# maybe detail page: tap play
tap(551, 405, 12)
# wait playback
print('[*] playback wait...', flush=True)
time.sleep(20)
# back out, try another card / channel
sh(ADB + ' shell input keyevent 4'); time.sleep(3)
tap(530, 900, 8)
tap(551, 405, 12)
time.sleep(20)
print('[*] totals: biz lua=%d invoke_method=%d' % (state['files'], state['ims']), flush=True)
