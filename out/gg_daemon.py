# -*- coding: utf-8 -*-
"""Persistent capture daemon: attach hooks, write captures to out/lua_dump, run until killed."""
import frida, time, sys, glob, os, json, re, hashlib

BRIDGE = glob.glob(r"C:\Users\haige\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\site-packages\frida_tools\bridges\java.js")[0]
DUMP = os.path.abspath('out/lua_dump')
os.makedirs(DUMP, exist_ok=True)

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
        send({ k: 'log', line: ts() + ' [+] LuaJNI hooked' });
    } catch (e) { send({ k: 'log', line: ts() + ' [!] LuaJNI: ' + e }); }
    try {
        const Plugin = Java.use('com.github.tgarm.luavm.LuavmPlugin');
        Plugin.invoke_method.implementation = function (name, arg) {
            send({ k: 'im', method: name === null ? null : name.toString(),
                   arg: arg === null ? null : arg.toString(),
                   ret: null });
            const ret = this.invoke_method(name, arg);
            send({ k: 'imret', method: name === null ? null : name.toString(),
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

# skip known library hashes
LIB_HASHES = set()
for f in glob.glob(DUMP + '/uniq_*.lua'):
    LIB_HASHES.add(hashlib.md5(open(f, 'rb').read()).hexdigest())
# also the stdlib cycle chunks captured in biz_* (same content, different name)
state = {'files': 0, 'ims': 0}
IM_DIR = os.path.join(DUMP, 'im')
os.makedirs(IM_DIR, exist_ok=True)

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[FRIDA-ERR]', msg.get('description', '')[:300], flush=True); return
    p = msg.get('payload')
    if not isinstance(p, dict): return
    k = p.get('k')
    if k == 'log':
        print('[LOG]', p['line'], flush=True)
    elif k == 'lua':
        src = p.get('data') or ''
        h = hashlib.md5(src.encode('utf-8', 'replace')).hexdigest()
        if h in LIB_HASHES: return
        # remember hash so repeats are skipped
        LIB_HASHES.add(h)
        n = state['files']; state['files'] += 1
        name = os.path.join(DUMP, 'biz_%03d_%s.lua' % (n, re.sub(r'[^A-Za-z0-9#_=-]', '_', p.get('tag') or 'chunk')))
        with open(name, 'w', encoding='utf-8', errors='replace') as f: f.write(src)
        print('[BIZ-LUA] %s (%d B) md5=%s' % (name, len(src), h[:10]), flush=True)
    elif k == 'im':
        state['ims'] += 1
        name = os.path.join(IM_DIR, 'im_%04d_%s.json' % (state['ims'], re.sub(r'[^A-Za-z0-9_.=-]', '_', p.get('method') or 'call')))
        with open(name, 'w', encoding='utf-8') as f:
            json.dump({'method': p.get('method'), 'arg': p.get('arg')}, f, ensure_ascii=False, indent=1)
        print('[IM#%d] %s arg=%s' % (state['ims'], p.get('method'), (p.get('arg') or '')[:240]), flush=True)
    elif k == 'imret':
        # append ret to the newest im file for that method
        try:
            files = sorted(glob.glob(os.path.join(IM_DIR, 'im_*.json')))
            for f in reversed(files):
                d = json.load(open(f, encoding='utf-8'))
                if d.get('method') == p.get('method') and 'ret' not in d:
                    d['ret'] = p.get('ret')
                    json.dump(d, open(f, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
                    break
        except Exception as e:
            print('[imret-persist-err]', e, flush=True)
        print('[IM-RET] %s -> %s' % (p.get('method'), (p.get('ret') or '')[:200]), flush=True)
    elif k == 'res':
        print('[RES] %s' % p['val'][:200], flush=True)

print('[*] attaching...', flush=True)
t0 = time.time(); session = None
while time.time() - t0 < 120:
    try:
        session = frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget'); break
    except Exception as e:
        print('[wait]', str(e)[:80], flush=True); time.sleep(2)
if not session: raise SystemExit('attach fail')

bridge = open(BRIDGE, encoding='utf-8').read()
full = "(function(){\n" + bridge + "\nObject.defineProperty(globalThis, 'Java', { value: bridge });\n})();\n" + HOOK
script = session.create_script(full)
script.on('message', on_message)
script.load()
print('[*] hooks live; capturing until killed', flush=True)
while True:
    time.sleep(5)
