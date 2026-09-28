# -*- coding: utf-8 -*-
"""Native-level Lua capture: hook luaL_loadbufferx / lua_pcallk / Java_..._LuaJNI_eval
in liblua-core.so directly (no Java method replacement -> no GC pressure, no SIGBUS).

Every Lua chunk (including the play-resolver script downloaded from the server)
passes through luaL_loadbufferx BEFORE compile/execute. Dump it there."""
import frida, time, sys, glob, os, json, re

DUMP = os.path.abspath('out/lua_dump')
os.makedirs(DUMP, exist_ok=True)
CHUNK_DIR = os.path.join(DUMP, 'chunks')
os.makedirs(CHUNK_DIR, exist_ok=True)

HOOK = r"""
var seq = 0;
function ts() { return new Date().toISOString().slice(11, 23); }

function findMod(name) {
    var m = Process.findModuleByName(name);
    if (m) return m;
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) if (mods[i].name === name) return mods[i];
    return null;
}

function hookWhenLoaded(name, cb) {
    var m = findMod(name);
    if (m) { cb(m); return; }
    var t = setInterval(function () {
        var mm = findMod(name);
        if (mm) { clearInterval(t); cb(mm); }
    }, 300);
}

hookWhenLoaded('liblua-core.so', function (m) {
    send({ k: 'log', line: ts() + ' [+] liblua-core.so @ ' + m.base });

    // 1. every chunk before compile: luaL_loadbufferx(L, buf, size, name, mode)
    var loadbuf = m.findExportByName('luaL_loadbufferx');
    if (loadbuf) {
        Interceptor.attach(loadbuf, {
            onEnter: function (args) {
                try {
                    var buf = args[1], size = args[2].toInt32();
                    var name = args[3].isNull() ? '' : args[3].readCString();
                    if (size > 0 && size < 4 * 1024 * 1024) {
                        var bytes = buf.readByteArray(Math.min(size, 512 * 1024));
                        send({ k: 'chunk', tag: (name || 'chunk'), size: size }, bytes);
                    }
                } catch (e) { send({ k: 'log', line: ts() + ' [!] loadbuf: ' + e }); }
            }
        });
        send({ k: 'log', line: ts() + ' [+] luaL_loadbufferx hooked' });
    } else send({ k: 'log', line: ts() + ' [-] luaL_loadbufferx not found' });

    // 2. protected calls: lua_pcallk(L, nargs, nresults, errfunc, ctx, k)
    var pcall = m.findExportByName('lua_pcallk');
    if (pcall) {
        Interceptor.attach(pcall, {
            onEnter: function (a) { send({ k: 'log', line: ts() + ' pcall nargs=' + a[1].toInt32() }); },
            onLeave: function (r) { send({ k: 'log', line: ts() + ' pcall -> ' + r.toInt32() }); }
        });
    }

    // 3. native eval JNI entry (raw, no Java replacement)
    var evalfn = m.findExportByName('Java_com_github_tgarm_luavm_LuaJNI_eval');
    if (evalfn) {
        Interceptor.attach(evalfn, {
            onEnter: function (args) {
                send({ k: 'log', line: ts() + ' LuaJNI.eval(id=' + args[2].toInt32() + ')' });
            }
        });
        send({ k: 'log', line: ts() + ' [+] Java_..._eval hooked (native)' });
    } else send({ k: 'log', line: ts() + ' [-] Java eval not exported' });

    // 4. JNI set_plugin - when the Java plugin object gets registered
    var setp = m.findExportByName('Java_com_github_tgarm_luavm_LuaJNI_set_1plugin');
    if (setp) {
        Interceptor.attach(setp, {
            onEnter: function (args) { send({ k: 'log', line: ts() + ' set_plugin(obj=' + args[2] + ')' }); }
        });
    }

    // 5. other loaders that may be used instead
    var loaders = ['luaL_loadstring', 'luaL_loadbuffer', 'luaL_loadfilex', 'lua_load'];
    loaders.forEach(function (fn) {
        var a = m.findExportByName(fn);
        if (a) {
            Interceptor.attach(a, {
                onEnter: function (args) {
                    try {
                        var buf, size, name;
                        if (fn === 'luaL_loadstring' || fn === 'lua_load') {
                            buf = args[1]; size = -1; name = fn;
                            // read C string
                            var s = buf.readCString();
                            if (s && s.length < 512*1024) {
                                send({ k: 'chunk', tag: fn + ':' + (s.length), size: s.length }, s);
                            }
                            return;
                        }
                        if (fn === 'luaL_loadbuffer') { buf = args[1]; size = args[2].toInt32(); }
                        if (fn === 'luaL_loadfilex') { var p = args[1].readCString(); send({k:'log', line: ts()+' loadfile '+p}); return; }
                        if (size > 0) {
                            var bytes = buf.readByteArray(Math.min(size, 512*1024));
                            send({ k: 'chunk', tag: fn, size: size }, bytes);
                        }
                    } catch (e) {}
                }
            });
            send({ k: 'log', line: ts() + ' [+] ' + fn + ' hooked' });
        }
    });

    // 6. every string pushed into Lua (incl. eval'd source, arg strings, results)
    var pushl = m.findExportByName('lua_pushlstring');
    if (pushl) {
        Interceptor.attach(pushl, {
            onEnter: function (args) {
                try {
                    var size = args[2].toInt32();
                    if (size > 64 && size < 262144) {
                        var bytes = args[1].readByteArray(size);
                        send({ k: 'chunk', tag: 'pushl', size: size }, bytes);
                    }
                } catch (e) {}
            }
        });
        send({ k: 'log', line: ts() + ' [+] lua_pushlstring hooked' });
    }
});
"""

state = {'n': 0, 'bytes': 0}

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[FRIDA-ERR]', msg.get('description', '')[:300], flush=True); return
    p = msg.get('payload')
    if not isinstance(p, dict): return
    k = p.get('k')
    if k == 'log':
        print('[LOG]', p['line'], flush=True)
    elif k == 'chunk':
        n = state['n']; state['n'] += 1
        if data: state['bytes'] += len(data)
        name = re.sub(r'[^A-Za-z0-9_@=-]', '_', p.get('tag') or 'chunk')[:40]
        path = os.path.join(CHUNK_DIR, 'c%03d_%s.lua' % (n, name))
        with open(path, 'wb') as f:
            if data: f.write(data)
        print('[CHUNK] %s (%d B) name=%s' % (path, p.get('size', 0), p.get('tag')), flush=True)

print('[*] attaching...', flush=True)
t0 = time.time(); session = None
while time.time() - t0 < 60:
    try:
        session = frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget'); break
    except Exception as e:
        print('[wait]', str(e)[:80], flush=True); time.sleep(2)
if not session: raise SystemExit('attach fail')
script = session.create_script(HOOK)
script.on('message', on_message)
script.load()
print('[*] native hooks live', flush=True)
while True:
    time.sleep(5)
