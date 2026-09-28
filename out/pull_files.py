# -*- coding: utf-8 -*-
"""Pull files from app-private storage via frida (runs as app)."""
import frida, time, glob, os, base64, sys

TARGETS = [
    '/data/user/0/com.tudou.tool/files/libcore2.so',
    '/data/user/0/com.tudou.tool/files/libcore.so',
]
OUT = 'out'
HOOK = r"""
rpc.exports = {
    readfile: function (p) {
        var s = '';
        Java.perform(function () {
            var FIS = Java.use('java.io.FileInputStream');
            var fis = FIS.$new(p);
            try {
                var BAOS = Java.use('java.io.ByteArrayOutputStream');
                var baos = BAOS.$new();
                var buf = Java.array('byte', new Array(65536).fill(0));
                var n;
                while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
                var B64 = Java.use('android.util.Base64');
                s = B64.encodeToString(baos.toByteArray(), 2);
            } finally { fis.close(); }
        });
        return s;
    },
    listdir: function (p) {
        var out = [];
        Java.perform(function () {
            var F = Java.use('java.io.File').$new(p);
            var arr = F.listFiles();
            if (arr !== null) for (var i = 0; i < arr.length; i++)
                out.push((arr[i].isDirectory() ? 'D ' : 'F ') + arr[i].getName() + ' ' + arr[i].length());
        });
        return out;
    }
};
"""

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[ERR]', msg.get('description', '')[:200])

t0 = time.time(); session = None
while time.time() - t0 < 60:
    try:
        session = frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget'); break
    except Exception: time.sleep(2)
if not session: raise SystemExit('attach fail')

BRIDGE = glob.glob(r"C:\Users\haige\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\site-packages\frida_tools\bridges\java.js")[0]
bridge = open(BRIDGE, encoding='utf-8').read()
full = "(function(){\n" + bridge + "\nObject.defineProperty(globalThis, 'Java', { value: bridge });\n})();\n" + HOOK
script = session.create_script(full)
script.on('message', on_message)
script.load()

# fresh list
for d in ['/data/user/0/com.tudou.tool/files', '/data/user/0/com.tudou.tool/cache', '/data/user/0/com.tudou.tool/app_flutter']:
    try:
        print('[DIR]', d, script.exports_sync.listdir(d)[:30])
    except Exception as e:
        print('[DIR]', d, 'err', e)

for t in TARGETS:
    try:
        b64 = script.exports_sync.readfile(t)
        data = base64.b64decode(b64)
        out = os.path.join(OUT, os.path.basename(t))
        open(out, 'wb').write(data)
        print('[PULLED]', out, len(data), 'bytes')
    except Exception as e:
        print('[PULL-ERR]', t, str(e)[:200])
