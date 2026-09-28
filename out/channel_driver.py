# -*- coding: utf-8 -*-
"""Driver: attach java-bridge hooks, drive app, capture channel traffic."""
import frida, time, sys, glob

BRIDGE = glob.glob(r"C:\Users\haige\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\site-packages\frida_tools\bridges\java.js")[0]

PROBE = r"""
Java.perform(function () {
    function dumpBB(buf) {
        try {
            if (buf === null) return '';
            const ByteBuffer_ = Java.use('java.nio.ByteBuffer');
            const bb = Java.cast(buf, ByteBuffer_);
            const rem = bb.remaining();
            if (rem <= 0 || rem > 262144) return '(len ' + rem + ')';
            const arr = Java.array('byte', new Array(rem).fill(0));
            const pos = bb.position();
            bb.get(arr);
            bb.position(pos);
            const String_ = Java.use('java.lang.String');
            return String_.$new(arr, 'UTF-8');
        } catch (e) { return '(err ' + e + ')'; }
    }
    // outgoing: Java -> Dart
    try {
        const DartMessenger = Java.use('io.flutter.embedding.engine.dart.DartMessenger');
        DartMessenger.send.overloads.forEach(function (ov) {
            ov.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                console.log('[OUT ch=' + args[0] + '] ' + dumpBB(args.length > 1 ? args[1] : null).substring(0, 1000));
                return ov.apply(this, arguments);
            };
        });
    } catch (e) { console.log('[!] DM.send: ' + e); }
    // incoming: Dart -> Java (vmplugin bridge lives here)
    try {
        const DartMessenger = Java.use('io.flutter.embedding.engine.dart.DartMessenger');
        DartMessenger.handleMessageFromDart.implementation = function (ch, msg) {
            console.log('[IN ch=' + ch + '] ' + dumpBB(msg).substring(0, 1200));
            return this.handleMessageFromDart(ch, msg);
        };
    } catch (e) { console.log('[!] DM.handle: ' + e); }
    // fallback: FlutterJNI.handlePlatformMessage (pre-emulator path)
    try {
        const FJNI = Java.use('io.flutter.embedding.engine.FlutterJNI');
        FJNI.handlePlatformMessage.overloads.forEach(function (ov) {
            ov.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                const ch = args[0];
                const msg = (typeof ch === 'string') ? args[1] : args[1];
                console.log('[JNI-IN ch=' + ch + '] ' + dumpBB(msg).substring(0, 1200));
                return ov.apply(this, arguments);
            };
        });
    } catch (e) { console.log('[!] FJNI: ' + e); }
    // outgoing MethodCall handler responses are delivered via Reply
    try {
        const MethodChannel = Java.use('io.flutter.plugin.common.MethodChannel');
        MethodChannel.invokeMethod.overloads.forEach(function (ov) {
            ov.implementation = function () {
                const args = Array.prototype.slice.call(arguments);
                let a = '?';
                try { a = args[1] === null ? 'null' : args[1].toString(); } catch (e) {}
                console.log('[MC-out ' + args[0] + '] ' + a.substring(0, 700));
                return ov.apply(this, arguments);
            };
        });
    } catch (e) { console.log('[!] MC: ' + e); }
    console.log('[*] bidirectional channel hooks installed');
});
"""

def main():
    bridge = open(BRIDGE, encoding='utf-8').read()
    full = "(function(){\n" + bridge + "\nObject.defineProperty(globalThis, 'Java', { value: bridge });\n})();\n" + PROBE
    d = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    session = d.attach('Gadget')
    script = session.create_script(full)
    out = open('out/channel_traffic.log', 'w', encoding='utf-8')
    def on_msg(m, data):
        if m['type'] == 'log':
            line = m.get('payload', '')
        elif m['type'] == 'error':
            line = '[ERR] ' + m.get('description', '')[:200]
        else:
            line = str(m)[:200]
        print(line, flush=True)
        out.write(line + '\n')
        out.flush()
    script.on('message', on_msg)
    script.load()
    print('--- hooks live for 120s ---', flush=True)
    time.sleep(120)

if __name__ == '__main__':
    main()
