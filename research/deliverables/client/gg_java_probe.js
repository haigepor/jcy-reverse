// gg_java_probe.js — test Java bridge + hook MethodChannel & vmplugin
'use strict';

console.log('[*] probe start');
console.log('[*] typeof Java = ' + typeof Java);

if (typeof Java !== 'undefined') {
    Java.perform(function () {
        console.log('[*] inside Java.perform');
        try {
            const ApplicationLoaders = Java.use('android.app.Application');
            console.log('[*] Java.use(Application) OK');
        } catch (e) { console.log('[!] Application err: ' + e); }

        // Hook MethodChannel$IncomingMethodCallHandler or the setMethodCallHandler path
        try {
            const MethodChannel = Java.use('io.flutter.plugin.common.MethodChannel');
            const overloads = MethodChannel.invokeMethod.overloads;
            console.log('[*] MethodChannel.invokeMethod overloads: ' + overloads.length);
            overloads.forEach(function (ov) {
                ov.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    let m = args[0], a = args.length > 1 ? args[1] : null;
                    let s = '?';
                    try { s = a === null ? 'null' : a.toString(); } catch (e) { s = '(err ' + e + ')'; }
                    console.log('[MC-out] ' + m + ' args=' + s.substring(0, 800));
                    return ov.apply(this, arguments);
                };
            });
        } catch (e) { console.log('[!] MC hook err: ' + e); }

        // vmplugin channel handler: Flutter Native side implements MethodChannel.MethodCallHandler
        // Hook MethodCall result callback too
        try {
            const MCResult = Java.use('io.flutter.plugin.common.MethodChannel$Result');
            console.log('[*] Result class loaded');
        } catch (e) { console.log('[!] Result err: ' + e); }

        // Hook BasicMessageChannel / BinaryMessenger to catch EVERYTHING raw
        try {
            const BinaryMessenger = Java.use('io.flutter.embedding.engine.dart.DartMessenger');
            const sendOv = BinaryMessenger.send.overloads;
            console.log('[*] DartMessenger.send overloads: ' + sendOv.length);
            sendOv.forEach(function (ov) {
                ov.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const ch = args[0];
                    let payload = '';
                    try {
                        const buf = args[1];
                        if (buf !== null) {
                            const ByteBuffer_ = Java.use('java.nio.ByteBuffer');
                            const bb = Java.cast(buf, ByteBuffer_);
                            const rem = bb.remaining();
                            if (rem > 0 && rem < 65536) {
                                const arr = Java.array('byte', new Array(rem).fill(0));
                                const pos = bb.position();
                                bb.get(arr);
                                bb.position(pos);
                                const String_ = Java.use('java.lang.String');
                                payload = String_.$new(arr, 'UTF-8');
                            }
                        }
                    } catch (e) { payload = '(err ' + e + ')'; }
                    console.log('[BIN-out] ch=' + ch + ' payload=' + payload.substring(0, 900));
                    return ov.apply(this, arguments);
                };
            });
        } catch (e) { console.log('[!] DartMessenger err: ' + e); }
        console.log('[*] java hooks installed');
    });
} else {
    console.log('[!] NO JAVA BRIDGE — process may be pure native at this point');
}
