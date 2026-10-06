'use strict';
/* hunt8.js - 决定性实验: 按文件路径定位 libcore 实例, hook native call 入口
 * + Dart 回调 ffiClosure + EVP/RSA GOT。一次运行看全链路。 */
const LIBCORE_OFF_CALL = 0x307a38;      // native call(input, callback)
const LIBCORE_OFF_INIT = 0x2fdc24;      // native init
const GOT = [
    ['EVP_CipherInit_ex', 0x664ea0], ['EVP_DecryptInit_ex', 0x661428],
    ['EVP_DecryptUpdate', 0x661430], ['EVP_EncryptUpdate', 0x661410],
    ['AES_set_decrypt_key', 0x6622a8], ['AES_set_encrypt_key', 0x6622b0],
    ['RSA_private_decrypt', 0x6613f8], ['MD5_Update', 0x665920],
    ['SHA256_Update', 0x661458],
];
const LIBAPP_OFF = [
    ['ffiClosure1(loadCore)', 0xcd3b64],
    ['ffiClosure2(init)', 0x797e90],
    ['_rawCall', 0x5ae5c0],
];

function log(s) { send(s); }

function findLibcoreBase() {
    const ranges = Process.enumerateRanges({ protection: 'r--', coalesce: false });
    for (const r of ranges) {
        if (r.file && r.file.path && r.file.path.indexOf('libcore.so') >= 0) {
            log('[*] libcore r-- 映射 ' + r.base + ' size=' + r.size + ' path=' + r.file.path);
        }
    }
    // 取最大的那个文件映射当基址候选
    let best = null;
    for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: false })) {
        if (r.file && r.file.path && r.file.path.indexOf('libcore.so') >= 0) {
            if (!best || r.size > best.size) best = r;
        }
    }
    return best ? best.base : null;
}

function findLibappBase() {
    for (const m of Process.enumerateModules()) {
        if (m.name === 'libapp.so') return m.base;
    }
    return null;
}

function cstr(p, max) {
    try { return p.readCString(max || 256); } catch (e) { return null; }
}
function hexdump16(p, n) {
    try {
        const b = new Uint8Array(p.readByteArray(n || 48));
        let s = '';
        for (let i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return 'ERR'; }
}

function main() {
    const coreBase = findLibcoreBase();
    const appBase = findLibappBase();
    log('[*] libcore base=' + coreBase + ' libapp base=' + appBase);
    if (!coreBase && !appBase) { log('[!] 两者都没找到'); return; }

    if (coreBase) {
        // 1) native call 入口
        try {
            Interceptor.attach(coreBase.add(LIBCORE_OFF_CALL), {
                onEnter: function (args) {
                    log('[CALL] enter x0=' + args[0] + ' x1=' + args[1] +
                        ' input0="' + cstr(args[1], 120) + '" hex=' + hexdump16(args[1], 48) +
                        ' cb=' + args[2]);
                    this.cb = args[2];
                },
                onLeave: function (ret) { log('[CALL] leave ret=' + ret); }
            });
            log('[+] hooked native call @' + coreBase.add(LIBCORE_OFF_CALL));
        } catch (e) { log('[!] call hook 失败: ' + e); }

        // 2) native init 入口
        try {
            Interceptor.attach(coreBase.add(LIBCORE_OFF_INIT), {
                onEnter: function (args) {
                    log('[INIT] enter input="' + cstr(args[1], 200) + '"');
                }
            });
            log('[+] hooked native init @' + coreBase.add(LIBCORE_OFF_INIT));
        } catch (e) { log('[!] init hook 失败: ' + e); }

        // 3) GOT 槽 (crypto 函数)
        for (const [name, off] of GOT) {
            try {
                const slot = coreBase.add(off);
                const fnp = slot.readPointer();
                log('[GOT] ' + name + ' slot=' + slot + ' -> ' + fnp);
                Interceptor.attach(fnp, {
                    onEnter: function (args) { log('[CRYPTO] ' + name + ' CALLED!'); }
                });
            } catch (e) { log('[!] GOT ' + name + ' 失败: ' + e); }
        }
    }

    if (appBase) {
        // 4) Dart 侧回调与 _rawCall
        for (const [name, off] of LIBAPP_OFF) {
            try {
                Interceptor.attach(appBase.add(off), {
                    onEnter: function (args) {
                        log('[DART] ' + name + ' enter x0=' + args[0] + ' x1=' + args[1] +
                            ' s0="' + cstr(args[0], 100) + '" s1="' + cstr(args[1], 200) + '"');
                    },
                    onLeave: function (ret) {
                        log('[DART] ' + name + ' leave x0=' + ret +
                            ' s="' + cstr(ret, 200) + '"');
                    }
                });
                log('[+] hooked dart ' + name + ' @' + appBase.add(off));
            } catch (e) { log('[!] dart ' + name + ' 失败: ' + e); }
        }
    }
    log('[*] hunt8 就绪');
}

setImmediate(main);
