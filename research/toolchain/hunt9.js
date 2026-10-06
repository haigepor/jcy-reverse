'use strict';
/* hunt9.js - hook encrypt 包 AES::AES / Encrypter::decrypt64 / decrypt
 * 直接读 Dart Key/IV 对象中的字节 → 抓派生 key/iv 明文 */
function log(s) { send(s); }

function findLibappBase() {
    // libapp.so 不在 modules 里, 找文件映射
    for (const prot of ['r--', 'r-x', 'rw-']) {
        for (const r of Process.enumerateRanges({ protection: prot, coalesce: false })) {
            if (r.file && r.file.path && r.file.path.indexOf('libapp.so') >= 0) {
                return { base: r.base, path: r.file.path };
            }
        }
    }
    return null;
}

// Dart 对象工具 (compressed pointers, tagged bit0=1)
function u32(p) { try { return p.readU32(); } catch (e) { return 0; } }
function heapOf(tagged) { return tagged.and(0xffffffff00000000); }
function decompress(tagged, compressedU32) {
    // compressed 指针还原: 高 32 位来自堆基址
    return tagged.and(0xffffffff00000000).or(compressedU32);
}
// ByteArrayWrapper: field_7 = Uint8List (tagged compressed)
function readBytesField(objTagged, fieldOff) {
    try {
        const o = objTagged.sub(1);
        const c = u32(o.add(fieldOff));
        if (c === 0) return null;
        const listObj = decompress(objTagged, c).sub(1);
        const lenSmi = u32(listObj.add(0xb));
        const len = lenSmi >> 1;
        if (len <= 0 || len > 1024) return null;
        const data = listObj.add(0xf).readByteArray(len);
        return { len: len, hex: buf2hex(data), ascii: toAscii(data) };
    } catch (e) { return { err: '' + e }; }
}
function buf2hex(b) {
    const u = new Uint8Array(b); let s = '';
    for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
    return s;
}
function toAscii(b) {
    const u = new Uint8Array(b); let s = '';
    for (let i = 0; i < u.length; i++) {
        const c = u[i];
        s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
    }
    return s;
}
// Dart String (OneByteString): 长度 Smi at +0xb? 字符串布局: [hdr][hash][length][data]
// compressed: length at +0xc (Smi 4B), data at +0x10? 用 blutter 布局: field_f 是数组数据。
// 字符串: 尝试 +0xf 直接读
function readDartString(tagged, max) {
    try {
        const o = tagged.sub(1);
        const lenSmi = u32(o.add(0xc));
        const len = lenSmi >> 1;
        if (len <= 0 || len > max) return null;
        const data = o.add(0xf).readByteArray(Math.min(len, max));
        return { len: len, ascii: toAscii(data), hex: buf2hex(data).slice(0, 200) };
    } catch (e) { return null; }
}

function main() {
    const found = findLibappBase();
    if (!found) { log('[!] libapp.so 未找到'); return; }
    const base = found.base;
    log('[*] libapp base=' + base + ' path=' + found.path);

    const HOOKS = [
        // [名字, 偏移, 是否读key参数x1, 是否读栈上iv]
        ['AES::AES', 0x5b064c, 'key'],
        ['Encrypter::decrypt64', 0x5db04c, 'iv'],
        ['Encrypter::encrypt', 0x5b055c, 'both'],
        ['Encrypter::decrypt', 0x5b0464, 'both'],
    ];
    // encrypt 包函数地址以 blutter 为准:
    const ADDR = {
        'AES::AES': 0x5b064c,
        'Encrypter::decrypt64': 0x5db04c,
        'Encrypter::encrypt': 0x5b055c,
        'Encrypter::decrypt': 0x5b0588,
    };

    for (const name in ADDR) {
        const off = ADDR[name];
        try {
            Interceptor.attach(base.add(off), {
                onEnter: function (args) {
                    const info = { fn: name, x0: '' + args[0], x1: '' + args[1], x2: '' + args[2] };
                    // x1 = this 或 key 对象
                    const k = readBytesField(args[1], 7);
                    if (k && k.hex) info.k1 = k.hex + '|' + k.ascii;
                    // x2 可能是另一个对象 (Encrypted)
                    const k2 = readBytesField(args[2], 7);
                    if (k2 && k2.hex) info.k2 = k2.hex;
                    // 栈上第 0 个参数 (命名参数 iv / padding)
                    try {
                        const spArg = this.context.sp.readPointer();
                        const kb = readBytesField(spArg, 7);
                        if (kb && kb.hex) info.sp0 = kb.hex + '|' + kb.ascii;
                        else {
                            const s = readDartString(spArg, 64);
                            if (s) info.sp0str = s.ascii;
                        }
                    } catch (e) { }
                    log('[AES] ' + JSON.stringify(info));
                }
            });
            log('[+] hooked ' + name + ' @' + base.add(off));
        } catch (e) { log('[!] ' + name + ' 失败: ' + e); }
    }

    // AppTransformer::transformResponse + apiDecrypt 观察流量
    try {
        Interceptor.attach(base.add(0xbd6fc8), {
            onEnter: function (args) {
                log('[TRANSFORM] enter x2=' + args[2] + ' str=' +
                    JSON.stringify(readDartString(args[2], 80)));
            }
        });
        log('[+] hooked transformResponse');
    } catch (e) { log('[!] transform 失败: ' + e); }
    try {
        Interceptor.attach(base.add(0xbd7a68), {
            onEnter: function (args) {
                log('[APIDECRYPT] x1=' + JSON.stringify(readDartString(args[1], 80)) +
                    ' x2=' + JSON.stringify(readDartString(args[2], 40)));
            }
        });
        log('[+] hooked apiDecrypt');
    } catch (e) { log('[!] apiDecrypt 失败: ' + e); }

    log('[*] hunt9 就绪');
}

setImmediate(main);
