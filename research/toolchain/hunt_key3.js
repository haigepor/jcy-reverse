'use strict';
/* hunt_key3.js - r-- 匿名映射内逐特征扫描, 双库(libcore+libloader_device)全 hook */
const SIGS = [
    ['aes_v8_set_decrypt_key', 'dec', '3f2303d5fd7bbfa9fd03009175ffff971f0000f1'],
    ['aes_v8_set_encrypt_key', 'enc', 'fd7bbfa9fd030091030080921f0000f1600f0054'],
    ['aes_v8_cbc_encrypt', 'cbc', 'fd7bbfa9fd030091424000f1080280d2831e0054'],
    ['EVP_DecryptInit_ex', 'evpi', 'e5031f2a264b0a14090001cb5f000071e8031faa'],
    ['RSA_private_decrypt', 'rsa', '680440f9051140f9a0001fd6680440f9050940f9'],
    ['EVP_DecryptUpdate', 'evpu', 'fd7bbba9f90b00f9f85f02a9f65703a9f44f04a9'],
];

function hexbuf(p, n) {
    try { return Memory.readByteArray(p, n); } catch (e) { return null; }
}
function toHex(buf) {
    if (!buf) return 'null';
    const u = new Uint8Array(buf), s = [];
    for (let i = 0; i < u.length; i++) s.push(('0' + u[i].toString(16)).slice(-2));
    return s.join('');
}

function doHook(name, kind, addr, tag) {
    try {
        if (kind === 'dec' || kind === 'enc') {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    const bits = args[1].toInt32();
                    if (bits !== 128 && bits !== 256) return;
                    send('[SET_KEY ' + tag + ':' + name + '] bits=' + bits +
                        ' key="' + args[0].readCString(64) + '" hex=' + toHex(hexbuf(args[0], bits / 8)));
                }
            });
        } else if (kind === 'evpi') {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    send('[EVP_INIT ' + tag + '] key=' + toHex(hexbuf(args[3], 16)) +
                        ' iv=' + toHex(hexbuf(args[4], 16)));
                }
            });
        } else if (kind === 'rsa') {
            Interceptor.attach(addr, {
                onEnter: function (args) { this.to = args[2]; },
                onLeave: function (ret) {
                    const n = ret.toInt32();
                    if (n > 0 && n <= 64)
                        send('[RSA_DEC ' + tag + '] n=' + n + ' K="' + this.to.readCString(64) + '"');
                }
            });
        } else if (kind === 'cbc') {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    const len = args[2].toInt32();
                    if (len < 16 || len > 65536) return;
                    this.out = args[1]; this.len = len; this.iv = args[4];
                },
                onLeave: function () {
                    try {
                        send('[CBC_DEC ' + tag + '] len=' + this.len +
                            ' iv=' + toHex(hexbuf(this.iv, 16)) +
                            ' out0="' + this.out.readCString(96) + '"');
                    } catch (e) { }
                }
            });
        } else if (kind === 'evpu') {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    send('[EVP_UPDATE ' + tag + '] in0=' + toHex(hexbuf(args[3], 16)));
                }
            });
        }
        send('[*] hooked ' + tag + ':' + name + ' @' + addr);
        return true;
    } catch (e) {
        send('[!] hook fail ' + tag + ':' + name + ' ' + e);
        return false;
    }
}

function main() {
    // 重扫全部可读段, 找含 SIG20 的 4-8MB 段(即库平铺映射), 段内逐特征定位
    const anchors = [];
    for (const r of Process.enumerateRanges({ protection: 'r--', coalesce: false })
        .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: false }))) {
        if (r.size < 0x400000 || r.size > 0x800000) continue;
        try {
            const hits = Memory.scanSync(r.base, r.size, SIGS[0][2]);
            for (const h of hits) anchors.push([r, h.address]);
        } catch (e) { }
    }
    send('[*] 锚点库段 ' + anchors.length + ' 个');
    const hooked = new Set();
    for (const [r, anchor] of anchors) {
        const tag = 'lib@' + r.base;
        // 该库内每个特征独立扫描定位(兼容不同 so 的内部偏移)
        for (const [name, kind, sig] of SIGS) {
            try {
                const hs = Memory.scanSync(r.base, r.size, sig);
                for (const h of hs) {
                    const key = h.address.toString() + name;
                    if (hooked.has(key)) continue;
                    hooked.add(key);
                    doHook(name, kind, h.address, tag);
                }
            } catch (e) { }
        }
    }
    send('[*] hook 安装完成, 共 ' + hooked.size + ' 个');
}

main();
