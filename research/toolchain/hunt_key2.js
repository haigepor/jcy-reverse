'use strict';
/* hunt_key2.js - 匿名内存扫描定位 libcore, 按偏移 hook RSA/AES */
const OFFSETS = [
    ['aes_v8_set_decrypt_key', 0x385400, 'dec'],
    ['aes_v8_set_encrypt_key', 0x3851e0, 'enc'],
    ['aes_v8_cbc_encrypt', 0x385540, 'cbc'],
    ['EVP_DecryptInit_ex', 0x387db4, 'evpi'],
    ['RSA_private_decrypt', 0x43e324, 'rsa'],
    ['EVP_DecryptUpdate', 0x3877d0, 'evpu'],
];
const SIGS = {
    0x385400: '3f2303d5fd7bbfa9fd03009175ffff971f0000f1',
    0x3851e0: 'fd7bbfa9fd030091030080921f0000f1600f0054',
    0x385540: 'fd7bbfa9fd030091424000f1080280d2831e0054',
    0x387db4: 'e5031f2a264b0a14090001cb5f000071e8031faa',
    0x43e324: '680440f9051140f9a0001fd6680440f9050940f9',
    0x3877d0: 'fd7bbba9f90b00f9f85f02a9f65703a9f44f04a9',
};

function parseHex(s) {
    const a = new Uint8Array(s.length / 2);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16);
    return a.buffer;
}

function findBase() {
    const ranges = Process.enumerateRanges({ protection: 'r-x', coalesce: true });
    send('[*] r-x 段数 ' + ranges.length);
    for (const r of ranges) {
        if (r.size < 0x10000 || r.size > 0x40000000) continue;
        // 用 set_decrypt_key 特征在段内搜
        const sig = SIGS[0x385400];
        try {
            const found = Memory.scanSync(r.base, r.size, sig);
            if (found.length > 0) {
                const addr = found[0].address;
                const base = addr.sub(0x385400);
                send('[*] 命中 @' + addr + ' -> 推算 base=' + base);
                return base;
            }
        } catch (e) { }
    }
    return null;
}

function hexbuf(p, n) {
    try { return Memory.readByteArray(p, n); } catch (e) { return null; }
}

function doHooks(base) {
    for (const [name, off, kind] of OFFSETS) {
        const a = base.add(off);
        try {
            const real = Memory.readByteArray(a, 20);
            const want = parseHex(SIGS[off]);
            if (BufferCompare(real, want)) { send('[!] ' + name + ' 特征不符, 跳过'); continue; }
        } catch (e) { }
        if (kind === 'dec' || kind === 'enc') {
            Interceptor.attach(a, {
                onEnter: function (args) {
                    const bits = args[1].toInt32();
                    if (bits !== 128 && bits !== 256) return;
                    send('[SET_KEY ' + name + '] bits=' + bits +
                        ' key="' + args[0].readCString(64) + '"');
                }
            });
        } else if (kind === 'evpi') {
            Interceptor.attach(a, {
                onEnter: function (args) {
                    const k = args[3], iv = args[4];
                    send('[EVP_INIT] key=' + (k.isNull() ? 'NULL' : hexbuf(k, 16)) +
                        ' iv=' + (iv.isNull() ? 'NULL' : hexbuf(iv, 16)));
                }
            });
        } else if (kind === 'rsa') {
            Interceptor.attach(a, {
                onEnter: function (args) { this.to = args[2]; },
                onLeave: function (ret) {
                    const n = ret.toInt32();
                    if (n > 0 && n <= 64) {
                        send('[RSA_DEC] n=' + n + ' K="' + this.to.readCString(64) + '"');
                    }
                }
            });
        } else if (kind === 'cbc') {
            Interceptor.attach(a, {
                onEnter: function (args) {
                    const len = args[2].toInt32();
                    if (len < 16 || len > 65536) return;
                    this.out = args[1];
                    this.len = len;
                },
                onLeave: function () {
                    try { send('[CBC_DEC] len=' + this.len +
                        ' out0="' + this.out.readCString(64) + '"'); } catch (e) { }
                }
            });
        } else if (kind === 'evpu') {
            Interceptor.attach(a, {
                onEnter: function (args) {
                    const inp = args[3];
                    try { send('[EVP_UPDATE] in0=' + hexbuf(inp, 16)); } catch (e) { }
                }
            });
        }
        send('[*] hooked ' + name + ' @' + a);
    }
}

function BufferCompare(a, b) {
    const ua = new Uint8Array(a), ub = new Uint8Array(b);
    if (ua.length !== ub.length) return true;
    for (let i = 0; i < ua.length; i++) if (ua[i] !== ub[i]) return true;
    return false;  // false = 相同
}

function main() {
    const base = findBase();
    if (!base) { send('[!] 未找到 libcore 匿名映射'); return; }
    doHooks(base);
}

main();
