'use strict';
/* hunt_key4.js - 异步轮询全保护段特征扫描+增量 hook, 适配 libcore 页面权限动态翻转 */
const SIGS = [
    ['aes_v8_set_decrypt_key', 'dec', '3f2303d5fd7bbfa9fd03009175ffff971f0000f1'],
    ['aes_v8_set_encrypt_key', 'enc', 'fd7bbfa9fd030091030080921f0000f1600f0054'],
    ['aes_v8_cbc_encrypt', 'cbc', 'fd7bbfa9fd030091424000f1080280d2831e0054'],
    ['EVP_DecryptInit_ex', 'evpi', 'e5031f2a264b0a14090001cb5f000071e8031faa'],
    ['RSA_private_decrypt', 'rsa', '680440f9051140f9a0001fd6680440f9050940f9'],
    ['AES_set_encrypt_key_C', 'encC', '08008012600900b4420900b43f000271a0000054'],
    ['AES_set_decrypt_key_C', 'decC', 'fd7bbea9f44f01a9fd030091f30302aa20430a94'],
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

function doHook(name, kind, addr) {
    try {
        if (kind === 'dec' || kind === 'enc' || kind === 'decC' || kind === 'encC') {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    const bits = args[1].toInt32();
                    if (bits !== 128 && bits !== 256) return;
                    send('[SET_KEY ' + name + '] bits=' + bits +
                        ' key="' + args[0].readCString(64) + '" hex=' + toHex(hexbuf(args[0], bits / 8)) +
                        ' @' + addr);
                }
            });
        } else if (kind === 'evpi') {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    send('[EVP_INIT] key=' + toHex(hexbuf(args[3], 32)) +
                        ' iv=' + toHex(hexbuf(args[4], 16)) + ' @' + addr);
                }
            });
        } else if (kind === 'rsa') {
            Interceptor.attach(addr, {
                onEnter: function (args) { this.to = args[2]; },
                onLeave: function (ret) {
                    const n = ret.toInt32();
                    if (n > 0 && n <= 64)
                        send('[RSA_DEC] n=' + n + ' K="' + this.to.readCString(64) + '" @' + addr);
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
                        send('[CBC_DEC] len=' + this.len +
                            ' iv=' + toHex(hexbuf(this.iv, 16)) +
                            ' out0="' + this.out.readCString(96) + '" @' + addr);
                    } catch (e) { }
                }
            });
        }
        send('[+] hooked ' + name + ' @' + addr);
        return true;
    } catch (e) {
        send('[!] hook fail ' + name + ' @' + addr + ' ' + e.message);
        return false;
    }
}

const hooked = new Set();
let polls = 0;

function pollOnce() {
    const ranges = Process.enumerateRanges({ protection: 'rwx', coalesce: false })
        .concat(Process.enumerateRanges({ protection: 'r-x', coalesce: false }))
        .concat(Process.enumerateRanges({ protection: 'r--', coalesce: false }))
        .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: false }));
    for (const r of ranges) {
        // rwx/r-x 全扫(含 4KB 翻转页); r--/rw- 只扫库体量大段, 避开堆
        const isExec = r.protection === 'rwx' || r.protection === 'r-x';
        if (!isExec && (r.size < 0x80000 || r.size > 0x800000)) continue;
        if (r.size > 0x10000000) continue;
        for (const [name, kind, sig] of SIGS) {
            try {
                const hs = Memory.scanSync(r.base, r.size, sig);
                for (const h of hs) {
                    const key = h.address.toString();
                    if (hooked.has(key)) continue;
                    hooked.add(key);
                    doHook(name, kind, h.address);
                }
            } catch (e) { }
        }
    }
    return hooked.size;
}

function main() {
    pollOnce();
    send('[*] 初始 hook ' + hooked.size + ' 个, 进入轮询 (每 400ms)');
    setInterval(function () {
        polls++;
        try { pollOnce(); } catch (e) { }
        if (polls % 25 === 0) send('[*] poll#' + polls + ' 累计hook=' + hooked.size);
    }, 400);
}

main();
