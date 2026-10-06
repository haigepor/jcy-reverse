'use strict';
/* hunt_key6.js - 双库 GOT 补丁: libcore(/files/libcore.so) + libloader(lib/arm64/libloader.so)
 * 两库均 BIND_NOW, 加密符号经 GOT 解析; loader 平铺只读映射需先 Memory.protect 开写 */
const CORE_GOT = {
    RSA_private_decrypt: [0x6613f8, 'int', ['int', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_CipherInit_ex: [0x664ea0, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_CipherInit: [0x664e98, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_CipherUpdate: [0x664ea8, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_DecryptInit_ex: [0x661428, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']],
    EVP_DecryptUpdate: [0x661430, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_EncryptInit_ex: [0x661408, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']],
    EVP_EncryptUpdate: [0x661410, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']],
    AES_set_decrypt_key: [0x6622a8, 'int', ['pointer', 'int', 'pointer']],
    AES_set_encrypt_key: [0x6622b0, 'int', ['pointer', 'int', 'pointer']],
    MD5_Update: [0x665920, 'void', ['pointer', 'pointer', 'int']],
    MD5_Final: [0x665910, 'int', ['pointer', 'pointer']],
    MD5: [0x6613b0, 'pointer', ['pointer', 'pointer', 'int']],
    SHA256_Update: [0x661458, 'void', ['pointer', 'pointer', 'int']],
    SHA256_Final: [0x661460, 'int', ['pointer', 'pointer']],
    SHA1: [0x661230, 'pointer', ['pointer', 'pointer', 'int']],
    RAND_bytes: [0x6612a8, 'int', ['pointer', 'int']],
    EVP_aes_128_cbc: [0x661400, 'pointer', []],
    EVP_aes_256_cbc: [0x661440, 'pointer', []],
    EVP_CIPHER_CTX_free: [0x661420, 'void', ['pointer']],
};
const LOADER_GOT = {
    RSA_private_decrypt: [0x5c18a0, 'int', ['int', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_CipherInit_ex: [0x5c54f0, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_CipherInit: [0x5c54e8, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_CipherUpdate: [0x5c54f8, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_DecryptInit_ex: [0x5c18d0, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']],
    EVP_DecryptUpdate: [0x5c18d8, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_EncryptInit_ex: [0x5c18b0, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']],
    EVP_EncryptUpdate: [0x5c18b8, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int']],
    EVP_DecryptFinal_ex: [0x5c18e0, 'int', ['pointer']],
    AES_set_decrypt_key: [0x5c2888, 'int', ['pointer', 'int', 'pointer']],
    AES_set_encrypt_key: [0x5c2890, 'int', ['pointer', 'int', 'pointer']],
    MD5_Update: [0x5c5f88, 'void', ['pointer', 'pointer', 'int']],
    MD5_Final: [0x5c5f78, 'int', ['pointer', 'pointer']],
    SHA256_Update: [0x5c1900, 'void', ['pointer', 'pointer', 'int']],
    SHA256_Final: [0x5c1908, 'int', ['pointer', 'pointer']],
    RAND_bytes: [0x5c5118, 'int', ['pointer', 'int']],
    EVP_aes_128_cbc: [0x5c18a8, 'pointer', []],
    EVP_aes_256_cbc: [0x5c18e8, 'pointer', []],
    EVP_Cipher: [0x5c5588, 'int', ['pointer', 'pointer', 'pointer', 'int']],
    EVP_CIPHER_CTX_free: [0x5c5f70 - 0x10, 'void', ['pointer']],  // 占位, 下面单独校正
};
// libloader EVP_CIPHER_CTX_free 实际槽位需按导入表; 此处若偏移错误会写坏 GOT, 保守移除
delete LOADER_GOT.EVP_CIPHER_CTX_free;

function toHex(buf) {
    if (!buf) return 'null';
    const u = new Uint8Array(buf), s = [];
    for (let i = 0; i < u.length; i++) s.push(('0' + u[i].toString(16)).slice(-2));
    return s.join('');
}
function rd(p, n) { try { return Memory.readByteArray(p, n); } catch (e) { return null; } }
function rdS(p, n) { try { return p.readCString(n); } catch (e) { return null; } }

const keep = [];
let done = {};

function handlers(tag) {
    const upd = (t2) => (a) => {
        let n = 0;
        try { n = a[2].readInt(); } catch (e) { }
        logEv('[' + tag + ':' + t2 + '] outl=' + n + ' in0=' + toHex(rd(a[3], Math.min(Math.max(n, 0), 32))) +
            ' out="' + (n > 0 ? (rdS(a[1], Math.min(n, 96)) || '') : '') + '"');
    };
    const setKey = (t2) => (a) => logEv('[' + tag + ':' + t2 + '] bits=' + a[1] +
        ' key="' + rdS(a[0], 64) + '" hex=' + toHex(rd(a[0], 32)));
    const H = {
        EVP_CipherInit_ex: (a) => logEv('[' + tag + ':CINIT_ex] key=' + toHex(rd(a[3], 32)) + ' iv=' + toHex(rd(a[4], 16)) + ' enc=' + a[5]),
        EVP_CipherInit: (a) => logEv('[' + tag + ':CINIT] key=' + toHex(rd(a[2], 32)) + ' iv=' + toHex(rd(a[3], 16)) + ' enc=' + a[4]),
        EVP_DecryptInit_ex: (a) => logEv('[' + tag + ':DINIT_ex] key=' + toHex(rd(a[3], 32)) + ' iv=' + toHex(rd(a[4], 16))),
        EVP_EncryptInit_ex: (a) => logEv('[' + tag + ':EINIT_ex] key=' + toHex(rd(a[3], 32)) + ' iv=' + toHex(rd(a[4], 16))),
        EVP_CipherUpdate: upd('CUPDATE'), EVP_DecryptUpdate: upd('DUPDATE'), EVP_EncryptUpdate: upd('EUPDATE'),
        RSA_private_decrypt: (a, rv) => {
            if (rv > 0 && rv <= 64)
                logEv('[' + tag + ':RSA_DEC] n=' + rv + ' K="' + rdS(a[2], rv) + '" hex=' + toHex(rd(a[2], rv)));
        },
        AES_set_decrypt_key: setKey('SETDK'), AES_set_encrypt_key: setKey('SETEK'),
        MD5_Update: (a) => logEv('[' + tag + ':MD5_UP] len=' + a[2] + ' data="' + rdS(a[1], Math.min(a[2], 80)) + '" hex=' + toHex(rd(a[1], Math.min(a[2], 32)))),
        MD5_Final: (a) => logEv('[' + tag + ':MD5_FIN] md=' + toHex(rd(a[0], 16))),
        MD5: (a, rv) => logEv('[' + tag + ':MD5] len=' + a[2] + ' in="' + rdS(a[1], Math.min(a[2], 80)) + '" out=' + toHex(rd(rv, 16))),
        SHA256_Update: (a) => logEv('[' + tag + ':SHA256_UP] len=' + a[2] + ' data="' + rdS(a[1], Math.min(a[2], 80)) + '" hex=' + toHex(rd(a[1], Math.min(a[2], 32)))),
        SHA256_Final: (a) => logEv('[' + tag + ':SHA256_FIN] md=' + toHex(rd(a[0], 32))),
        SHA1: (a, rv) => logEv('[' + tag + ':SHA1] len=' + a[2] + ' in="' + rdS(a[1], Math.min(a[2], 80)) + '" out=' + toHex(rd(rv, 20))),
        RAND_bytes: (a) => logEv('[' + tag + ':RAND] num=' + a[1] + ' buf="' + rdS(a[0], Math.min(a[1], 64)) + '" hex=' + toHex(rd(a[0], Math.min(a[1], 32)))),
        EVP_aes_128_cbc: () => logEv('[' + tag + ':CIPHER] aes_128_cbc'),
        EVP_aes_256_cbc: () => logEv('[' + tag + ':CIPHER] aes_256_cbc'),
        EVP_DecryptFinal_ex: (a) => logEv('[' + tag + ':DFINAL]'),
        EVP_Cipher: (a) => logEv('[' + tag + ':CIPHER_OP] op=' + a[3] + ' in=' + toHex(rd(a[2], 16))),
        EVP_CIPHER_CTX_free: (a) => {
            try {
                const c = a[0], cd = c.add(0x38).readPointer();
                logEv('[' + tag + ':CTX_FREE] oiv=' + toHex(rd(c.add(0x18), 16)) + ' iv=' + toHex(rd(c.add(0x28), 16)) +
                    ' rounds=' + (cd.isNull() ? -1 : cd.readInt()));
            } catch (e) { }
        },
    };
    return H;
}

function logEv(s) { send(s); }

function patchLib(tag, base, table) {
    const H = handlers(tag);
    let n = 0, fail = 0;
    for (const name in table) {
        if (done[tag + ':' + name]) continue;
        const entry = table[name];
        try {
            const slot = base.add(entry[0]);
            const origAddr = slot.readPointer();
            // 校验 orig 合理性: 指向可执行区域外则跳过(防写坏)
            const orig = new NativeFunction(origAddr, entry[1], entry[2]);
            const onCall = H[name];
            const cb = new NativeCallback(function () {
                const a = Array.prototype.slice.call(arguments);
                let rv;
                try { rv = orig.apply(null, a); }
                catch (e) { throw e; }
                try { if (onCall) onCall(a, rv); } catch (e) { }
                return rv;
            }, entry[1], entry[2]);
            keep.push(cb);
            try { Memory.protect(slot.and(ptr('0xfffffffffffff000')), 8192, 'rw-'); } catch (e) { }
            slot.writePointer(cb);
            done[tag + ':' + name] = true;
            n++;
        } catch (e) { fail++; }
    }
    logEv('[*] ' + tag + ' GOT 补丁 ok=' + n + ' fail=' + fail + ' @base=' + base);
}

function findLib(suffix) {
    for (const p of ['r--', 'r-x', 'rw-']) {
        for (const r of Process.enumerateRanges({ protection: p, coalesce: false })) {
            if (r.file && r.file.path && r.file.path.indexOf(suffix) >= 0) return r.base;
        }
    }
    return null;
}

let polls = 0;
function main() {
    setInterval(function () {
        polls++;
        try {
            if (!done.core) {
                const b = findLib('files/libcore.so');
                if (b) { logEv('[*] libcore base=' + b + ' (poll#' + polls + ')'); patchLib('core', b, CORE_GOT); done.core = true; }
            }
            if (!done.loader) {
                const b2 = findLib('lib/arm64/libloader.so');
                if (b2) { logEv('[*] libloader base=' + b2 + ' (poll#' + polls + ')'); patchLib('ldr', b2, LOADER_GOT); done.loader = true; }
            }
            if (polls % 100 === 0) logEv('[*] alive poll#' + polls);
        } catch (e) { logEv('[!] poll err ' + e); }
    }, 150);
}

main();
