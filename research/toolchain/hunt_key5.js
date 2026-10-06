'use strict';
/* hunt_key5.js - GOT 补丁法 hook libcore 加密函数(抗代码页翻转)
 * 基址: 按 /files/libcore.so 文件映射路径定位; GOT 槽位来自 .rela.plt 静态解析 */
const GOT = {
    RAND_bytes: 0x6612a8,
    MD5: 0x6613b0,
    SHA1: 0x661230,
    RSA_public_encrypt: 0x6613f0,
    RSA_private_decrypt: 0x6613f8,
    EVP_aes_128_cbc: 0x661400,
    EVP_EncryptInit_ex: 0x661408,
    EVP_EncryptUpdate: 0x661410,
    EVP_CIPHER_CTX_free: 0x661420,
    EVP_DecryptInit_ex: 0x661428,
    EVP_DecryptUpdate: 0x661430,
    EVP_aes_256_cbc: 0x661440,
    SHA256_Init: 0x661448,
    SHA256_Update: 0x661458,
    SHA256_Final: 0x661460,
    EVP_CIPHER_CTX_new: 0x6614b0,
    AES_set_decrypt_key: 0x6622a8,
    AES_set_encrypt_key: 0x6622b0,
    EVP_CipherInit: 0x664e98,
    EVP_CipherInit_ex: 0x664ea0,
    EVP_CipherUpdate: 0x664ea8,
    SHA1_Init: 0x665488,
    SHA1_Final: 0x665480,
    MD5_Final: 0x665910,
    MD5_Init: 0x665918,
    MD5_Update: 0x665920,
};

function toHex(buf) {
    if (!buf) return 'null';
    const u = new Uint8Array(buf), s = [];
    for (let i = 0; i < u.length; i++) s.push(('0' + u[i].toString(16)).slice(-2));
    return s.join('');
}
function rd(p, n) { try { return Memory.readByteArray(p, n); } catch (e) { return null; } }
function rdS(p, n) { try { return p.readCString(n); } catch (e) { return null; } }

const keep = [];      // NativeCallback 引用防 GC
const stubs = {};     // name -> {slot, cb, orig}
let BASE = null;
let baseSize = 0;

function logEv(s) { send(s); }

function patchAll(base) {
    BASE = base;
    const S = {};
    for (const k in GOT) S[k] = base.add(GOT[k]);

    // 1. 记录原始槽位值
    for (const k in S) {
        try {
            const v = S[k].readPointer();
            const inside = v.compare(base) >= 0 && v.compare(base.add(0x800000)) < 0;
            logEv('[SLOT] ' + k + ' = ' + v + (inside ? ' (libcore 内部: lazy/本地)' : ' (外部: 已绑定)'));
        } catch (e) { logEv('[SLOT] ' + k + ' 读取失败 ' + e); }
    }

    function patch(name, retType, argTypes, onCall) {
        const slot = S[name];
        if (!slot) return;
        try {
            const origAddr = slot.readPointer();
            const orig = new NativeFunction(origAddr, retType, argTypes);
            const cb = new NativeCallback(function () {
                const a = Array.prototype.slice.call(arguments);
                let rv;
                try { rv = orig.apply(null, a); }
                catch (e) { logEv('[!] orig ' + name + ' exc'); throw e; }
                try { onCall(a, rv); } catch (e) { }
                return rv;
            }, retType, argTypes);
            keep.push(cb);
            // loader 平铺映射整文件为只读, 先开写权限再补丁
            try { Memory.protect(slot.and(ptr('0xfffffffffffff000')), 8192, 'rw-'); }
            catch (e) { logEv('[!] protect fail ' + name + ': ' + e); }
            slot.writePointer(cb);
            stubs[name] = { slot: slot, cb: cb, origAddr: origAddr };
            logEv('[+] patched ' + name + ' @' + slot + ' orig=' + origAddr);
        } catch (e) {
            logEv('[!] patch fail ' + name + ': ' + e);
        }
    }

    const upd = (tag) => (a) => {
        let n = 0;
        try { n = a[2].readInt(); } catch (e) { }
        const inHex = toHex(rd(a[3], Math.min(Math.max(n, 0), 32)));
        const outStr = n > 0 ? (rdS(a[1], Math.min(n, 96)) || '') : '';
        logEv('[' + tag + '] outl=' + n + ' in0=' + inHex + ' out="' + outStr + '"');
    };
    const setKey = (tag) => (a) => logEv('[' + tag + '] bits=' + a[1] +
        ' key="' + rdS(a[0], 64) + '" hex=' + toHex(rd(a[0], 32)));

    patch('EVP_CipherInit_ex', 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'int'],
        (a) => logEv('[CINIT_ex] key=' + toHex(rd(a[3], 32)) + ' iv=' + toHex(rd(a[4], 16)) + ' enc=' + a[5]));
    patch('EVP_CipherInit', 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'],
        (a) => logEv('[CINIT] key=' + toHex(rd(a[2], 32)) + ' iv=' + toHex(rd(a[3], 16)) + ' enc=' + a[4]));
    patch('EVP_DecryptInit_ex', 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        (a) => logEv('[DINIT_ex] key=' + toHex(rd(a[3], 32)) + ' iv=' + toHex(rd(a[4], 16))));
    patch('EVP_EncryptInit_ex', 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        (a) => logEv('[EINIT_ex] key=' + toHex(rd(a[3], 32)) + ' iv=' + toHex(rd(a[4], 16))));
    patch('EVP_CipherUpdate', 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], upd('CUPDATE'));
    patch('EVP_DecryptUpdate', 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], upd('DUPDATE'));
    patch('EVP_EncryptUpdate', 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], upd('EUPDATE'));
    patch('RSA_private_decrypt', 'int', ['int', 'pointer', 'pointer', 'pointer', 'int'],
        (a, rv) => {
            if (rv > 0 && rv <= 64)
                logEv('[RSA_DEC] n=' + rv + ' K="' + rdS(a[2], rv) + '" hex=' + toHex(rd(a[2], rv)));
        });
    patch('AES_set_decrypt_key', 'int', ['pointer', 'int', 'pointer'], setKey('SETDK'));
    patch('AES_set_encrypt_key', 'int', ['pointer', 'int', 'pointer'], setKey('SETEK'));
    patch('MD5_Update', 'void', ['pointer', 'pointer', 'int'],
        (a) => logEv('[MD5_UP] len=' + a[2] + ' data="' + rdS(a[1], Math.min(a[2], 80)) + '" hex=' + toHex(rd(a[1], Math.min(a[2], 32)))));
    patch('MD5_Final', 'int', ['pointer', 'pointer'],
        (a) => logEv('[MD5_FIN] md=' + toHex(rd(a[0], 16))));
    patch('MD5', 'pointer', ['pointer', 'pointer', 'int'],
        (a, rv) => logEv('[MD5] len=' + a[2] + ' in="' + rdS(a[1], Math.min(a[2], 80)) + '" out=' + toHex(rd(rv, 16))));
    patch('SHA256_Update', 'void', ['pointer', 'pointer', 'int'],
        (a) => logEv('[SHA256_UP] len=' + a[2] + ' data="' + rdS(a[1], Math.min(a[2], 80)) + '" hex=' + toHex(rd(a[1], Math.min(a[2], 32)))));
    patch('SHA256_Final', 'int', ['pointer', 'pointer'],
        (a) => logEv('[SHA256_FIN] md=' + toHex(rd(a[0], 32))));
    patch('SHA1', 'pointer', ['pointer', 'pointer', 'int'],
        (a, rv) => logEv('[SHA1] len=' + a[2] + ' in="' + rdS(a[1], Math.min(a[2], 80)) + '" out=' + toHex(rd(rv, 20))));
    patch('RAND_bytes', 'int', ['pointer', 'int'],
        (a) => logEv('[RAND] num=' + a[1] + ' buf="' + rdS(a[0], Math.min(a[1], 64)) + '" hex=' + toHex(rd(a[0], Math.min(a[1], 32)))));
    patch('EVP_aes_128_cbc', 'pointer', [], () => logEv('[CIPHER] aes_128_cbc'));
    patch('EVP_aes_256_cbc', 'pointer', [], () => logEv('[CIPHER] aes_256_cbc'));
    patch('EVP_CIPHER_CTX_free', 'void', ['pointer'],
        (a) => {
            try {
                const c = a[0];
                const cd = c.add(0x38).readPointer();
                logEv('[CTX_FREE] oiv=' + toHex(rd(c.add(0x18), 16)) + ' iv=' + toHex(rd(c.add(0x28), 16)) +
                    ' rounds=' + (cd.isNull() ? -1 : cd.readInt()));
            } catch (e) { }
        });

    let n = 0;
    for (const k in stubs) n++;
    logEv('[*] GOT 补丁完成 ' + n + '/26 个 @base=' + base);
}

function findBase() {
    const prots = ['r--', 'r-x', 'rw-'];
    for (const p of prots) {
        for (const r of Process.enumerateRanges({ protection: p, coalesce: false })) {
            if (r.file && r.file.path && r.file.path.indexOf('files/libcore.so') >= 0) return r.base;
        }
    }
    return null;
}

let polls = 0;
function main() {
    setInterval(function () {
        polls++;
        try {
            if (!BASE) {
                const b = findBase();
                if (b) { logEv('[*] 发现 libcore base=' + b + ' (poll#' + polls + ')'); patchAll(b); }
            } else {
                // 只读校验: 槽位被改写仅记录(libcore 为 BIND_NOW, 正常不应发生)
                for (const name in stubs) {
                    const st = stubs[name];
                    const cur = st.slot.readPointer();
                    if (!cur.equals(st.cb)) logEv('[!] 槽位被改写 ' + name + ' -> ' + cur);
                }
            }
            if (polls % 40 === 0) logEv('[*] alive poll#' + polls + ' base=' + BASE);
        } catch (e) { logEv('[!] poll err ' + e); }
    }, 500);
}

main();
