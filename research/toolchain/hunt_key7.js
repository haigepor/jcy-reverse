'use strict';
/* hunt_key7.js - 直接 hook 两库本地函数入口(libcore 偏移来自 hunt5 orig 指针, libloader 来自 dynsym)
 * + GOT 补丁双保险; 触发靠 PC 侧 tap/monkey */
const LIBS = {
    core: {
        suffix: 'files/libcore.so',
        fns: {
            EVP_CipherInit_ex: [0x387368, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'int'], 'init'],
            EVP_CipherInit: [0x387308, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], 'init'],
            EVP_CipherUpdate: [0x387780, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], 'upd'],
            EVP_DecryptUpdate: [0x3877d0, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], 'upd'],
            EVP_EncryptUpdate: [0x387790, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], 'upd'],
            RSA_private_decrypt: [0x43e324, 'int', ['int', 'pointer', 'pointer', 'pointer', 'int'], 'rsa'],
            AES_set_decrypt_key: [0x3845e0, 'int', ['pointer', 'int', 'pointer'], 'setkey'],
            AES_set_encrypt_key: [0x3842ac, 'int', ['pointer', 'int', 'pointer'], 'setkey'],
            MD5_Update: [0x422eb0, 'void', ['pointer', 'pointer', 'int'], 'hash'],
            MD5_Final: [0x4239c0, 'int', ['pointer', 'pointer'], 'hashfin'],
            MD5: [0x423ab4, 'pointer', ['pointer', 'pointer', 'int'], 'hash1'],
            SHA256_Update: [0x449b10, 'void', ['pointer', 'pointer', 'int'], 'hash'],
            SHA256_Final: [0x449c14, 'int', ['pointer', 'pointer'], 'hashfin'],
            SHA1: [0x44848c, 'pointer', ['pointer', 'pointer', 'int'], 'hash1'],
            RAND_bytes: [0x438d18, 'int', ['pointer', 'int'], 'rand'],
            EVP_aes_128_cbc: [0x381fe4, 'pointer', [], 'cipher'],
            EVP_aes_256_cbc: [0x38208c, 'pointer', [], 'cipher'],
            EVP_CIPHER_CTX_free: [0x3872d8, 'void', ['pointer'], 'ctxfree'],
        },
    },
    ldr: {
        suffix: 'lib/arm64/libloader.so',
        fns: {
            EVP_CipherInit_ex: [0x35ae68, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'int'], 'init'],
            EVP_CipherInit: [0x35ae08, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], 'init'],
            EVP_CipherUpdate: [0x35b280, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], 'upd'],
            EVP_DecryptUpdate: [0x35b2d0, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], 'upd'],
            EVP_EncryptUpdate: [0x35b290, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int'], 'upd'],
            RSA_private_decrypt: [0x412324, 'int', ['int', 'pointer', 'pointer', 'pointer', 'int'], 'rsa'],
            AES_set_decrypt_key: [0x3580dc, 'int', ['pointer', 'int', 'pointer'], 'setkey'],
            AES_set_encrypt_key: [0x357da8, 'int', ['pointer', 'int', 'pointer'], 'setkey'],
            MD5_Update: [0x3f6eb0, 'void', ['pointer', 'pointer', 'int'], 'hash'],
            MD5_Final: [0x3f79c0, 'int', ['pointer', 'pointer'], 'hashfin'],
            SHA256_Update: [0x41db10, 'void', ['pointer', 'pointer', 'int'], 'hash'],
            SHA256_Final: [0x41dc14, 'int', ['pointer', 'pointer'], 'hashfin'],
            RAND_bytes: [0x40cd18, 'int', ['pointer', 'int'], 'rand'],
            EVP_aes_128_cbc: [0x355ae0, 'pointer', [], 'cipher'],
            EVP_aes_256_cbc: [0x355b88, 'pointer', [], 'cipher'],
            EVP_CipherFinal_ex: [0x35b598, 'int', ['pointer', 'pointer', 'pointer'], 'ctxfree'],
        },
    },
};

function toHex(buf) {
    if (!buf) return 'null';
    const u = new Uint8Array(buf), s = [];
    for (let i = 0; i < u.length; i++) s.push(('0' + u[i].toString(16)).slice(-2));
    return s.join('');
}
function rd(p, n) { try { return Memory.readByteArray(p, n); } catch (e) { return null; } }
function rdS(p, n) { try { return p.readCString(n); } catch (e) { return null; } }

function onEv(tag, name, kind) {
    const t = tag + ':' + name;
    switch (kind) {
        case 'init':
            return function (args) {
                const key = args[3] || args[2], iv = args[4] || args[3];
                send('[' + t + '] key=' + toHex(rd(key, 32)) + ' iv=' + toHex(rd(iv, 16)));
            };
        case 'upd':
            return function (args) {
                this.out = args[1]; this.outl = args[2]; this.inp = args[3]; this.len = args[4].toInt32();
            };
        case 'rsa':
            return function (args) { this.to = args[2]; };
        case 'setkey':
            return function (args) {
                const bits = args[1].toInt32();
                if (bits !== 128 && bits !== 256) return;
                send('[' + t + '] bits=' + bits + ' key="' + rdS(args[0], 64) + '" hex=' + toHex(rd(args[0], 32)));
            };
        case 'hash':
            return function (args) {
                const n = args[2].toInt32();
                if (n <= 0 || n > 512) return;
                send('[' + t + '] len=' + n + ' data="' + rdS(args[1], Math.min(n, 80)) + '" hex=' + toHex(rd(args[1], Math.min(n, 32))));
            };
        case 'hashfin':
            return function (args) { this.md = args[0]; };
        case 'hash1':
            return function (args) { this.inp = args[1]; this.n = args[2].toInt32(); };
        case 'rand':
            return function (args) { this.buf = args[0]; this.n = args[1].toInt32(); };
        case 'cipher':
            return function () { send('[' + t + '] call'); };
        case 'ctxfree':
            return function (args) { this.ctx = args[0]; };
    }
    return null;
}

function onLeaveEv(tag, name, kind) {
    const t = tag + ':' + name;
    switch (kind) {
        case 'upd':
            return function (retval) {
                let n = 0;
                try { n = this.outl.readInt(); } catch (e) { }
                if (n > 0)
                    send('[' + t + '] outl=' + n + ' in0=' + toHex(rd(this.inp, 16)) +
                        ' out="' + (rdS(this.out, Math.min(n, 96)) || toHex(rd(this.out, Math.min(n, 16)))) + '"');
            };
        case 'rsa':
            return function (retval) {
                const n = retval.toInt32();
                if (n > 0 && n <= 64)
                    send('[' + t + '] n=' + n + ' K="' + rdS(this.to, n) + '" hex=' + toHex(rd(this.to, n)));
            };
        case 'hashfin':
            return function (retval) {
                const sz = t.indexOf('SHA256') >= 0 ? 32 : 16;
                send('[' + t + '] md=' + toHex(rd(this.md, sz)));
            };
        case 'hash1':
            return function (retval) {
                const sz = t.indexOf('SHA1') >= 0 ? 20 : 16;
                send('[' + t + '] len=' + this.n + ' in="' + rdS(this.inp, Math.min(this.n, 80)) + '" out=' + toHex(rd(retval, sz)));
            };
        case 'rand':
            return function (retval) {
                send('[' + t + '] num=' + this.n + ' buf="' + rdS(this.buf, Math.min(this.n, 64)) + '" hex=' + toHex(rd(this.buf, Math.min(this.n, 32))));
            };
        case 'ctxfree':
            return function (retval) {
                try {
                    if (t.endsWith('CTX_free')) {
                        const c = this.ctx, cd = c.add(0x38).readPointer();
                        send('[' + t + '] oiv=' + toHex(rd(c.add(0x18), 16)) + ' iv=' + toHex(rd(c.add(0x28), 16)) +
                            ' rounds=' + (cd.isNull() ? -1 : cd.readInt()));
                    } else {
                        send('[' + t + '] fin out="' + rdS(this.ctx, 32) + '"');
                    }
                } catch (e) { }
            };
    }
    return null;
}

const hooked = {};
function attachLib(tag, base, fns) {
    let ok = 0, fail = 0;
    for (const name in fns) {
        if (hooked[tag + ':' + name]) continue;
        const [off, ret, args, kind] = fns[name];
        try {
            const a = onEv(tag, name, kind);
            const l = onLeaveEv(tag, name, kind);
            Interceptor.attach(base.add(off), a ? { onEnter: a, onLeave: l } : (l ? { onLeave: l } : { onEnter: function () { } }));
            hooked[tag + ':' + name] = true;
            ok++;
        } catch (e) { fail++; send('[!] attach fail ' + tag + ':' + name + ' ' + e.message); }
    }
    send('[*] ' + tag + ' 入口 hook ok=' + ok + ' fail=' + fail + ' @base=' + base);
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
            for (const tag in LIBS) {
                if (hooked['base:' + tag]) continue;
                const b = findLib(LIBS[tag].suffix);
                if (b) { hooked['base:' + tag] = true; attachLib(tag, b, LIBS[tag].fns); }
            }
            if (polls % 100 === 0) send('[*] alive poll#' + polls + ' hooked=' + Object.keys(hooked).length);
        } catch (e) { send('[!] poll err ' + e); }
    }, 300);
}

main();
