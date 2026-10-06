'use strict';
/* diag2.js - 测绘活体代码/数据: 匿名 exec 段函数特征 + 全内存明文常量定位 */
const CONSTS = {
    qPwC_key: 'qPwClBj7j7ZQraSm',
    p3Jd_iv: 'p3JdVQl3q7WQJIgG',
    kFGT_key: 'kFGTbLlOzFHQCIKp',
    F3q2_iv: 'F3q22XoM8l6T2Ydc',
    rsa_mod: 'c66d8aceef4bfc5357e367a6f57a3bdc95ed242b6b8657',
    rand_alpha: 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890',
    b64_alpha: '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj',
    action: 'api_decrypt',
};
// 20B 函数特征: [名, 文件偏移, hex]
const SIGS = [
    ['core.EVP_CipherInit_ex', 0x387368],
    ['core.RSA_private_decrypt', 0x43e324],
    ['core.AES_set_decrypt_key', 0x3845e0],
    ['core.EVP_DecryptUpdate', 0x3877d0],
    ['core.MD5_Update', 0x422eb0],
    ['core.RAND_bytes', 0x438d18],
    ['ldr.EVP_CipherInit_ex', 0x35ae68],
    ['ldr.RSA_private_decrypt', 0x412324],
    ['ldr.AES_set_decrypt_key', 0x3580dc],
    ['ldr.EVP_DecryptUpdate', 0x35b2d0],
    ['ldr.MD5_Update', 0x3f6eb0],
    ['ldr.RAND_bytes', 0x40cd18],
];

function hexOf(s) {
    let out = '';
    for (let i = 0; i < s.length; i++) {
        const h = ('0' + (s.charCodeAt(i) & 0xff).toString(16));
        out += h.slice(-2);
    }
    return out;
}

function main() {
    send('[*] 开始: 匿名 exec 段清单');
    const anonExec = [];
    for (const p of ['r-x', 'rwx']) {
        for (const r of Process.enumerateRanges({ protection: p, coalesce: false })) {
            if (r.file && r.file.path) continue;
            anonExec.push(r);
        }
    }
    send('[*] 匿名 exec 段 ' + anonExec.length + ' 个: ' +
        anonExec.map(r => r.base + '(' + r.size + ')').join(' ').slice(0, 900));

    // 特征码由 PC 注入: SIGHEX 全局变量
    if (typeof SIGHEX !== 'undefined') {
        let hitTotal = 0;
        for (const r of anonExec) {
            if (r.size < 0x10000) continue;
            for (const [name, sig] of SIGHEX) {
                try {
                    const hits = Memory.scanSync(r.base, r.size, sig);
                    for (const h of hits) {
                        hitTotal++;
                        send('[SIG] ' + name + ' @' + h.address + ' (range ' + r.base + ')');
                    }
                } catch (e) { }
            }
        }
        send('[*] 匿名 exec 特征命中 ' + hitTotal);
    }

    // 常量扫描(全可读)
    for (const cname in CONSTS) {
        const pat = hexOf(CONSTS[cname]);
        let n = 0;
        const seen = [];
        for (const p of ['r--', 'rw-', 'r-x', 'rwx']) {
            for (const r of Process.enumerateRanges({ protection: p, coalesce: false })) {
                if (r.size < 0x4000) continue;
                try {
                    const hits = Memory.scanSync(r.base, r.size, pat);
                    for (const h of hits) {
                        n++;
                        const inFile = r.file && r.file.path ? r.file.path.split('/').pop() : 'anon:' + r.protection;
                        if (seen.length < 14) seen.push(inFile + '@' + h.address);
                    }
                } catch (e) { }
            }
        }
        send('[CONST] ' + cname + ' 命中 ' + n + ': ' + seen.join(' | '));
    }
    send('[*] done');
}

main();
