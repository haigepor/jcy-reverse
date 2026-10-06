'use strict';
/* hunt_key.js - dlopen 时机 hook libcore 的 RSA/AES 底层入口, 抓响应解密 key/iv */
const TARGETS = ['aes_v8_set_decrypt_key', 'aes_v8_set_encrypt_key',
    'EVP_DecryptInit_ex', 'RSA_private_decrypt', 'aes_v8_cbc_encrypt'];

function hexbuf(p, n) {
    try { return Memory.readByteArray(p, n); } catch (e) { return null; }
}

function doHooks(mod) {
    let hooked = 0;
    const exps = mod.enumerateExports();
    for (const e of exps) {
        if (TARGETS.indexOf(e.name) < 0) continue;
        if (e.name === 'aes_v8_set_decrypt_key' || e.name === 'aes_v8_set_encrypt_key') {
            Interceptor.attach(e.address, {
                onEnter: function (args) {
                    const bits = args[1].toInt32();
                    if (bits !== 128 && bits !== 256) return;
                    send('[SET_KEY ' + e.name + '] bits=' + bits +
                        ' key="' + args[0].readCString(64) + '"');
                }
            });
            hooked++;
        } else if (e.name === 'EVP_DecryptInit_ex') {
            Interceptor.attach(e.address, {
                onEnter: function (args) {
                    const k = args[3], iv = args[4];
                    send('[EVP_INIT] key=' + (k.isNull() ? 'NULL' : hexbuf(k, 16)) +
                        ' iv=' + (iv.isNull() ? 'NULL' : hexbuf(iv, 16)));
                }
            });
            hooked++;
        } else if (e.name === 'RSA_private_decrypt') {
            Interceptor.attach(e.address, {
                onEnter: function (args) {
                    this.to = args[2];
                },
                onLeave: function (ret) {
                    const n = ret.toInt32();
                    if (n > 0 && n <= 64) {
                        send('[RSA_DEC] n=' + n + ' K="' + this.to.readCString(64) + '"');
                    }
                }
            });
            hooked++;
        } else if (e.name === 'aes_v8_cbc_encrypt') {
            Interceptor.attach(e.address, {
                onEnter: function (args) {
                    const len = args[2].toInt32();
                    if (len < 16 || len > 65536) return;
                    this.out = args[1];
                    this.len = len;
                },
                onLeave: function (ret) {
                    try {
                        send('[CBC_DEC] len=' + this.len +
                            ' out0="' + this.out.readCString(64) + '"');
                    } catch (err) { }
                }
            });
            hooked++;
        }
    }
    send('[*] hooked ' + hooked + ' / libcore base=' + mod.base);
}

let done = false;
const NAMES = ['android_dlopen_ext', 'dlopen', '__loader_dlopen', 'do_dlopen'];
let dlopens = [];
for (const nm of NAMES) {
    try { dlopens.push([nm, Module.getGlobalExportByName(nm)]); } catch (e) { }
}
if (dlopens.length === 0) send('[!] 无 dlopen 入口');
const dlopen = dlopens[0][1];
for (const [nm, addr] of dlopens) {
Interceptor.attach(addr, {
    onEnter: function (args) {
        try { this.path = args[0].readCString(); if (this.path && this.path.indexOf('.so') >= 0) send('[dlopen] ' + this.path); } catch (e) { this.path = null; }
    },
    onLeave: function (ret) {
        if (done || !this.path) return;
        if (this.path.indexOf('libcore.so') < 0) return;
        done = true;
        const m = Process.findModuleByName('libcore.so');
        if (m) doHooks(m);
        else send('[!] dlopen 返回但模块未找到');
    }
});
}
send('[*] dlopen hook 就绪');
