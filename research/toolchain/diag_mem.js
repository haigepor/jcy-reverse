'use strict';
/* diag_mem.js - 诊断 libcore 匿名映射位置: 全保护段扫描 + 大段清单 */
function hex2buf(s) {
    const a = new Uint8Array(s.length / 2);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16);
    return a.buffer;
}

// 20B 短特征 (0x385400 set_decrypt_key 序言)
const SIG20 = '3f2303d5fd7bbfa9fd03009175ffff971f0000f1';
// 64B 长特征: libcore_files.so @0x385400 起 64 字节 (由 PC 侧校验与文件一致)
const SIG64 = '3f2303d5fd7bbfa9fd03009175ffff971f0000f1600f0054a9020091'; // 前 30B

function main() {
    const mods = Process.enumerateModules();
    const named = new Set();
    for (const m of mods) named.add(m.base.toString());

    const ranges = Process.enumerateRanges({ protection: 'r--', coalesce: false })
        .concat(Process.enumerateRanges({ protection: 'rw-', coalesce: false }))
        .concat(Process.enumerateRanges({ protection: 'r-x', coalesce: false }));
    send('[*] 全可读段总数 ' + ranges.length);

    // 大段清单 (>=1MB)
    let anonBig = 0;
    for (const r of ranges) {
        if (r.size >= 0x100000) {
            const hasFile = !!(r.file && r.file.path);
            if (!hasFile) anonBig++;
        }
    }
    send('[*] >=1MB 匿名可读段 ' + anonBig + ' 个, 逐段扫描中...');

    const s20 = hex2buf(SIG20);
    let hit20 = [], hit64 = [];
    for (const r of ranges) {
        if (r.size < 0x1000) continue;
        try {
            const f = Memory.scanSync(r.base, r.size, SIG20);
            for (const m of f) hit20.push([r.base.toString(), r.protection, r.size, m.address.toString()]);
        } catch (e) { }
        try {
            const f2 = Memory.scanSync(r.base, r.size, SIG64);
            for (const m of f2) hit64.push([r.base.toString(), r.protection, r.size, m.address.toString()]);
        } catch (e) { }
    }
    send('[*] SIG20 命中 ' + hit20.length + ' 处');
    for (const h of hit20.slice(0, 20)) send('  [20] range=' + h[0] + ' ' + h[1] + ' size=' + h[2] + ' @' + h[3]);
    send('[*] SIG64 命中 ' + hit64.length + ' 处');
    for (const h of hit64.slice(0, 20)) send('  [64] range=' + h[0] + ' ' + h[1] + ' size=' + h[2] + ' @' + h[3]);

    // 找 ELF 魔数开头的匿名大段 (疑似整 .so 映射)
    let elfAnon = [];
    for (const r of ranges) {
        if (r.size < 0x100000 || (r.file && r.file.path)) continue;
        try {
            const head = Memory.readByteArray(r.base, 4);
            const u = new Uint8Array(head);
            if (u[0] === 0x7f && u[1] === 0x45 && u[2] === 0x4c && u[3] === 0x46)
                elfAnon.push(r.base.toString() + ' ' + r.protection + ' size=' + r.size);
        } catch (e) { }
    }
    send('[*] ELF 头匿名大段 ' + elfAnon.length + ' 个');
    for (const e of elfAnon) send('  [ELF] ' + e);
}

main();
