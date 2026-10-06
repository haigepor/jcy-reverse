// dump_libcore.js — 整段 dump 真机 libcore 映像 (含 .bss 匿名延伸)
recv('go', function (msg) {
    var base = ptr(msg.base);
    var total = msg.total;
    var CH = 0x10000;
    var off = 0;
    send({ ev: 'start', base: base.toString(), total: total });
    while (off < total) {
        var n = Math.min(CH, total - off);
        var ok = false, hex = '';
        for (var tryN = 0; tryN < 3 && !ok; tryN++) {
            try {
                var buf = base.add(off).readByteArray(n);
                var b = new Uint8Array(buf);
                var parts = [];
                for (var i = 0; i < b.length; i++) parts.push(('0' + b[i].toString(16)).slice(-2));
                hex = parts.join('');
                ok = true;
            } catch (e) {
                // 该页不可读: 用零填充
                hex = '';
                for (var k = 0; k < n; k++) hex += '00';
                ok = true;
                send({ ev: 'unreadable', off: off, n: n });
            }
        }
        send({ ev: 'chunk', off: off, n: n, hex: hex });
        off += n;
    }
    send({ ev: 'done' });
});
