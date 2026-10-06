// rd.js — 读真机 libcore 指定偏移的实时值
recv('go', function (msg) {
    var base = ptr(msg.base);
    var offs = msg.offs || [];
    var out = [];
    for (var i = 0; i < offs.length; i++) {
        var o = offs[i];
        var hex = '';
        try {
            var buf = new Uint8Array(base.add(o[0]).readByteArray(o[1]));
            for (var k = 0; k < buf.length; k++) hex += ('0' + buf[k].toString(16)).slice(-2);
        } catch (e) { hex = '<e ' + e + '>'; }
        out.push({ off: o[0], n: o[1], hex: hex });
    }
    send({ ev: 'vals', vals: out });
});
