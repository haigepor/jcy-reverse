#!/usr/bin/env python3
"""dev_dump_registry.py - dump 真机 libcore slot-12 handler 注册表 + 16 槽状态."""
import frida

JS = r"""
function coreBase() {
    var f = new File('/proc/self/maps', 'r');
    var line; var first = null;
    while ((line = f.readLine()) !== null && line !== '' && line !== undefined) {
        if (line.indexOf('files/libcore.so') >= 0) {
            var b = parseInt(line.split('-')[0], 16);
            if (first === null || b < first) first = b;
        }
    }
    f.close();
    return first;
}
function rd(p, n) {
    try { return Array.from(new Uint8Array(p.readByteArray(n)))
        .map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }
    catch (e) { return 'ERR:' + e; }
}
function p64(p) {
    var h = rd(p, 8);
    if (h.indexOf('ERR') === 0) return null;
    return h;
}
rpc.exports.dump = function () {
    var base = coreBase();
    if (base === null) return JSON.stringify({ err: 'no core' });
    var B = ptr(base);
    var out = { base: B.toString() };
    out.flags_68db78 = rd(B.add(0x68db78), 8);
    var slots = [];
    for (var i = 0; i < 16; i++) {
        slots.push(p64(B.add(0x68daf0 + i * 8)));
    }
    out.slots = slots;
    var obj = slots[12];
    if (obj && obj.indexOf('ERR') !== 0) {
        var op = ptr(obj);
        var raw0 = p64(op);
        var raw8 = p64(op.add(8));
        out.slot12 = { raw0: raw0, raw8: raw8 };
        if (raw0 && raw8) {
            var cnt = parseInt(raw0.substr(0, 8), 16);  // int32 LE
            out.count = cnt;
            var arr = ptr('0x' + raw8);
            out.arr = arr.toString();
            var items = [];
            for (var j = 0; j < cnt && j < 16; j++) {
                var ip = p64(arr.add(j * 8));
                if (ip && ip.indexOf('ERR') !== 0) {
                    var it = ptr('0x' + ip);
                    items.push({
                        item: it.toString(),
                        f0: p64(it),
                        f8: p64(it.add(8)),
                        fn: p64(it.add(16))
                    });
                } else { items.push({ err: ip }); }
            }
            out.items = items;
        }
    }
    return JSON.stringify(out);
};
rpc.exports.slots2 = function () {
    var base = coreBase();
    var B = ptr(base);
    var o = {};
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15].forEach(function (i) {
        var v = p64(B.add(0x68daf0 + i * 8));
        if (v && v.indexOf('ERR') !== 0 && v !== '0000000000000000') o['slot' + i] = v;
    });
    return JSON.stringify(o);
};
"""


def main():
    dev = frida.get_device('127.0.0.1:5555')
    sess = dev.attach('囧次元')
    sc = sess.create_script(JS)
    sc.load()
    import json
    o = json.loads(sc.exports_sync.dump())
    print(json.dumps(o, indent=1))
    sess.detach()


if __name__ == '__main__':
    main()
