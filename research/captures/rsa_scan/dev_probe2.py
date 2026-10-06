#!/usr/bin/env python3
"""dev_probe2.py - 真机综合探针:
1) dump 关键全局 (0x68dad8, 通道槽, E 管线槽)
2) RWX 执行副本定位 (入口字节扫描)
3) Interceptor 挂 RSA 包装 0x43e324 / 分叉区入口, 等应用流量触发
"""
import json
import sys
import time

import frida

JS = r"""
var EXEC = null;
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
function rwxRange() {
    var rs = Process.enumerateRanges('r-x');
    for (var i = 0; i < rs.length; i++) {
        var b = rs[i].base.toString(16);
        if (b.indexOf('40006014') === 0) return rs[i];
    }
    return null;
}
function rd(p, n) {
    try { return Array.from(new Uint8Array(p.readByteArray(n)))
        .map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }
    catch (e) { return 'ERR'; }
}
rpc.exports.globals = function () {
    var B = ptr(coreBase());
    return JSON.stringify({
        base: B.toString(),
        g68dad8: rd(B.add(0x68dad8), 16),
        g68db70: rd(B.add(0x68db70), 16),
        ks_key: rd(B.add(0x689528), 20),
        ks_iv: rd(B.add(0x689540), 20),
        pipe_key: rd(B.add(0x688130), 24),
        pipe_iv: rd(B.add(0x688148), 24),
        vm_tab: rd(B.add(0x67c028), 16)
    });
};
rpc.exports.findexec = function () {
    var r = rwxRange();
    if (!r) return JSON.stringify({ err: 'no rwx' });
    var pat = 'fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9';
    var found = [];
    try {
        var m = Memory.scanSync(r.base, Math.min(r.size, 0x10000000), pat);
        for (var i = 0; i < m.length; i++) found.push(m[i].address.toString());
    } catch (e) { return JSON.stringify({ err: '' + e }); }
    return JSON.stringify({ range: r.base + ' sz=' + r.size, hits: found });
};
rpc.exports.hook = function (execStr) {
    var E = ptr(execStr);
    var log = [];
    function mk(off, label) {
        try {
            Interceptor.attach(E.add(off), {
                onEnter: function (args) {
                    this.t = label;
                    log.push(label + ' HIT x0=' + args[0] + ' x1=' + args[1] + ' x2=' + args[2] +
                        ' x3=' + args[3] + ' lr=' + this.returnAddress.sub(E));
                }
            });
            return label + '@+0x' + off.toString(16) + ' OK';
        } catch (e) { return label + ' FAIL ' + e; }
    }
    var st = [];
    st.push(mk(0x43e324, 'RSA_WRAP'));
    st.push(mk(0x335544, 'FORK_A'));
    st.push(mk(0x3373b4, 'FORK_B'));
    st.push(mk(0x2cd8b0, 'E_KSA'));
    EXEC = E;
    return JSON.stringify({ status: st, log: log });
};
rpc.exports.pull = function () {
    return JSON.stringify({ log: globalThis._log || [] });
};
rpc.exports.enablelog = function () {
    globalThis._log = globalThis._log || [];
    return 'ok';
};
"""


def main():
    dev = frida.get_device('127.0.0.1:5555')
    sess = dev.attach('囧次元')
    sc = sess.create_script(JS)
    sc.load()
    print('[globals]', sc.exports_sync.globals())
    fx = json.loads(sc.exports_sync.findexec())
    print('[findexec]', json.dumps(fx))
    if fx.get('hits'):
        exec_base = int(fx['hits'][0], 16) - 0x307a38
        print('[exec_base] 0x%x' % exec_base)
        print('[hooks]', sc.exports_sync.hook(hex(exec_base)))
        print('[*] hooks 已挂, 等待应用流量 45s...')
        time.sleep(45)
        try:
            print('[pull]', sc.exports_sync.pull())
        except Exception as ex:
            print('[pull] fail', ex)
    sess.detach()


if __name__ == '__main__':
    main()
