# -*- coding: utf-8 -*-
"""雷电14 Magisk 逆向环境验收：frida spawn + 模块枚举 + 关键 native 库探测"""
import json
import sys
import time

import frida

PKG = "com.tudou.tool"
REMOTE = "127.0.0.1:27042"

JS = r"""
(function () {
    var out = { modules: [], targets: {}, threadNames: [] };
    function snap() {
        var mods = Process.enumerateModules();
        out.modules = mods.map(function (m) { return m.name; });
        ['libflutter.so', 'libapp.so', 'libcore.so', 'libloader.so',
         'libgadget.so', 'libhoudini.so'].forEach(function (n) {
            var m = Process.findModuleByName(n);
            if (m) out.targets[n] = { base: m.base.toString(), size: m.size };
        });
        try {
            Process.enumerateThreads().forEach(function (t) {
                out.threadNames.push(t.name || ('tid' + t.id));
            });
        } catch (e) {}
        send(JSON.stringify(out));
    }
    setTimeout(snap, 8000);
    setTimeout(snap, 20000);
})();
"""


def main():
    dev = frida.get_device_manager().add_remote_device(REMOTE)
    print("[*] device:", dev)
    print("[*] frida-server:", dev.enumerate_processes()[0].pid is not None)

    pid = dev.spawn([PKG])
    print("[*] spawned %s -> pid %d" % (PKG, pid))
    session = dev.attach(pid)

    seen = []

    def on_message(msg, data):
        if msg.get("type") == "send":
            seen.append(msg["payload"])
            info = json.loads(msg["payload"])
            print("[*] modules: %d" % len(info["modules"]))
            for k, v in info["targets"].items():
                print("    %-16s base=%s size=%s" % (k, v["base"], v["size"]))
            print("[*] threads: %d" % len(info["threadNames"]))
        else:
            print("[!]", msg)

    script = session.create_script(JS)
    script.on("message", on_message)
    script.load()
    try:
        session.resume()
    except TypeError:
        session.resume(pid)
    print("[*] resumed, waiting for snapshots ...")
    for _ in range(30):
        time.sleep(1)
        if len(seen) >= 2:
            break

    print("[*] done, snapshots:", len(seen))
    return 0 if seen else 1


if __name__ == "__main__":
    sys.exit(main())
