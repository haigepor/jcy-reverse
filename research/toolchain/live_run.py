# -*- coding: utf-8 -*-
"""live_run.py — spawn com.tudou.tool + live_hook.js, 事件落盘 jsonl。

用法: ./.venv/Scripts/python.exe research/toolchain/live_run.py [秒数=150]
输出: research/captures/live_hook/events.jsonl
"""
import json
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(os.path.join(os.path.dirname(HERE)), "captures", "live_hook")
os.makedirs(OUT_DIR, exist_ok=True)
OUT = os.path.join(OUT_DIR, "events.jsonl")

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 150


def resolve_base(pid):
    """libcore.so 被自定义 loader 隐藏, 从 /proc/pid/maps 抓首映射地址。"""
    import subprocess
    out = subprocess.run(
        ["adb", "shell", "su -c 'cat /proc/%d/maps'" % pid],
        capture_output=True, text=True, timeout=30).stdout
    for line in out.splitlines():
        if line.rstrip().endswith("/libcore.so") and " r--p " in line:
            return int(line.split("-")[0], 16)
    return None


def main():
    dev = frida.get_device("emulator-5554", timeout=10)
    pid = int(os.environ.get("LIVE_PID", "0")) or None
    if pid:
        session = dev.attach(pid)
        print("attach pid=%d" % pid)
    else:
        session = dev.attach("com.tudou.tool")
        print("attach com.tudou.tool")
    js = open(os.path.join(HERE, "live_hook.js"), "r", encoding="utf-8").read()
    base = resolve_base(pid or session._impl.pid)
    if base is None:
        raise RuntimeError("maps 里找不到 libcore.so")
    js = js.replace("__LIBCORE_BASE__", "0x%x" % base)
    print("libcore base = 0x%x" % base)
    script = session.create_script(js)
    events = 0
    fout = open(OUT, "w", encoding="utf-8")

    def on_message(message, data):
        nonlocal events
        if message.get("type") == "send":
            rec = message["payload"]
            if data:
                rec["_bin"] = data.hex()
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            events += 1
            if events % 20 == 0:
                fout.flush()
                print("events=%d" % events)
        elif message.get("type") == "error":
            print("JS 错误:", message.get("description", "")[:300])

    script.on("message", on_message)
    script.load()
    print("hook 已加载, 采集 %ds ..." % DURATION)
    t0 = time.time()
    while time.time() - t0 < DURATION:
        time.sleep(2)
    fout.flush()
    fout.close()
    session.detach()
    print("完成: %d 条事件 → %s" % (events, OUT))


if __name__ == "__main__":
    main()
