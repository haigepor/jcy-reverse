# -*- coding: utf-8 -*-
"""live_collect.py — attach 被动 hook + adb 点击驱动 UI 流量。

用法: ./.venv/Scripts/python.exe research/toolchain/live_collect.py [秒=180]
输出: research/captures/live_hook/events.jsonl
"""
import json
import os
import subprocess
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "captures", "live_hook", "events.jsonl")
os.makedirs(os.path.dirname(OUT), exist_ok=True)
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 180


def resolve_base(pid):
    out = subprocess.run(
        ["adb", "shell", "su -c 'cat /proc/%d/maps'" % pid],
        capture_output=True, text=True, timeout=30).stdout
    for line in out.splitlines():
        if line.rstrip().endswith("/libcore.so") and " r--p " in line:
            return int(line.split("-")[0], 16)
    return None


def main():
    pid = int(subprocess.run(["adb", "shell", "pidof com.tudou.tool"],
                             capture_output=True, text=True).stdout.strip())
    dev = frida.get_device("emulator-5554", timeout=10)
    session = dev.attach(pid)
    base = resolve_base(pid)
    for _ in range(10):
        if base is not None:
            break
        print("libcore 未映射, 10s 后重试", flush=True)
        time.sleep(10)
        base = resolve_base(pid)
    if base is None:
        raise RuntimeError("libcore.so 始终未映射")
    js = open(os.path.join(HERE, "live_hook.js"), encoding="utf-8").read()
    js = js.replace("__LIBCORE_BASE__", "0x%x" % base)
    events = 0
    fout = open(OUT, "w", encoding="utf-8")

    def on_message(message, data):
        nonlocal events
        if message.get("type") == "send":
            fout.write(json.dumps(message["payload"], ensure_ascii=False) + "\n")
            events += 1
            if events % 10 == 0:
                fout.flush()
                print("events=%d" % events, flush=True)
        elif message.get("type") == "error":
            print("JS 错误:", message.get("description", "")[:200], flush=True)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    print("hooks on pid=%d base=0x%x, 采集 %ds, 每 15s 点一次屏" % (pid, base, DURATION), flush=True)

    t0 = time.time()
    seq = [(270, 800), (270, 760), (120, 800), (420, 800), (270, 400),
           (270, 700), (430, 760), (100, 760), (270, 300), (270, 500)]
    i = 0
    no_tap = os.environ.get("NO_TAP") == "1"
    while time.time() - t0 < DURATION:
        time.sleep(5)
        if no_tap or time.time() - t0 >= DURATION:
            continue
        if int(time.time() - t0) % 45 == 0:
            x, y = seq[i % len(seq)]
            i += 1
            subprocess.run(["adb", "shell", "input tap %d %d" % (x, y)],
                           capture_output=True, timeout=15)
    fout.flush()
    fout.close()
    print("完成: %d 条 → %s" % (events, OUT), flush=True)


if __name__ == "__main__":
    main()
