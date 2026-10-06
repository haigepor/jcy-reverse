# -*- coding: utf-8 -*-
"""live_drive.py — attach + hook, 然后主动驱动 call() 跑 api_encrypt。

输出: research/captures/live_hook/events.jsonl (hook 事件)
      research/captures/live_hook/drive_result.json (驱动结果)
"""
import base64
import json
import os
import subprocess
import sys
import time

import frida
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

HERE = os.path.dirname(os.path.abspath(__file__))
RESEARCH = os.path.dirname(HERE)
OUT_DIR = os.path.join(RESEARCH, "captures", "live_hook")
os.makedirs(OUT_DIR, exist_ok=True)
OUT = os.path.join(OUT_DIR, "events.jsonl")
DRIVE = os.path.join(OUT_DIR, "drive_result.json")

K = b"qPwClBj7j7ZQraSm"
IV = b"p3JdVQl3q7WQJIgG"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def envelope(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    ct = AES.new(K, AES.MODE_CBC, IV).encrypt(pad(raw, 16))
    return base64.b64encode(ct).decode()


def resolve_base(pid):
    out = subprocess.run(
        ["adb", "shell", "su -c 'cat /proc/%d/maps'" % pid],
        capture_output=True, text=True, timeout=30).stdout
    for line in out.splitlines():
        if line.rstrip().endswith("/libcore.so") and " r--p " in line:
            return int(line.split("-")[0], 16)
    return None


PARAMS = ('{"app_id":"4150439554430529","device_id":"16613a7076284a15bc723d018bcd67e1",'
          '"code_version":"3.0.0.8","app_version":"1.5.8.0","files_path":'
          '"/data/user/0/com.tudou.tool/files","tcp":"43.145.33.254:8191"}')


def main():
    dev = frida.get_device("emulator-5554", timeout=10)
    pid = int(os.environ.get("LIVE_PID", "0"))
    session = dev.attach(pid)
    js = open(os.path.join(HERE, "live_hook.js"), "r", encoding="utf-8").read()
    base = resolve_base(pid)
    js = js.replace("__LIBCORE_BASE__", "0x%x" % base)
    events = 0
    fout = open(OUT, "w", encoding="utf-8")

    def on_message(message, data):
        nonlocal events
        if message.get("type") == "send":
            rec = message["payload"]
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
            events += 1
            if events % 10 == 0:
                fout.flush()
        elif message.get("type") == "error":
            print("JS 错误:", message.get("description", "")[:200])

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    print("hooks on, base=0x%x" % base)
    time.sleep(2)

    results = {}
    env = envelope({"action": "api_encrypt", "payload": {"data": PARAMS,
                   "path": "/app/video/device-base"}})
    try:
        r = script.exports_sync.callenv(env) if hasattr(script, "exports_sync") \
            else script.exports.callenv(env)
        results["api_encrypt"] = r
        print("api_encrypt 调用完成")
    except Exception as e:
        print("callenv 失败:", e)
        results["api_encrypt_error"] = str(e)
    time.sleep(2)
    fout.flush()
    fout.close()
    json.dump(results, open(DRIVE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("事件 %d 条 → %s" % (events, OUT))


if __name__ == "__main__":
    main()
