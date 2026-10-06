#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_hook_call.py - 挂 hook_call.js, 驱动 UI, 信封原文落盘 calls.jsonl"""
import json
import os
import subprocess
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = "com.tudou.tool"
OUT = os.path.join(HERE, "..", "captures", "rsa_scan", "watch_action", "calls.jsonl")
ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
ENV = dict(os.environ, ANDROID_ADB_SERVER_PORT='5039', MSYS_NO_PATHCONV='1')


def adb(*args):
    return subprocess.run([ADB] + list(args), capture_output=True, timeout=60, env=ENV)


def main():
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    r = adb('-s', 'emulator-5554', 'shell', 'pidof', PKG)
    pid = int(r.stdout.decode().split()[0])
    session = dev.attach(pid)
    with open(os.path.join(HERE, 'hook_call.js'), encoding='utf-8') as f:
        src = f.read()
    script = session.create_script(src)
    log = open(OUT, 'w', encoding='utf-8')
    n = [0]

    def on_msg(msg, data):
        if msg.get('type') != 'send':
            print('msg:', str(msg)[:200], flush=True)
            return
        p = msg['payload']
        t = p.get('type')
        if t in ('call_in', 'call_out'):
            n[0] += 1
            log.write(json.dumps({'t': t, 's': p.get('s', '')[:200000]}, ensure_ascii=False) + "\n")
            log.flush()
        else:
            print(p, flush=True)

    script.on('message', on_msg)
    script.load()
    t0 = time.time()
    k = 0
    while time.time() - t0 < total:
        k += 1
        if k % 2 == 1:
            adb('-s', 'emulator-5554', 'shell', 'input', 'swipe', '540', '800', '540', '300', '150')
        else:
            adb('-s', 'emulator-5554', 'shell', 'input', 'tap', '270', '920')
        time.sleep(4)
    print('完成: %d 条信封 → %s' % (n[0], OUT), flush=True)
    session.detach()


if __name__ == '__main__':
    main()
