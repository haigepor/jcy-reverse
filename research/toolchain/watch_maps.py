#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""watch_maps.py - 高频轮询 /proc/pid/maps, 捕获匿名可执行段出现瞬间."""
import os
import subprocess
import sys
import time

ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
ENV = dict(os.environ, ANDROID_ADB_SERVER_PORT='5039', MSYS_NO_PATHCONV='1')
PID = sys.argv[1]
DUR = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0

out = open(os.path.join(os.path.dirname(__file__),
                        '../captures/rsa_scan/maps_watch.log'), 'w', encoding='utf-8')
t0 = time.time()
seen_exec = set()
n_polls = 0
while time.time() - t0 < DUR:
    n_polls += 1
    r = subprocess.run([ADB, '-s', 'emulator-5554', 'shell',
                        f'su -c "cat /proc/{PID}/maps"'],
                       env=ENV, capture_output=True)
    lines = r.stdout.decode('utf-8', 'replace').splitlines()
    for ln in lines:
        perms = ln[19:23] if len(ln) > 23 else ''
        if 'x' not in perms:
            continue
        # 匿名(无路径) 或 anon 标签
        path = ln.split(' ', 5)[5] if len(ln.split(' ', 5)) > 5 else ''
        if path.strip() == '' or '[anon' in path:
            key = ln
            if key not in seen_exec:
                seen_exec.add(key)
                line = '[NEW] ' + ln
                print(line, flush=True)
                out.write(line + '\n')
                out.flush()
out.close()
print(f'done polls={n_polls} exec_anon={len(seen_exec)}', flush=True)
