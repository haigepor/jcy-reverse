# -*- coding: utf-8 -*-
"""批量重放驱动: 保活 app + 定时点 tab, 配合 inject_mitm(--inject-dir) 轮播语料体.

用法: python replay_driver.py [分钟=35]
职责: 只管让 app 活着并持续产生请求; 注入交给代理, 取明文交给 watch_forever。
"""
import subprocess, sys, time, os

ADB = r"C:\leidian\LDPlayer14\adb.exe"
SERIAL = "127.0.0.1:5555"
PKG = "com.tudou.tool"
DUR_MIN = float(sys.argv[1]) if len(sys.argv) > 1 else 35

TAPS = [(90, 60), (180, 60), (270, 60), (360, 60), (450, 60), (270, 530), (90, 530)]


def sh(*args):
    return subprocess.run([ADB, "-s", SERIAL] + list(args), capture_output=True, text=True,
                          errors="replace")


def app_pid():
    for line in sh("shell", "pidof", PKG).stdout.split():
        if line.strip().isdigit():
            return int(line.strip())
    return None


def launch():
    sh("shell", "am", "force-stop", PKG)
    time.sleep(2)
    sh("shell", "am", "start", "-n", PKG + "/app.video.guoguo.SplashActivity")


t0 = time.time()
launch()
time.sleep(20)
ti = 0
last_pid = None
while time.time() - t0 < DUR_MIN * 60:
    pid = app_pid()
    if not pid:
        print("[driver] app 死亡, 重启", flush=True)
        launch()
        time.sleep(20)
        continue
    if pid != last_pid:
        print("[driver] app pid=%d" % pid, flush=True)
        last_pid = pid
    x, y = TAPS[ti % len(TAPS)]
    sh("shell", "input", "tap", str(x), str(y))
    ti += 1
    time.sleep(4)
print("[driver] 完成; taps=%d" % ti, flush=True)
