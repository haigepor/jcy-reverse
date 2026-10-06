#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_frida.py - attach com.tudou.tool 注入 hunt_key2.js, 抓 RSA/AES key."""
import os
import subprocess
import sys
import time

import frida

JS = sys.argv[1] if len(sys.argv) > 1 else \
    r"C:/Users/haige/Desktop/instruct/囧次元/research/toolchain/hunt_key2.js"
ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
ENV = dict(os.environ, ANDROID_ADB_SERVER_PORT='5039', MSYS_NO_PATHCONV='1')


def on_msg(message, data):
    if message['type'] == 'send':
        print('[send]', message['payload'], flush=True)
    elif message['type'] == 'log':
        print(message.get('payload', ''), flush=True)
    elif message['type'] == 'error':
        print('[err]', message.get('description', '')[:300], flush=True)
    else:
        print('[?]', str(message)[:200], flush=True)


def main():
    wait = int(sys.argv[2]) if len(sys.argv) > 2 else 90
    mode = sys.argv[3] if len(sys.argv) > 3 else 'attach'
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    if mode == 'spawn':
        # spawn 挂起态注入, resume 后轮询 hooker 在 libcore 映射瞬间就位,
        # 覆盖启动期第一批请求的解密
        pid = dev.spawn(['com.tudou.tool'])
        session = dev.attach(pid)
        print('[*] spawned pid=%s' % pid, flush=True)
        script = session.create_script(open(JS, encoding='utf-8').read())
        script.on('message', on_msg)
        script.load()
        dev.resume(pid)
        print('[*] resumed', flush=True)
    else:
        # attach 模式: app 已启动, libcore 已映射
        pid = int(subprocess.run(
            [ADB, '-s', 'emulator-5554', 'shell', 'pidof', 'com.tudou.tool'],
            env=ENV, capture_output=True).stdout.decode().split()[0])
        session = dev.attach(pid)
        print('[*] attached pid=%s' % pid, flush=True)
        script = session.create_script(open(JS, encoding='utf-8').read())
        script.on('message', on_msg)
        script.load()

    # 持续触发: tap 切 tab + 滑动 + monkey 随机事件
    deadline = time.time() + wait
    monkeyed = False
    while time.time() < deadline:
        subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap',
                        '270', '920'], env=ENV, capture_output=True)
        time.sleep(3)
        subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'tap',
                        '450', '920'], env=ENV, capture_output=True)
        time.sleep(3)
        subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'input', 'swipe',
                        '540', '800', '540', '300', '200'], env=ENV, capture_output=True)
        time.sleep(3)
        if not monkeyed and time.time() > deadline - wait / 2:
            monkeyed = True
            subprocess.run([ADB, '-s', 'emulator-5554', 'shell', 'monkey',
                            '-p', 'com.tudou.tool', '--throttle', '300', '60'],
                           env=ENV, capture_output=True)
            print('[*] monkey 60 events 注入', flush=True)
    session.detach()
    print('[*] done', flush=True)


if __name__ == '__main__':
    main()
