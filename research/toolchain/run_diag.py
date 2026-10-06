#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_diag.py - attach 后跑诊断脚本; 支持注入 SIGHEX(从本地 so 提取函数特征)."""
import os
import subprocess
import sys
import time

import frida

JS = sys.argv[1] if len(sys.argv) > 1 else r"C:/Users/haige/Desktop/instruct/囧次元/research/toolchain/diag_mem.js"
ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
ENV = dict(os.environ, ANDROID_ADB_SERVER_PORT='5039', MSYS_NO_PATHCONV='1')
SIGS = [
    ('core.EVP_CipherInit_ex', 'libcore_files.so', 0x387368),
    ('core.RSA_private_decrypt', 'libcore_files.so', 0x43e324),
    ('core.AES_set_decrypt_key', 'libcore_files.so', 0x3845e0),
    ('core.EVP_DecryptUpdate', 'libcore_files.so', 0x3877d0),
    ('core.MD5_Update', 'libcore_files.so', 0x422eb0),
    ('core.RAND_bytes', 'libcore_files.so', 0x438d18),
    ('ldr.EVP_CipherInit_ex', 'libloader_device.so', 0x35ae68),
    ('ldr.RSA_private_decrypt', 'libloader_device.so', 0x412324),
    ('ldr.AES_set_decrypt_key', 'libloader_device.so', 0x3580dc),
    ('ldr.EVP_DecryptUpdate', 'libloader_device.so', 0x35b2d0),
    ('ldr.MD5_Update', 'libloader_device.so', 0x3f6eb0),
    ('ldr.RAND_bytes', 'libloader_device.so', 0x40cd18),
]
CAPDIR = r"C:/Users/haige/Desktop/instruct/囧次元/research/captures/rsa_scan"


def build_sighex():
    out = []
    for name, fn, off in SIGS:
        data = open(os.path.join(CAPDIR, fn), 'rb').read()
        out.append([name, data[off:off + 20].hex()])
    return out


def on_msg(message, data):
    if message['type'] == 'send':
        print('[send]', message['payload'], flush=True)
    elif message['type'] == 'error':
        print('[err]', message.get('description', '')[:300], flush=True)
    else:
        print('[?]', str(message)[:200], flush=True)


def main():
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    pid = int(subprocess.run(
        [ADB, '-s', 'emulator-5554', 'shell', 'pidof', 'com.tudou.tool'],
        env=ENV, capture_output=True).stdout.decode().split()[0])
    session = dev.attach(pid)
    print('[*] attached pid=%s' % pid, flush=True)
    prelude = 'const SIGHEX = %s;\n' % str(build_sighex())
    src = prelude + open(JS, encoding='utf-8').read()
    script = session.create_script(src)
    script.on('message', on_msg)
    t0 = time.time()
    script.load()
    time.sleep(float(os.environ.get('DIAG_WAIT', '60')))
    session.detach()
    print('[*] done in %.1fs' % (time.time() - t0), flush=True)


if __name__ == '__main__':
    main()
