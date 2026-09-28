# -*- coding: utf-8 -*-
"""auth 生成链运行时抓取驱动: 冷启动 -> hook -> 等 UI -> 点进视频列表流量"""
import frida, time, json, subprocess, sys

ADB = './tools/platform-tools/adb.exe'
LOG = open('out/auth_rt_log.jsonl', 'w', encoding='utf-8')

def adb(*args):
    return subprocess.run([ADB] + list(args), capture_output=True, text=True, timeout=30)

def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t','')
        if t == 'INFO': print('[*]', rec.get('msg'), flush=True)
        elif t == 'grs.leave': print('[KEY]', (rec.get('hex') or '')[:64], 'len', rec.get('len'), flush=True)
        else: print('['+t+']', flush=True)
    elif msg['type'] == 'error':
        print('[ERR]', msg.get('description'), flush=True)

def attach(timeout=60):
    t0=time.time()
    while time.time()-t0<timeout:
        try:
            return frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        except Exception: time.sleep(1.2)
    raise RuntimeError('attach timeout')

# 冷启动: am crash + am start + sleep 25
print('[*] crash+start', flush=True)
adb('shell', 'am', 'crash', 'com.tudou.tool')
time.sleep(2)
adb('shell', 'am', 'start', '-n', 'com.tudou.tool/app.video.guoguo.SplashActivity')
print('[*] waiting 25s for app+gadget up (双弹窗需手动处理...)', flush=True)
time.sleep(25)

session = attach()
script = session.create_script(open('out/gg_auth_hook.js', encoding='utf-8').read())
script.on('message', on_message)
script.load()
print('[*] hooks loaded, monitoring 300s — 请在手机上操作(打开首页/点视频)', flush=True)
time.sleep(300)
print('[*] done', flush=True)
