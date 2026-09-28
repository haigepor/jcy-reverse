# -*- coding: utf-8 -*-
"""第三轮驱动: 冷启动 + Pointer 解引用响应捕获"""
import frida, time, json, subprocess

ADB = './tools/platform-tools/adb.exe'
LOG = open('out/auth_rt3_log.jsonl', 'w', encoding='utf-8')

def adb(*args):
    return subprocess.run([ADB] + list(args), capture_output=True, text=True, timeout=30)

def tap(x, y, wait=1.2):
    adb('shell', 'input', 'tap', str(x), str(y)); time.sleep(wait)

def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t','')
        if t == 'INFO': print('[*]', rec.get('msg'), flush=True)
        elif t == 'rawCall.enter':
            import base64
            s = ''
            if rec.get('hex'):
                try: s = bytes.fromhex(rec['hex']).decode('utf-8','replace')[:100]
                except Exception: pass
            print('[RAW]', s, flush=True)
        elif t == 'dartCallback.enter':
            for p in (rec.get('ptrs') or []):
                s = p.get('str') or ''
                print('[CB@%s] %s' % (p.get('off'), s[:150].replace('\n',' ')), flush=True)
        else: print('['+t+']', flush=True)
    elif msg['type'] == 'error':
        print('[ERR]', msg.get('description'), flush=True)

def attach(timeout=90):
    t0=time.time()
    while time.time()-t0<timeout:
        try:
            return frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        except Exception: time.sleep(1.2)
    raise RuntimeError('attach timeout')

print('[*] crash+start', flush=True)
adb('shell', 'am', 'crash', 'com.tudou.tool')
time.sleep(2)
adb('shell', 'am', 'start', '-n', 'com.tudou.tool/app.video.guoguo.SplashActivity')
print('[*] wait 25s', flush=True)
time.sleep(25)

session = attach()
script = session.create_script(open('out/gg_auth3_hook.js', encoding='utf-8').read())
script.on('message', on_message)
script.load()
print('[*] hooks loaded; 弹窗处理', flush=True)
tap(110, 2030); tap(281, 2150)
time.sleep(3)
tap(110, 2030); tap(823, 2150)
time.sleep(6)
# 上滑触发列表刷新
adb('shell', 'input', 'swipe', '540', '1500', '540', '600', '300'); time.sleep(3)

print('[*] monitoring 150s', flush=True)
time.sleep(150)
print('[*] done', flush=True)
