# -*- coding: utf-8 -*-
# one-shot: cold start + frida hooks + dialog clearing + fresh video request
import subprocess, time, io, json, sys, threading
import frida
from PIL import Image

ADB = './tools/platform-tools/adb.exe'
LOG = open('out/full_run_log.jsonl', 'a', encoding='utf-8')
EVENTS = []

def sh(cmd, timeout=30):
    return subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)

def tap(x, y, wait=1.5):
    sh(f'{ADB} shell input tap {x} {y}'); time.sleep(wait)

def bottom_mean():
    p = subprocess.run(f'{ADB} exec-out screencap -p', shell=True, capture_output=True, timeout=20)
    im = Image.open(io.BytesIO(p.stdout)).convert('L')
    w, h = im.size
    crop = im.crop((0, int(h*0.78), w, h))
    px = list(crop.getdata())
    return sum(px)/len(px)

def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        EVENTS.append(rec)
        t = rec.get('t','')
        if t == 'INFO':
            print('[*]', rec.get('msg'), flush=True)
        else:
            strs = rec.get('strs') or []
            print('[%s] n=%d' % (t, len(strs)), flush=True)
            for s in strs[:6]:
                print('    |', s[:120], flush=True)
    elif msg['type'] == 'error':
        print('[ERR]', msg.get('description'), flush=True)

def attach(timeout=90):
    t0 = time.time()
    while time.time()-t0 < timeout:
        try:
            return frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        except Exception:
            time.sleep(1.2)
    raise RuntimeError('attach timeout')

def main():
    session = attach()
    print('[*] attached', flush=True)
    js = open('out/gg_enc_hook4.js', encoding='utf-8').read()
    script = None
    for attempt in range(5):
        try:
            script = session.create_script(js)
            break
        except Exception as e:
            print('[*] create_script retry', attempt, e, flush=True)
            time.sleep(4)
    if script is None:
        raise RuntimeError('create_script failed')
    script.on('message', on_message)
    script.load()
    print('[*] hooks loaded; clearing dialogs', flush=True)
    # dialog loop: bottom-white detection
    t0 = time.time()
    while time.time()-t0 < 100:
        try: m = bottom_mean()
        except Exception: time.sleep(2); continue
        if m < 140:
            print('[drive] bottom dark (mean=%.0f) -> UI clear' % m, flush=True)
            break
        print('[drive] dialog (bottom mean=%.0f), tap' % m, flush=True)
        tap(110, 2030, 0.6)
        tap(270, 2130, 2.0)
        time.sleep(1.5)
    else:
        print('[drive] dialogs persist', flush=True)
    time.sleep(2)
    # drive: channel tab, first card, play
    tap(911, 146, 4)
    tap(186, 1272, 8)
    tap(545, 396, 5)
    tap(545, 396, 10)
    print('[*] drive done', flush=True)
    time.sleep(15)
    print('[*] session end', flush=True)

if __name__ == '__main__':
    main()
