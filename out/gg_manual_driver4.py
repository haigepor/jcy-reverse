# -*- coding: utf-8 -*-
import frida, time, json, sys
LOG = open('out/manual_log4.jsonl', 'w', encoding='utf-8')
def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t','')
        if t == 'INFO':
            print('[*]', rec.get('msg'), flush=True)
        else:
            s0 = rec.get('s0') or rec.get('retstr') or ''
            strs = rec.get('strs') or rec.get('direct') or []
            print('[%s] %s' % (t, (s0[:80] if s0 else ' '.join(x[:60] for x in strs[:3]))), flush=True)
    elif msg['type'] == 'error':
        print('[ERR]', msg.get('description'), flush=True)
def attach(timeout=90):
    t0=time.time()
    while time.time()-t0<timeout:
        try:
            return frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        except Exception: time.sleep(1.2)
    raise RuntimeError('attach timeout')
session = attach()
js = open('out/gg_manual_hook4.js', encoding='utf-8').read()
script = session.create_script(js)
script.on('message', on_message)
script.load()
print('[*] MONITORING 600s — go use the app now', flush=True)
time.sleep(600)
print('[*] window closed', flush=True)
