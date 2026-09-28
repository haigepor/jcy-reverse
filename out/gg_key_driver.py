# -*- coding: utf-8 -*-
import frida, time, json
LOG = open('out/key_log.jsonl', 'w', encoding='utf-8')
def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t','')
        if t == 'INFO': print('[*]', rec.get('msg'), flush=True)
        elif t == 'getRandomString.leave': print('[KEY]', rec.get('str'), flush=True)
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
session = attach()
script = session.create_script(open('out/gg_key_hook.js', encoding='utf-8').read())
script.on('message', on_message)
script.load()
print('[*] MONITORING 600s', flush=True)
time.sleep(600)
