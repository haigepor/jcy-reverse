# out/gg_dart_hook2.py — attach+hook, stay alive 150s while manual adb UI drive happens
import frida, time, json, subprocess, sys

LOG = open('out/dart_log5.jsonl', 'a', encoding='utf-8')

def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t', '')
        if t == 'INFO':
            print('[*]', rec.get('msg'), flush=True)
        else:
            args = rec.get('args') or []
            strs = {a['r']: a['str'] for a in args if a.get('str')}
            if strs:
                print('[%s] %s' % (t, json.dumps(strs, ensure_ascii=False)[:800]), flush=True)
    elif msg['type'] == 'error':
        print('[ERR]', msg.get('description'), flush=True)

def attach_with_retry(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            return frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        except Exception:
            time.sleep(1.5)
    raise RuntimeError('attach timeout')

def main():
    session = attach_with_retry()
    js = open('out/gg_dart_hook5.js', 'r', encoding='utf-8').read()
    script = session.create_script(js)
    script.on('message', on_message)
    script.load()
    print('[*] dart hooks live for 150s — drive UI now', flush=True)
    time.sleep(150)
    print('[*] window closed')

if __name__ == '__main__':
    main()
