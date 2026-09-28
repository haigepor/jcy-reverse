# out/gg_dart_hook.py — attach live process, hook Dart functions, drive UI (episode switch)
import frida, time, json, subprocess

LOG = open('out/dart_log.jsonl', 'a', encoding='utf-8')

def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t', '')
        if t == 'INFO':
            print('[*]', rec.get('msg'))
        else:
            args = rec.get('args') or []
            strs = {a['r']: a['str'] for a in args if a.get('str')}
            print('[%s]' % t, json.dumps(strs, ensure_ascii=False)[:600])
    elif msg['type'] == 'error':
        print('[ERR]', msg.get('description'))

def attach_with_retry(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            return frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        except Exception:
            time.sleep(1.5)
    raise RuntimeError('attach timeout')

def sh(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout,
                          encoding='utf-8', errors='replace').stdout.strip()

ADB = './tools/platform-tools/adb.exe'
def tap(x, y, wait=2.0):
    sh('%s shell input tap %d %d' % (ADB, x, y)); time.sleep(wait)

def main():
    session = attach_with_retry()
    js = open('out/gg_dart_hook.js', 'r', encoding='utf-8').read()
    script = session.create_script(js)
    script.on('message', on_message)
    script.load()
    print('[*] dart hooks live; tapping episode 2 to trigger requests')
    time.sleep(2)
    tap(314, 1499, wait=5)   # episode chip "2"
    time.sleep(10)
    tap(545, 396, wait=5)    # play button if needed
    time.sleep(20)
    print('[*] done')

if __name__ == '__main__':
    main()
