# out/gg_ffi_hook.py — attach Gadget, install gg_ffi_hook.js, cold-restart app, log FFI traffic
import frida, sys, time, json, subprocess

LOG = open('out/ffi_log.jsonl', 'a', encoding='utf-8')

def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        if isinstance(rec, str):
            try: rec = json.loads(rec)
            except Exception: rec = {'t': 'RAWSTR', 'v': rec[:400]}
        if data:
            rec['blob'] = data.hex()[:512]
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t', '')
        if t == 'INFO':
            print('[*]', rec.get('msg'))
        elif 'AES_KEY_SETUP' in t:
            print('[KEY]', rec.get('fn'), 'bits=', rec.get('bits'), 'key=', rec.get('key'))
        elif t.endswith('.enter') or t.endswith('.leave'):
            k = t.replace('.enter', ' E>').replace('.leave', ' L>')
            args = rec.get('args') or rec.get('ret')
            s = json.dumps(args, ensure_ascii=False) if not isinstance(args, str) else args
            print('[%s]' % k, (s or '')[:400])
    elif msg['type'] == 'error':
        print('[ERR]', msg.get('description'))
        LOG.write(json.dumps({'t': 'SCRIPT_ERROR', 'd': msg.get('description')}) + '\n'); LOG.flush()

def attach_with_retry(timeout=120):
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

def main():
    print('[*] attaching...')
    session = attach_with_retry()
    print('[*] attached')
    js = open('out/gg_ffi_hook.js', 'r', encoding='utf-8').read()
    script = session.create_script(js)
    script.on('message', on_message)
    script.load()
    print('[*] script loaded; cold-restarting app to capture init/call from the start')
    sh('%s shell am force-stop com.tudou.tool' % ADB); time.sleep(2)
    sh('%s shell am start -n com.tudou.tool/app.video.guoguo.SplashActivity' % ADB)
    time.sleep(45)
    print('[*] observation window done')

if __name__ == '__main__':
    main()
