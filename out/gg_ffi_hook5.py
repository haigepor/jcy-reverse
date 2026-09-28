# out/gg_ffi_hook3.py — attach, hook, dismiss dialog, browse to video detail+play, capture API FFI calls
import frida, time, json, subprocess

LOG = open('out/ffi_log5.jsonl', 'a', encoding='utf-8')
HB = 0

def on_message(msg, data):
    global HB
    if msg['type'] == 'send':
        rec = msg['payload']
        if isinstance(rec, str):
            try: rec = json.loads(rec)
            except Exception: rec = {'t': 'RAWSTR', 'v': rec[:400]}
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t', '')
        if t == 'INFO':
            print('[*]', rec.get('msg'))
        elif 'AES_KEY_SETUP' in t:
            k = rec.get('key')
            if k and k != '715077436c426a376a375a517261536d':
                print('[KEY!!]', rec.get('fn'), 'bits=', rec.get('bits'), 'key=', k)
        elif t.endswith('.enter'):
            args = rec.get('args') or []
            a0 = args[0] if len(args) > 0 else {}
            s = a0.get('str') or ''
            if len(s) != 256:
                print('[%s !NONHB!]' % t.replace('.enter', ''), json.dumps(args, ensure_ascii=False)[:1200])
            else:
                HB += 1
        elif t.endswith('.leave'):
            ret = rec.get('ret')
            if ret not in ('0x280', '0x0'):
                print('[%s]' % t.replace('.leave', ' L>'), 'ret=', ret, 'retstr=', (rec.get('retstr') or '')[:300])
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
    js = open('out/gg_ffi_hook.js', 'r', encoding='utf-8').read()
    script = session.create_script(js)
    script.on('message', on_message)
    script.load()
    print('[*] hooks live on live process')
    # episode 2 chip -> new play request while hooked
    tap(314, 1499, wait=5)
    time.sleep(12)
    tap(545, 396, wait=5)
    time.sleep(15)
    print('[*] drive done; HB=', HB)

if __name__ == '__main__':
    main()
