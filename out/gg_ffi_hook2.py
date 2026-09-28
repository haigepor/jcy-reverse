# out/gg_ffi_hook2.py — attach CURRENT process, load hooks, drive UI to trigger API calls
import frida, sys, time, json, subprocess

LOG = open('out/ffi_log2.jsonl', 'a', encoding='utf-8')
HEARTBEAT = 0

def on_message(msg, data):
    global HEARTBEAT
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
            else:
                HEARTBEAT += 1
        elif t.endswith('.enter'):
            args = rec.get('args') or []
            a0 = args[0] if len(args) > 0 else {}
            s = a0.get('str') or ''
            mark = 'HB' if len(s) == 256 else '!!NONHB!!'
            if mark != 'HB':
                print('[%s %s]' % (t.replace('.enter', ''), mark), json.dumps(args, ensure_ascii=False)[:900])
            else:
                HEARTBEAT += 1
        elif t.endswith('.leave'):
            ret = rec.get('ret')
            if ret not in ('0x280', '0x0'):
                print('[%s]' % t.replace('.leave', ' L>'), 'ret=', ret, 'retstr=', (rec.get('retstr') or '')[:200])
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
    print('[*] attaching to live process...')
    session = attach_with_retry()
    js = open('out/gg_ffi_hook.js', 'r', encoding='utf-8').read()
    script = session.create_script(js)
    script.on('message', on_message)
    script.load()
    print('[*] hooks live; driving UI to trigger API requests')
    time.sleep(3)
    # consent / splash handling: screenshot-free taps that previously mapped to consent page
    tap(540, 2144, wait=8)
    # home grid: tap first video card (mid-left column as in prior runs)
    tap(530, 1285, wait=6)
    tap(551, 405, wait=12)   # play button area
    time.sleep(15)
    # go back, open another video
    sh('%s shell input keyevent 4' % ADB); time.sleep(3)
    tap(530, 1285, wait=5)
    tap(551, 405, wait=12)
    time.sleep(15)
    print('[*] drive done; heartbeat-count=', HEARTBEAT)

if __name__ == '__main__':
    main()
