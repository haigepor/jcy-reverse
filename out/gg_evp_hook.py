# out/gg_evp_hook.py — attach Gadget, install EVP/AES hooks, relaunch app, drive UI, log everything
import frida, sys, time, json, subprocess, threading

LOG = open('out/evp_log.jsonl', 'a', encoding='utf-8')

def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n')
        LOG.flush()
        t = rec.get('t')
        if t in ('INFO',):
            print('[*]', rec.get('msg'))
        elif 'Init' in (t or ''):
            print('[KEY]', t, 'key=', rec.get('key'), 'iv=', rec.get('iv'), 'keylen=', rec.get('keylen'), 'mod=', rec.get('mod'))
        elif t and 'Update' in t:
            pt = rec.get('pt')
            show = (pt[:180] + '...') if pt and len(pt) > 180 else pt
            print('[PT ]', t, 'inl=', rec.get('inl'), show)
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
def tap(x, y, wait=1.2):
    sh('%s shell input tap %d %d' % (ADB, x, y)); time.sleep(wait)

def drive():
    time.sleep(3)
    # relaunch app fresh so startup requests regenerate
    sh('%s shell am force-stop com.tudou.tool' % ADB)
    time.sleep(2)
    sh('%s shell monkey -p com.tudou.tool -c android.intent.category.LAUNCHER 1' % ADB)
    time.sleep(16)
    # consent page if it appears
    tap(540, 2144, wait=6)
    # home loaded: tap a video card
    tap(530, 1285, wait=6)
    # play button
    tap(551, 405, wait=12)
    time.sleep(20)
    # back to home, tap another video
    sh('%s shell input keyevent 4' % ADB); time.sleep(3)
    tap(530, 1285, wait=5)
    tap(551, 405, wait=12)
    time.sleep(20)
    print('[*] drive done')

print('[*] attaching...')
session = attach_with_retry()
script = session.create_script(open('out/evp_hook.js', encoding='utf-8').read())
script.on('message', on_message)
script.load()
print('[*] hooks live, driving app...')

# enumerate modules once for the record
try:
    mods = script.exports_sync if hasattr(script, 'exports_sync') else None
except Exception:
    pass

th = threading.Thread(target=drive, daemon=True)
th.start()
th.join(timeout=180)
print('[*] collecting extra 20s...')
time.sleep(20)
print('[*] done. log: out/evp_log.jsonl')
try: session.detach()
except Exception: pass
