# out/gg_evp_coldstart.py — cold start + hooks-live-before-burst + UI drive
import frida, sys, time, json, subprocess, threading

LOG = open('out/evp_coldstart.jsonl', 'w', encoding='utf-8')
ADB = './tools/platform-tools/adb.exe'

def sh(cmd, timeout=90):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout,
                          encoding='utf-8', errors='replace').stdout.strip()

def tap(x, y, wait=1.2):
    sh('%s shell input tap %d %d' % (ADB, x, y)); time.sleep(wait)

seen_keys = set()

def on_message(msg, data):
    if msg['type'] == 'send':
        r = msg['payload']
        LOG.write(json.dumps(r) + '\n'); LOG.flush()
        t = r.get('t', '')
        if t == 'INFO':
            print('[*]', r.get('msg'))
        elif 'Init' in t:
            key = r.get('key')
            print('[KEY]', t, 'len=', r.get('keylen'), 'key=', key, 'iv=', r.get('iv'))
        elif 'Update' in t:
            s = r.get('str')
            if s:
                printable = sum(1 for c in s if 32 <= ord(c) < 127)
                if printable > len(s) * 0.5 and len(s) > 8:
                    print('[%s] inl=%4d PT=%r' % ('DEC' if 'Dec' in t else 'ENC', r.get('inl'), s[:200]))
                    return
            print('[%s] inl=%4d %s' % ('DEC' if 'Dec' in t else 'ENC', r.get('inl'), (r.get('hex') or '')[:96]))
        elif t in ('DecOut', 'EncOut'):
            s = r.get('str')
            if s:
                printable = sum(1 for c in s if 32 <= ord(c) < 127)
                if printable > len(s) * 0.5 and len(s) > 8:
                    print('[%s] outl=%4d PT=%r' % ('DECR', t == 'DecOut', r.get('outl'), s[:200]))
                    return
            print('[%s] outl=%4d %s' % ('DECR' if t == 'DecOut' else 'ENCR', r.get('outl'), (r.get('hex') or '')[:96]))
    else:
        print('[ERR]', msg.get('description'))

def attach_with_retry(timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            return frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        except Exception:
            time.sleep(0.8)
    raise RuntimeError('attach timeout')

# 1. cold start
print('[*] force-stop + cold start')
sh('%s shell am force-stop com.tudou.tool' % ADB)
time.sleep(2)
sh('%s shell monkey -p com.tudou.tool -c android.intent.category.LAUNCHER 1' % ADB)

# 2. attach fast
print('[*] attaching ASAP...')
session = attach_with_retry()
script = session.create_script(open('out/evp_hook.js', encoding='utf-8').read())
script.on('message', on_message)
script.load()
print('[*] hooks live — waiting startup burst (35s)')
time.sleep(35)

# 3. UI drive: consent -> home -> video -> play
print('[*] driving UI')
tap(540, 2144, wait=8)     # consent agree if present
tap(540, 2144, wait=5)     # possible second dialog
time.sleep(6)              # home load
tap(530, 1285, wait=6)     # video card
tap(551, 405, wait=14)     # play
time.sleep(25)             # playback running
sh('%s shell input keyevent 4' % ADB); time.sleep(3)
tap(530, 1285, wait=5)
tap(551, 405, wait=12)
time.sleep(20)
print('[*] done')
try: session.detach()
except Exception: pass
