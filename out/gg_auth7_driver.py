# -*- coding: utf-8 -*-
"""第五轮驱动: 修复的 native crypto hook + CB 全量"""
import frida, time, json, subprocess

ADB = 'C:/Users/haige/Desktop/instruct/囧次元/tools/platform-tools/adb.exe'
LOG = open('auth_rt7_log.jsonl', 'w', encoding='utf-8')

def adb(*args):
    return subprocess.run([ADB] + list(args), capture_output=True, text=True, timeout=30)

def tap(x, y, wait=1.2):
    adb('shell', 'input', 'tap', str(x), str(y)); time.sleep(wait)

def h2s(hexstr, cap=200):
    if not hexstr: return ''
    try: return bytes.fromhex(hexstr)[:cap].decode('utf-8', 'replace')
    except Exception: return ''

def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t','')
        if t == 'INFO': print('[*]', rec.get('msg'), flush=True)
        elif t == 'ks': print('[KS] %s bits=%d key=%r' % (rec.get('fn'), rec.get('bits'), h2s(rec.get('key'), 32)), flush=True)
        elif t == 'evp.init': print('[EVP-INIT] %s enc=%s keylen=%s key=%r iv=%r' % (rec.get('fn'), rec.get('enc'), rec.get('keylen'), h2s(rec.get('key'),32), h2s(rec.get('iv'),16)), flush=True)
        elif t == 'evp.up': print('[EVP-UP] %s inl=%s in=%r' % (rec.get('fn'), rec.get('inl'), h2s(rec.get('inHex'), 80)), flush=True)
        elif t == 'rand': print('[RAND] num=%s val=%r' % (rec.get('num'), h2s(rec.get('val'),64)), flush=True)
        elif t == 'rsa': print('[RSA] %s flen=%s from=%r' % (rec.get('fn'), rec.get('flen'), h2s(rec.get('fromHex'), 128)), flush=True)
        elif t == 'hmac': print('[HMAC] klen=%s key=%r' % (rec.get('klen'), h2s(rec.get('keyHex'), 64)), flush=True)
        elif t == 'blk': print('[BLK] %s in=%s out=%s' % (rec.get('fn'), rec.get('inHex'), rec.get('outHex')), flush=True)
        elif t == 'cb': print('[CB] len=%s use=%s %r' % (rec.get('lenRaw'), rec.get('use'), h2s(rec.get('hex'), 200)), flush=True)
        elif t == 'raw.full': print('[RAW-FULL]', (rec.get('text') or '')[:250].replace('\n',' '), flush=True)
        elif t == 'http.post': print('[HTTP]', rec.get('url'), flush=True)
        elif t in ('raw.act','mark'): pass
        else: print('['+t+']', h2s(rec.get('inHex') or rec.get('outHex') or rec.get('dataHex') or rec.get('md') or rec.get('toHex') or '', 80), flush=True)
    elif msg['type'] == 'error':
        print('[ERR]', msg.get('description'), flush=True)

print('[*] crash+start', flush=True)
adb('shell', 'am', 'crash', 'com.tudou.tool')
time.sleep(2)
t_start = time.time()
adb('shell', 'am', 'start', '-n', 'com.tudou.tool/app.video.guoguo.SplashActivity')

session = None
while time.time() - t_start < 60:
    try:
        session = frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        print('[*] attached after %.1fs' % (time.time()-t_start), flush=True)
        break
    except Exception:
        time.sleep(1)
if session is None: raise RuntimeError('attach timeout')

script = session.create_script(open('gg_auth7_hook.js', encoding='utf-8').read())
script.on('message', on_message)
script.load()
print('[*] hooks loaded', flush=True)

while time.time() - t_start < 18: time.sleep(1)
print('[*] 弹窗处理', flush=True)
tap(110, 2030); tap(281, 2150)
time.sleep(3)
tap(110, 2030); tap(823, 2150)
time.sleep(6)
adb('shell', 'input', 'swipe', '540', '1500', '540', '600', '300'); time.sleep(3)

print('[*] monitoring 150s', flush=True)
time.sleep(150)
print('[*] done', flush=True)
