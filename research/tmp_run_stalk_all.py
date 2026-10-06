import frida, time, subprocess, os, json
ADB = r'C:\leidian\LDPlayer14\adb.exe'
def adb(*a):
    env = dict(os.environ); env['MSYS_NO_PATHCONV']='1'
    subprocess.run([ADB, '-s', 'emulator-5554'] + list(a), capture_output=True, text=True, env=env)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
session = dev.attach(7322)
script = session.create_script(open('research/tmp_stalker_all.js', encoding='utf-8').read())
def on_msg(m, d):
    if m['type'] != 'send': print('[ERR]', str(m)[:200]); return
    print(m['payload'])
script.on('message', on_msg)
script.load()
time.sleep(2)
print('>>> tap 刷新'); adb('shell', 'input', 'tap', '208', '221')
time.sleep(6)
print('>>> back+swipe'); adb('shell', 'input', 'keyevent', 'KEYCODE_BACK'); time.sleep(2)
adb('shell', 'input', 'swipe', '270', '300', '270', '800', '300')
time.sleep(6)
print('>>> tap 刷新'); adb('shell', 'input', 'tap', '208', '221')
time.sleep(8)
try:
    res = script.exports_sync.stop() if hasattr(script, 'exports_sync') else script.exports.stop()
    print('=== top libcore call targets ===')
    out = []
    for k, v in (res or [])[:120]:
        out.append(f"{k} x{v}")
        print(f"{k} x{v}")
    open('research/tmp_stalker_hits.txt', 'w').write('\n'.join(out))
except Exception as e:
    print('[stop error]', e)
