import frida, time, subprocess, os
ADB = r'C:\leidian\LDPlayer14\adb.exe'
def adb(*a):
    env = dict(os.environ); env['MSYS_NO_PATHCONV']='1'
    subprocess.run([ADB, '-s', 'emulator-5554'] + list(a), capture_output=True, text=True, env=env)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
session = dev.attach(7322)
script = session.create_script(open('research/tmp_evp_hook.js', encoding='utf-8').read())
f = open('research/tmp_evp_log.txt', 'wb')
def on_msg(m, d):
    if m['type'] != 'send':
        print('[ERR]', str(m)[:300]); return
    p = m['payload']
    if d:
        print(p, d.hex()[:160])
        f.write((p + ' ' + d.hex() + '\n').encode()); f.flush()
    else:
        print(p)
        f.write((p + '\n').encode()); f.flush()
script.on('message', on_msg)
script.load()
time.sleep(2)
print('>>> tap 刷新')
adb('shell', 'input', 'tap', '208', '221')
time.sleep(10)
print('>>> back + refresh list')
adb('shell', 'input', 'keyevent', 'KEYCODE_BACK')
time.sleep(2)
adb('shell', 'input', 'swipe', '270', '300', '270', '800', '300')
time.sleep(12)
print('>>> tap 刷新 again')
adb('shell', 'input', 'tap', '208', '221')
time.sleep(10)
print('--- done ---')
