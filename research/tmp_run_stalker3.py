import frida, time, subprocess, os
ADB = r'C:\leidian\LDPlayer14\adb.exe'
def adb(*a):
    env = dict(os.environ); env['MSYS_NO_PATHCONV']='1'
    subprocess.run([ADB, '-s', 'emulator-5554'] + list(a), capture_output=True, text=True, env=env)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
session = dev.attach(7322)
script = session.create_script(open('research/tmp_stalker.js', encoding='utf-8').read())
f = open('research/tmp_stalker_log.txt', 'w', encoding='utf-8')
hits = []
def on_msg(m, d):
    if m['type'] != 'send':
        print('[ERR]', str(m)[:200]); return
    p = m['payload']
    print(p[:500]); f.write(p + '\n'); f.flush()
    if p.startswith('CORECALLS:'): hits.append(p)
script.on('message', on_msg)
script.load()
time.sleep(3)
print('>>> tap 刷新')
adb('shell', 'input', 'tap', '208', '221')
time.sleep(12)
print('>>> tap 换源')
adb('shell', 'input', 'tap', '349', '221')
time.sleep(8)
print('>>> tap 刷新 again')
adb('shell', 'input', 'tap', '208', '221')
time.sleep(15)
print('=== hits:', len(hits))
