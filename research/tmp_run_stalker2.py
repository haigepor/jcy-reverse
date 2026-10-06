import frida, time, subprocess, os
ADB = r'C:\leidian\LDPlayer14\adb.exe'
def adb(*a):
    env = dict(os.environ); env['MSYS_NO_PATHCONV']='1'
    return subprocess.run([ADB, '-s', 'emulator-5554'] + list(a), capture_output=True, text=True, env=env).stdout
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
session = dev.attach(7322)
script = session.create_script(open('research/tmp_stalker.js', encoding='utf-8').read())
f = open('research/tmp_stalker_log.txt', 'w', encoding='utf-8')
def on_msg(m, d):
    if m['type'] != 'send':
        print('[ERR]', m); return
    p = m['payload']
    print(p[:300]); f.write(p + '\n'); f.flush()
script.on('message', on_msg)
script.load()
print('--- ensure foreground + poke UI ---')
print(adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP'))
print(adb('shell', 'am', 'start', '-n', 'com.tudou.tool/app.video.guoguo.SplashActivity').strip())
time.sleep(6)
for i in range(4):
    adb('shell', 'input', 'swipe', '270', '300', '270', '800', '300')  # 下拉刷新
    time.sleep(4)
    adb('shell', 'input', 'tap', '270', '500')  # 点列表项
    time.sleep(6)
    adb('shell', 'input', 'keyevent', 'KEYCODE_BACK')
    time.sleep(2)
print('--- done poking, wait 15s ---')
time.sleep(15)
