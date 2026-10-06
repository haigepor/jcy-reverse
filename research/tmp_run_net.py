import frida, time, subprocess, os
ADB = r'C:\leidian\LDPlayer14\adb.exe'
def adb(*a):
    env = dict(os.environ); env['MSYS_NO_PATHCONV']='1'
    subprocess.run([ADB,'-s','emulator-5554']+list(a), capture_output=True, text=True, env=env)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
pid = int(subprocess.run([ADB,'-s','emulator-5554','shell','pidof com.tudou.tool'], capture_output=True, text=True, env=dict(os.environ, MSYS_NO_PATHCONV='1')).stdout.strip())
session = dev.attach(pid)
script = session.create_script(open('research/tmp_nettrace.js', encoding='utf-8').read())
def on_msg(m, d):
    if m['type'] != 'send': print('[ERR]', str(m)[:200]); return
    print(m['payload'])
script.on('message', on_msg)
script.load()
time.sleep(1)
print('>>> tap a video card (detail flow)')
adb('shell','input','tap','94','620'); time.sleep(8)
print('>>> tap play episode 1 (approx bottom area)')
adb('shell','input','tap','65','735'); time.sleep(10)
print('>>> back home and another card')
adb('shell','input','keyevent','KEYCODE_BACK'); time.sleep(2)
adb('shell','input','tap','270','620'); time.sleep(8)
print('--- done ---')
