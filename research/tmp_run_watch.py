import frida, time, subprocess, os
ADB = r'C:\leidian\LDPlayer14\adb.exe'
def adb(*a):
    env = dict(os.environ); env['MSYS_NO_PATHCONV']='1'
    subprocess.run([ADB,'-s','emulator-5554']+list(a), capture_output=True, text=True, env=env)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
pid = int(subprocess.run([ADB,'-s','emulator-5554','shell','pidof com.tudou.tool'], capture_output=True, text=True, env=dict(os.environ, MSYS_NO_PATHCONV='1')).stdout.strip())
print('pid', pid)
session = dev.attach(pid)
script = session.create_script(open('research/tmp_watch.js', encoding='utf-8').read())
def on_msg(m, d):
    if m['type'] != 'send': print('[ERR]', str(m)[:150]); return
    print(m['payload'])
script.on('message', on_msg)
script.load()
time.sleep(1)
print('>>> UI traffic while watching')
for i in range(4):
    adb('shell','input','tap','270','500'); time.sleep(1.5)
    adb('shell','input','swipe','270','300','270','800','300'); time.sleep(2)
try:
    h = script.exports.scan()
    print('[scan hits]', h)
except Exception as e:
    print('[scan err]', e)
time.sleep(2)
try:
    print('flips observed:', script.exports.stopwatch())
except Exception as e:
    print('[stop err]', e)
