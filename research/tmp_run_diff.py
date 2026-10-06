import frida, time, subprocess, os
ADB = r'C:\leidian\LDPlayer14\adb.exe'
def adb(*a):
    env = dict(os.environ); env['MSYS_NO_PATHCONV']='1'
    subprocess.run([ADB,'-s','emulator-5554']+list(a), capture_output=True, text=True, env=env)
dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
pid = int(subprocess.run([ADB,'-s','emulator-5554','shell','pidof com.tudou.tool'], capture_output=True, text=True, env=dict(os.environ, MSYS_NO_PATHCONV='1')).stdout.strip())
session = dev.attach(pid)
script = session.create_script(open('research/tmp_diff.js', encoding='utf-8').read())
n = {'e':0,'d':0,'r':0}
def on_msg(m, d):
    if m['type'] != 'send': return
    p = m['payload']
    print(p)
    if 'apiEncrypt' in p: n['e'] += 1
    elif 'apiDecrypt' in p: n['d'] += 1
    elif '_rawCall' in p: n['r'] += 1
script.on('message', on_msg)
script.load()
print('--- waiting 60s idle (app heartbeats) ---')
time.sleep(60)
print('=== counts: apiEncrypt=%d apiDecrypt=%d rawCall=%d' % (n['e'], n['d'], n['r']))
