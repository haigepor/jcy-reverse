import subprocess, os, time, threading, collections
ADB = r'C:\leidian\LDPlayer14\adb.exe'
env = dict(os.environ); env['MSYS_NO_PATHCONV']='1'
seen = collections.Counter()
stop = False
def poller():
    # 单次 exec-out 长连接轮询不可行；用多次 dumpsys? 直接循环 adb shell cat
    while not stop:
        r = subprocess.run([ADB,'-s','emulator-5554','shell',
            'su -c "PID=\$(pidof com.tudou.tool); grep libcore.so /proc/\$PID/maps | grep -E \\"x p|xp\\" | head -5"'],
            capture_output=True, text=True, env=env)
        for line in r.stdout.strip().splitlines():
            if line.strip(): seen[line.strip()] += 1
t0=time.time()
th = threading.Thread(target=poller); th.start()
# 轮询期间戳 UI
for i in range(6):
    subprocess.run([ADB,'-s','emulator-5554','shell','input','tap','270','500'], env=env)
    time.sleep(1.2)
    subprocess.run([ADB,'-s','emulator-5554','shell','input','swipe','270','300','270','800','300'], env=env)
    time.sleep(1.5)
stop = True; th.join()
print('polling window: %.1fs, exec-page sightings: %d' % (time.time()-t0, len(seen)))
for k,v in seen.most_common(10): print(v, k)
if not seen: print('NO x pages ever observed')
