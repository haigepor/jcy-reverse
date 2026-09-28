# -*- coding: utf-8 -*-
"""第二轮驱动: 冷启动 -> hook -> 弹窗处理 -> 等 HTTP 流量"""
import frida, time, json, subprocess

ADB = './tools/platform-tools/adb.exe'
LOG = open('out/auth_rt2_log.jsonl', 'w', encoding='utf-8')

def adb(*args):
    return subprocess.run([ADB] + list(args), capture_output=True, text=True, timeout=30)

def tap(x, y, wait=1.2):
    adb('shell', 'input', 'tap', str(x), str(y)); time.sleep(wait)

def on_message(msg, data):
    if msg['type'] == 'send':
        rec = msg['payload']
        LOG.write(json.dumps(rec, ensure_ascii=False) + '\n'); LOG.flush()
        t = rec.get('t','')
        if t == 'INFO': print('[*]', rec.get('msg'), flush=True)
        elif t == 'rawCall.enter': print('[RAW]', (rec.get('hex') or '')[:80], 'len', rec.get('len'), flush=True)
        elif t == 'core.call.enter': print('[CORE]', (rec.get('s0') or '')[:60], flush=True)
        elif t == 'dartCallback.enter': print('[CB ]', (rec.get('x1str') or '')[:80], flush=True)
        elif t in ('apiEncrypt.leave','apiDecrypt.leave'): print('['+t+']', 'len', rec.get('len'), (rec.get('hex') or '')[:60], flush=True)
        else: print('['+t+']', flush=True)
    elif msg['type'] == 'error':
        print('[ERR]', msg.get('description'), flush=True)

def attach(timeout=90):
    t0=time.time()
    while time.time()-t0<timeout:
        try:
            return frida.get_device_manager().add_remote_device('127.0.0.1:27042').attach('Gadget')
        except Exception: time.sleep(1.2)
    raise RuntimeError('attach timeout')

print('[*] crash+start', flush=True)
adb('shell', 'am', 'crash', 'com.tudou.tool')
time.sleep(2)
adb('shell', 'am', 'start', '-n', 'com.tudou.tool/app.video.guoguo.SplashActivity')
print('[*] wait 25s', flush=True)
time.sleep(25)

session = attach()
script = session.create_script(open('out/gg_auth2_hook.js', encoding='utf-8').read())
script.on('message', on_message)
script.load()
print('[*] hooks loaded; 处理弹窗', flush=True)

# EMUI 弹窗: 风险提示 -> 不再提示 + 继续使用; 管控 -> 继续安装
tap(110, 2030); tap(281, 2150)
time.sleep(3)
tap(110, 2030); tap(823, 2150)
time.sleep(8)
# 首页应已加载并触发列表请求; 再向上滑两次触发翻页
adb('shell', 'input', 'swipe', '540', '1500', '540', '500', '300'); time.sleep(3)
adb('shell', 'input', 'swipe', '540', '1500', '540', '500', '300'); time.sleep(3)

print('[*] monitoring 240s — 请随机操作手机(点视频/返回)', flush=True)
time.sleep(240)
print('[*] done', flush=True)
