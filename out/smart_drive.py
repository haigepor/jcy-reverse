# -*- coding: utf-8 -*-
# screenshot-aware UI driver: dismiss EMUI dialogs, then browse a fresh video
import subprocess, time, io, sys
ADB = './tools/platform-tools/adb.exe'

def sh(cmd, timeout=30):
    return subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)

def tap(x, y, wait=1.5):
    sh(f'{ADB} shell input tap {x} {y}'); time.sleep(wait)

def screen_mean():
    p = subprocess.run(f'{ADB} exec-out screencap -p', shell=True, capture_output=True, timeout=20)
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(p.stdout)).convert('L')
        px = list(im.getdata())
        return sum(px)/len(px), im.size
    except Exception as e:
        return None, None

def dismiss_dialogs(max_wait=90):
    t0 = time.time()
    seq = 0
    while time.time() - t0 < max_wait:
        mean, size = screen_mean()
        if mean is None:
            time.sleep(2); continue
        # dialog screens are mostly white (mean > 150); app home is dark (mean < 80)
        if mean < 100:
            print('[drive] app UI ready (mean=%.0f)' % mean, flush=True)
            return True
        print('[drive] dialog on screen (mean=%.0f), tapping' % mean, flush=True)
        seq += 1
        if seq % 2 == 1:
            tap(110, 2030, 0.8)   # do-not-ask checkbox
            tap(270, 2130, 2.5)   # continue using / cancel
        else:
            tap(270, 2130, 2.5)   # cancel
            tap(823, 2150, 2.5)   # continue install (if on that page)
    return False

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'browse'
    if mode == 'dismiss':
        dismiss_dialogs(); sys.exit(0)
    if not dismiss_dialogs():
        print('[drive] dialogs never cleared', flush=True); sys.exit(1)
    # browse: switch to a less-used channel tab then first card, then play
    sh(f'{ADB} shell input tap 911 146'); time.sleep(4)
    sh(f'{ADB} shell input swipe 540 1800 540 1200 300'); time.sleep(2)
    sh(f'{ADB} shell input tap 186 1272'); time.sleep(8)
    sh(f'{ADB} shell input tap 545 396'); time.sleep(6)
    sh(f'{ADB} shell input tap 545 396'); time.sleep(10)
    print('[drive] done', flush=True)
