#!/usr/bin/env python3
"""pair_hunt2.py - 重启触发新请求 → 设备全量转储 → 设备端grep K16 → 只拉命中文件 → 派生测试."""
import base64
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

ADB = r"C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
PKG = "com.tudou.tool"
DEV_TMP = "/data/local/tmp/memdump2"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, 'research/captures/rsa_scan/pair2')

CUS = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
TR = str.maketrans(CUS, STD)


def cdec(s):
    return base64.b64decode(s.translate(TR) + "=" * (-len(s) % 4))


def adb(*args, timeout=300, binary=False):
    env = dict(os.environ, MSYS_NO_PATHCONV="1", ANDROID_ADB_SERVER_PORT="5039")
    r = subprocess.run([ADB, "-s", "emulator-5554"] + list(args),
                       capture_output=True, timeout=timeout, env=env)
    return r.stdout if binary else r.stdout.decode('utf-8', 'replace')


def load_bodies():
    out = []
    f = os.path.join(ROOT, 'research/captures/rsa_scan/bodies_now.jsonl')
    for line in open(f, encoding='utf-8', errors='replace'):
        try:
            o = json.loads(line)
        except Exception:
            continue
        resp = o.get('resp_body_ascii', '')
        if resp.count('.') != 1 or len(resp) < 400:
            continue
        parts = o['req'].split()
        if len(parts) < 2:
            continue
        out.append((parts[1].split('?')[0], resp))
    return out


def derivs(k16):
    kb = k16.encode()
    yield 'direct', kb
    yield 'reverse', kb[::-1]
    yield 'md5', hashlib.md5(kb).digest()
    yield 'md5hex16', hashlib.md5(kb).hexdigest().encode()[:16]
    yield 'sha1_16', hashlib.sha1(kb).digest()[:16]
    yield 'sha256_16', hashlib.sha256(kb).digest()[:16]
    yield 'md5_salt', hashlib.md5(kb + b'v50gjcy').digest()
    yield 'md5_salt2', hashlib.md5(b'v50gjcy' + kb).digest()
    yield 'md5_dev', hashlib.md5(
        (k16 + 'cddc4dcf-260d-4684-a8e7-463b2db261e5').encode()).digest()


def main():
    priv = RSA.import_key(open(os.path.join(
        ROOT, 'research/captures/rsa_scan/priv_from_go.pem'), 'rb').read())
    rsap = PKCS1_v1_5.new(priv)
    os.makedirs(OUT, exist_ok=True)

    old_n = len(load_bodies())
    print('bodies=%d, force-stop 重启 app...' % old_n, flush=True)
    adb("shell", "am", "force-stop", PKG)
    time.sleep(1.5)
    adb("shell", "am", "start", "-n", PKG + "/app.video.guoguo.SplashActivity")
    bodies = []
    for _ in range(30):
        time.sleep(2)
        bodies = load_bodies()
        if len(bodies) > old_n:
            break
    new = bodies[old_n:]
    if not new:
        print('失败: 重启后仍无新请求', flush=True)
        return
    print('新捕获 %d 条: %s' % (len(new), [p for p, _ in new][:8]), flush=True)

    k16s = []
    for path, resp in new:
        try:
            p0s, p1s = resp.split('.', 1)
            k = rsap.decrypt(cdec(p0s), None)
            if k and len(k) >= 16:
                k16s.append((path, k[:16].decode('ascii', 'replace'), p1s))
        except Exception:
            pass
    k16s = [(p, k, s) for p, k, s in k16s if re.fullmatch(r'[A-Za-z0-9]{16}', k)]
    print('K16 %d 个: %s' % (len(k16s), [k for _, k, _ in k16s]), flush=True)
    if not k16s:
        return

    # 转储窗口: K16 已在内存, 明文 ~15s. 立即设备端转储
    pid = adb("shell", "su -c 'pidof %s'" % PKG).strip().split()[0]
    maps = adb("shell", "su -c 'cat /proc/%s/maps'" % pid, timeout=60)
    regions = []
    for line in maps.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 2:
            continue
        perms = parts[1]
        path = parts[5].strip() if len(parts) > 5 else ""
        if not perms.startswith('r'):
            continue
        if path and not path.startswith('['):
            continue
        s, e = (int(x, 16) for x in parts[0].split('-'))
        if e - s > (1 << 30):
            continue
        regions.append((s, e - s))
    print('regions=%d, 生成设备脚本...' % len(regions), flush=True)

    lines = ["#!/system/bin/sh", "mkdir -p %s" % DEV_TMP,
             "rm -f %s/*.bin" % DEV_TMP]
    for i, (s, sz) in enumerate(regions):
        lines.append("/data/adb/magisk/busybox dd if=/proc/%s/mem of=%s/%03d_%x.bin"
                     " bs=4194304 skip=%d count=%d iflag=skip_bytes,count_bytes 2>/dev/null"
                     % (pid, DEV_TMP, i, s, s, sz))
    open(os.path.join(OUT, 'dump.sh'), 'w', newline='\n').write('\n'.join(lines) + '\n')
    adb("push", os.path.join(OUT, 'dump.sh'), "/data/local/tmp/pdump2.sh")
    t0 = time.time()
    adb("shell", "su -c 'sh /data/local/tmp/pdump2.sh'", timeout=900)
    print('设备转储 %.0fs' % (time.time() - t0), flush=True)

    # 设备端 grep K16
    pat = os.path.join(OUT, 'pats.txt')
    open(pat, 'w', newline='\n').write('\n'.join(k for _, k, _ in k16s) + '\n')
    adb("push", pat, "/data/local/tmp/pats.txt")
    hits = adb("shell", "su -c 'grep -l -f /data/local/tmp/pats.txt %s/*.bin 2>/dev/null'"
               % DEV_TMP, timeout=600)
    hitfiles = [h.strip().split('/')[-1] for h in hits.splitlines() if h.strip()]
    print('grep 命中 %d 文件: %s' % (len(hitfiles), hitfiles[:10]), flush=True)

    local_hits = []
    for hf in hitfiles:
        lp = os.path.join(OUT, hf)
        adb("pull", "%s/%s" % (DEV_TMP, hf), lp)
        local_hits.append(lp)

    # 配对与派生
    for path, k16, p1s in k16s:
        found = None
        for lp in local_hits:
            raw = open(lp, 'rb').read()
            p = raw.find(k16.encode())
            if p >= 0:
                found = (lp, raw, p)
                break
        if not found:
            print('%s K16=%s: dump 无匹配' % (path, k16), flush=True)
            continue
        lp, raw, p = found
        print('[配对] %s K16=%s @%s:0x%x ctx=%r' % (
            path, k16, os.path.basename(lp), p, raw[max(0, p-64):p+160]), flush=True)
        p1 = cdec(p1s)
        if len(p1) < 32:
            continue
        C1, C2 = p1[:16], p1[16:32]
        for nm, key in derivs(k16):
            if len(key) != 16:
                continue
            pt2 = bytes(x ^ y for x, y in zip(AES.new(key, AES.MODE_ECB).decrypt(C2), C1))
            pp = raw.find(pt2)
            if pp >= 0:
                dck = AES.new(key, AES.MODE_ECB).decrypt(C1)
                iv = bytes(x ^ y for x, y in zip(dck, raw[pp-16:pp]))
                print('[!!派生命中!!] %s 派生=%s key=%r iv=%r PT1=%r' % (
                    path, nm, key, iv, raw[pp-16:pp]), flush=True)
                json.dump({'path': path, 'derive': nm,
                           'key_hex': key.hex(), 'iv_hex': iv.hex()},
                          open(os.path.join(OUT, 'HIT.json'), 'w'))
                return
        print('%s: 9 派生未命中' % path, flush=True)


if __name__ == '__main__':
    main()
