#!/usr/bin/env python3
"""pair_hunt.py - 紧耦合配对: 触发请求 → 8 热区转储 → 解 K16 → 配对 → 派生测试."""
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
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, 'research/captures/rsa_scan/pair')

HOT = ['737c00000000', '737de0c69000', '737e3d745000', '737e41700000',
       '737e41c00000', '737e4265f000', '737e43117000', '737e62887000']

CUS = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
TR = str.maketrans(CUS, STD)
SALT = b'v50gjcy'


def cdec(s):
    return base64.b64decode(s.translate(TR) + "=" * (-len(s) % 4))


def adb(*args, timeout=180, binary=False):
    env = dict(os.environ, MSYS_NO_PATHCONV="1", ANDROID_ADB_SERVER_PORT="5039")
    return subprocess.run([ADB, "-s", "emulator-5554"] + list(args),
                          capture_output=True, timeout=timeout, env=env)


def tap(x, y):
    adb("shell", "input", "tap", str(x), str(y))


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
        out.append((o['req'].split()[1].split('?')[0], resp))
    return out


def main():
    priv = RSA.import_key(open(os.path.join(
        ROOT, 'research/captures/rsa_scan/priv_from_go.pem'), 'rb').read())
    rsap = PKCS1_v1_5.new(priv)
    os.makedirs(OUT, exist_ok=True)

    # 区域精确尺寸
    regions = {}
    rj = os.path.join(ROOT, 'research/captures/rsa_scan/livedump/regions.json')
    if os.path.exists(rj):
        data = json.load(open(rj))
        if isinstance(data, dict):
            data = data.get('regions', [])
        for r in data:
            if not isinstance(r, dict):
                continue
            start = r.get('start') or r.get('addr')
            if start:
                regions['%x' % int(str(start), 16)] = r.get('size', 0)
    # 从 livedump 文件名直接取
    for f in glob.glob(os.path.join(ROOT, 'research/captures/rsa_scan/livedump/*.bin')):
        b = os.path.basename(f)[:-4]
        tag, addr = b.split('_', 1)
        regions[addr] = os.path.getsize(f)

    old_n = len(load_bodies())
    print('现有 bodies %d 条, 触发请求...' % old_n, flush=True)
    tap(270, 480); time.sleep(0.8)
    tap(450, 480); time.sleep(0.8)
    tap(100, 480); time.sleep(2.5)
    if len(load_bodies()) == old_n:
        print('tap 未触发, 重启 SplashActivity', flush=True)
        adb("shell", "am", "start", "-n",
            "com.tudou.tool/app.video.guoguo.SplashActivity")
        for _ in range(12):
            time.sleep(1.5)
            if len(load_bodies()) > old_n:
                break
        else:
            print('失败: 重启后仍无新请求', flush=True)
            return

    # 生成设备脚本 (十进制 skip)
    lines = ["#!/system/bin/sh", "rm -f /data/local/tmp/p_*.bin"]
    for addr in HOT:
        sz = regions.get(addr)
        if not sz:
            continue
        nb = (sz + 4095) // 4096
        lines.append("/system/bin/toybox dd if=/proc/$(pidof com.tudou.tool)/mem "
                     "of=/data/local/tmp/p_%s.bin bs=4096 skip=%d count=%d conv=noerror,sync 2>/dev/null"
                     % (addr, int(addr, 16) // 4096, nb))
    script = os.path.join(OUT, 'pdump.sh')
    open(script, 'w', newline='\n').write('\n'.join(lines) + '\n')
    adb("push", script, "/data/local/tmp/pdump.sh")
    t0 = time.time()
    r = adb("shell", "su", "-c", "sh /data/local/tmp/pdump.sh", timeout=120)
    if r.returncode != 0 or b'not found' in r.stderr:
        print('设备脚本失败: %r %r' % (r.stdout[-200:], r.stderr[-200:]), flush=True)
        return
    nb = sum(1 for a in HOT if adb("shell", "ls", "/data/local/tmp/p_%s.bin" % a,
                                   ).returncode == 0)
    print('设备转储 %.1fs, %d/8 文件' % (time.time() - t0, nb), flush=True)

    for addr in HOT:
        adb("pull", "/data/local/tmp/p_%s.bin" % addr,
            os.path.join(OUT, "p_%s.bin" % addr))

    # 新 bodies -> K16
    bodies = load_bodies()
    new = bodies[old_n:]
    print('新捕获 %d 条' % len(new), flush=True)
    k16s = []
    for path, resp in new:
        try:
            p0s, p1s = resp.split('.', 1)
            k = rsap.decrypt(cdec(p0s), None)
            if k and len(k) >= 16:
                k16s.append((path, k[:16].decode('ascii', 'replace'), p1s))
        except Exception:
            pass
    print('K16 %d: %s' % (len(k16s), [k for _, k, _ in k16s]), flush=True)

    # 搜索
    dumps = {a: open(os.path.join(OUT, 'p_%s.bin' % a), 'rb').read() for a in HOT}
    paired = []
    for path, k16, p1s in k16s:
        for a, raw in dumps.items():
            p = raw.find(k16.encode())
            if p >= 0:
                print('[配对] %s K16=%s @%s/0x%x ctx=%r' % (path, k16, a, p, raw[max(0, p-96):p+128]), flush=True)
                paired.append((path, k16, p1s, a, p))
                break
    if not paired:
        print('未配对; dump 明文统计:', flush=True)
        for a, raw in dumps.items():
            print('  %s: {"code" x%d, K16式串 x%d' % (
                a, raw.count(b'{"code"'),
                len(re.findall(rb'[A-Z0-9]{16}', raw))), flush=True)
        return

    # 派生测试: block2 已知明文法 (配对明文必在附近, 直接全文搜 PT2)
    def derivs(k):
        kb = k.encode()
        yield 'direct', kb
        yield 'reverse', kb[::-1]
        yield 'md5', hashlib.md5(kb).digest()
        yield 'md5hex16', hashlib.md5(kb).hexdigest().encode()[:16]
        yield 'sha1_16', hashlib.sha1(kb).digest()[:16]
        yield 'sha256_16', hashlib.sha256(kb).digest()[:16]
        yield 'md5_salt', hashlib.md5(kb + SALT).digest()
        yield 'md5_salt2', hashlib.md5(SALT + kb).digest()

    for path, k16, p1s, a, _ in paired:
        p1 = cdec(p1s)
        if len(p1) < 32:
            continue
        C1, C2 = p1[:16], p1[16:32]
        raw = dumps[a]
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
                return
        print('%s: 9 种派生未命中 (明文可能不在同区)' % path, flush=True)


if __name__ == '__main__':
    main()
