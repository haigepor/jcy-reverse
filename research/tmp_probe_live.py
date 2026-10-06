# -*- coding: utf-8 -*-
"""tmp_probe_live.py — 用有效 auth 探测当前服务端可用端点。"""
import os, sys, json, time, random, subprocess, http.client
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(ROOT, 'research', 'captures', 'rsa_scan'))

HOST, PORT = '43.145.33.254', 27990
HEADERS = {
    'x-version': '2020-09-17', 'user-agent': 'Dart/3.6 (dart:io)',
    'appid': '4150439554430529', 'tcs': '2',
    'content-type': 'application/json; charset=utf-8',
}


def gen_auth(ts):
    out = subprocess.run([sys.executable, 'research/deliverables/authgen.py', '--ts', str(ts)],
                         capture_output=True, text=True, timeout=300, cwd=ROOT)
    for line in (out.stdout + out.stderr).splitlines():
        if 'auth' in line and '=' in line:
            v = line.split('=', 1)[1].strip()
            if len(v) >= 100:
                return v
    raise RuntimeError('authgen fail: ' + (out.stdout + out.stderr)[-300:])


def req(method, path, auth, ts, body=None, timeout=12):
    h = dict(HEADERS)
    h.update({'ts': str(ts), 'nonce': str(random.randint(10**7, 10**8 - 1)), 'authentication': auth})
    c = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request(method, path, body=(body.encode() if body else None), headers=h)
        r = c.getresponse()
        d = r.read()
        return r.status, d
    finally:
        c.close()


ts = int(time.time() * 1000)
auth = gen_auth(ts)
print('ts=%d auth=%s...' % (ts, auth[:28]))
PATHS = ['/app/config', '/app/channel?top-level=true', '/app/banners/0',
         '/app/video/list?channel=1&sort=weight&limit=6&page=1',
         '/app/video/detail?id=113354', '/app/task/sign_rule', '/app/v2/config/host',
         '/app/video_update_list/2026-10-04', '/app/video/key?id=113354',
         '/app/upgrade']
for p in PATHS:
    try:
        st, d = run = req('GET', p, auth, ts)
        print('GET  %-52s HTTP %-4s len=%-6d %r' % (p, st, len(d), d[:110]))
    except Exception as e:
        print('GET  %-52s ERR %s' % (p, e))
for p, b in [('/app/video/device-base', '{}'), ('/app/video/record', '{}')]:
    try:
        st, d = req('POST', p, auth, ts, body=b)
        print('POST %-52s HTTP %-4s len=%-6d %r' % (p, st, len(d), d[:110]))
    except Exception as e:
        print('POST %-52s ERR %s' % (p, e))
