# -*- coding: utf-8 -*-
"""tmp_resp_dec.py — 拉真实响应并离线解密 (P0 -> K16resp, P1 -> 明文)。"""
import os, sys, time, random, subprocess, http.client, base64
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(ROOT, 'research', 'captures', 'rsa_scan'))
sys.path.insert(0, os.path.join(ROOT, 'research', 'deliverables'))
sys.path.insert(0, os.path.join(ROOT, 'src'))
from jcy_protocol.auth import ALPHABET, STD_B64  # noqa
from Crypto.PublicKey import RSA  # noqa
from Crypto.Cipher import PKCS1_v1_5  # noqa
import decrypt_e as D  # noqa

HOST, PORT = '43.145.33.254', 27990
_TO_CUSTOM = str.maketrans(STD_B64, ALPHABET)
PRIV_GO = RSA.import_key(open(os.path.join(ROOT, 'research', 'captures', 'rsa_scan',
                                           'priv_from_go.pem'), 'rb').read())


def cb64d(s):
    s = s.strip().translate(str.maketrans(ALPHABET, STD_B64))
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def gen_auth(ts):
    out = subprocess.run([sys.executable, 'research/deliverables/authgen.py', '--ts', str(ts)],
                         capture_output=True, text=True, timeout=300, cwd=ROOT)
    for line in (out.stdout + out.stderr).splitlines():
        if 'auth' in line and '=' in line:
            v = line.split('=', 1)[1].strip()
            if len(v) >= 100:
                return v
    raise RuntimeError('authgen fail')


def get(path, ts, auth):
    H = {'x-version': '2020-09-17', 'user-agent': 'Dart/3.6 (dart:io)',
         'appid': '4150439554430529', 'tcs': '2', 'ts': str(ts),
         'nonce': str(random.randint(10**7, 10**8 - 1)), 'authentication': auth}
    c = http.client.HTTPConnection(HOST, PORT, timeout=15)
    c.request('GET', path, headers=H)
    r = c.getresponse()
    d = r.read().decode('utf-8', 'replace')
    c.close()
    return r.status, d


ts = int(time.time() * 1000)
auth = gen_auth(ts)
path = sys.argv[1] if len(sys.argv) > 1 else '/app/config'
st, body = get(path, ts, auth)
print('[%s] HTTP %s len=%d dots=%d' % (path, st, len(body), body.count('.')))
p0b, p1b = body.split('.', 1)
p0, p1 = cb64d(p0b), cb64d(p1b)
print('P0=%dB P1=%dB' % (len(p0), len(p1)))
k16resp = PKCS1_v1_5.new(PRIV_GO).decrypt(p0[:256], None)
print('K16resp=%r' % k16resp)
if k16resp:
    for label, key, iv in [('resp|rev', k16resp, k16resp[::-1]),
                           ('resp|same', k16resp, k16resp),
                           ('resp|0', k16resp, bytes(16))]:
        try:
            pt = D.decrypt(p1, key)
            ok = pt[:1] == b'{'
            print('  %-10s -> len=%d json=%s %r' % (label, len(pt), ok, pt[:90]))
        except Exception as e:
            print('  %-10s ERR %s' % (label, e))
