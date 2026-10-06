# -*- coding: utf-8 -*-
"""tmp_cbc_check.py — 检验真实响应 P1 是否可用"朴素 CBC"(无 tweak) 解出。"""
import os, sys, json, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
sys.path.insert(0, os.path.join(ROOT, 'research', 'deliverables'))
sys.path.insert(0, os.path.join(ROOT, 'research', 'captures', 'rsa_scan'))
sys.path.insert(0, os.path.join(ROOT, 'src'))
import jcy_client as J  # noqa
import decrypt_e as D  # noqa
import tmp_verify_decrypt as V  # noqa
from e_oracle import EOracle  # noqa

cli = J.JcyClient()
# 直接拿原始 P0/P1（绕过 decrypt_e 的标定），只做一次 oracle 调用求 C(K)
import http.client, random
ts, auth = cli._auth_header()
H = dict(J.STATIC_HEADERS); H.update({'ts': str(ts), 'nonce': str(random.randint(10**7, 10**8-1)), 'authentication': auth})
c = http.client.HTTPConnection(J.HOST, J.PORT, timeout=15)
c.request('GET', '/app/video/key?id=113354', headers=H)
r = c.getresponse(); body = r.read().decode('utf-8', 'replace'); c.close()
p0b, p1b = body.split('.', 1)
p0, p1 = J.cb64d(p0b), J.cb64d(p1b)
from Crypto.Cipher import PKCS1_v1_5
k16resp = PKCS1_v1_5.new(J.PRIV_GO).decrypt(p0[:256], None)
print('K16resp=%r  P1=%dB (%d blocks)' % (k16resp, len(p1), len(p1)//16))

o = EOracle()
t0 = time.time()
C = V.determine_C(o, k16resp)
print('C(K16resp)=%s  (%.1fs)' % (C.hex(), time.time() - t0))

# 朴素 CBC
t0 = time.time()
naive = V.decrypt(p1, k16resp, C)
print('naive CBC  (%.2fs): %r' % (time.time() - t0, naive[:100]))

# tweak 版
t0 = time.time()
tweaked = D.decrypt(p1, k16resp)
print('tweak decrypt (%.1fs): %r' % (time.time() - t0, tweaked[:100]))
print('naive == tweaked ?', naive == tweaked)
