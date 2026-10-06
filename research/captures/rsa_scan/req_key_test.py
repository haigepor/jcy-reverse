# -*- coding: utf-8 -*-
"""req_key_test.py — 验证：响应 P1 是否用【请求会话 key】加密（而非响应 K16 派生）。

请求 P0(RSA) → 请求会话 key+iv → 解请求 P1(验证) → 同 key 解响应 P1(裁决)。
"""
import base64
import json

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
TR = str.maketrans(ALPHA, STD)


def cb64d(s):
    t = s.translate(TR)
    t += '=' * ((-len(t)) % 4)
    return base64.b64decode(t)


def std64d(s):
    t = s + '=' * ((-len(s)) % 4)
    return base64.b64decode(t)


priv = RSA.import_key(open('research/captures/rsa_scan/priv_from_go.pem', 'rb').read())

hit = 0
for line in open('research/captures/rsa_scan/bodies_now.jsonl', encoding='utf-8',
                 errors='replace'):
    try:
        o = json.loads(line)
    except Exception:
        continue
    req = (o.get('req_body_ascii') or '').strip()
    resp = (o.get('resp_body_ascii') or '').strip()
    if req.count('.') != 1 or resp.count('.') != 1 or len(req) < 40:
        continue
    path = o.get('req', '').split('?')[0].split()[1] if o.get('req') else '?'
    p0r, p1r = req.split('.')
    p0s, p1s = resp.split('.')
    try:
        k = PKCS1_v1_5.new(priv).decrypt(cb64d(p0r), None)
    except Exception as e:
        k = None
    if not k:
        # 请求 P0 也许走 std b64
        try:
            k = PKCS1_v1_5.new(priv).decrypt(std64d(p0r), None)
        except Exception:
            k = None
    if not k:
        continue
    hit += 1
    print('=== %s 请求P0解出 %dB: %r' % (path, len(k), k[:40]))
    if len(k) >= 32:
        key, iv = k[:16], k[16:32]
        for enc, fn in (('custom', cb64d), ('std', std64d)):
            try:
                c = fn(p1r)
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
                pr = sum(32 <= x < 127 for x in pt) / max(len(pt), 1)
                print('  请求P1[%s] %dB 可打印率=%.2f: %r' % (enc, len(c), pr, pt[:120]))
                if pr > 0.9:
                    try:
                        print('  请求P1 JSON:', json.dumps(json.loads(pt.rstrip(
                            pt[-1:])), ensure_ascii=False)[:300])
                    except Exception:
                        pass
                    # 裁决: 同 key 解响应 P1
                    c2 = fn(p1s)
                    pt2 = AES.new(key, AES.MODE_CBC, iv).decrypt(c2)
                    pr2 = sum(32 <= x < 127 for x in pt2) / max(len(pt2), 1)
                    print('  >>> 响应P1[%s] %dB 可打印率=%.2f: %r' % (enc, len(c2), pr2, pt2[:200]))
                    if pr2 > 0.9:
                        print('  >>>>> 响应明文:', pt2[:400])
            except Exception as e:
                print('  请求P1[%s] 失败: %s' % (enc, e))
    if hit >= 4:
        break
print('共解出请求会话key:', hit, '条')
