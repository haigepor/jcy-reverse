# -*- coding: utf-8 -*-
# PKCS7 padding oracle: key=K16 各种变换下, D(C_last)^C_prev 末尾是否为合法 PKCS7
# 随机 16B 通过 PKCS7 概率 ≈ (1/256)*(1 + 1/256 + ...) ≈ 0.4% → 134 条中命中率高 = key 确认
import json, base64, hashlib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

HERE = 'C:/Users/haige/Desktop/instruct/囧次元/research/captures/rsa_scan'
CUST = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
TR = str.maketrans(CUST, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')

def cb64(s):
    t = s.translate(TR)
    return base64.b64decode(t + '=' * (-len(t) % 4))

priv = RSA.import_key(open(HERE + '/priv_from_go.pem', 'rb').read())
cp = PKCS1_v1_5.new(priv)

bodies = [json.loads(l) for l in open(HERE + '/bodies_now.jsonl', encoding='utf-8')]

def keycands(k):
    out = {'K16': k}
    out['K16rev'] = k[::-1]
    out['md5(K16)'] = hashlib.md5(k).digest()
    out['md5hex16'] = hashlib.md5(k).hexdigest()[:16].encode()
    out['sha256[:16]'] = hashlib.sha256(k).digest()[:16]
    out['md5hexU16'] = hashlib.md5(k).hexdigest().upper()[:16].encode()
    return out

stats = {}
samples = {}
n = 0
for i, o in enumerate(bodies):
    rh = o.get('resp_body_hex')
    if not rh: continue
    rb = bytes.fromhex(rh)
    try: txt = rb.decode('ascii')
    except Exception: continue
    if '.' not in txt: continue
    p0s, p1s = txt.split('.', 1)
    try: p0 = cb64(p0s); p1 = cb64(p1s)
    except Exception: continue
    if len(p0) != 256 or len(p1) < 32 or len(p1) % 16: continue
    k = cp.decrypt(p0, None)
    if not k or len(k) != 16: continue
    n += 1
    for kn, kk in keycands(k).items():
        ecb = AES.new(kk, AES.MODE_ECB)
        d = ecb.decrypt(p1[-16:])
        prev = p1[-32:-16]
        pt = bytes(a ^ b for a, b in zip(d, prev))
        nb = pt[-1]
        ok = 1 <= nb <= 16 and pt[-nb:] == bytes([nb]) * nb
        stats[kn] = stats.get(kn, 0) + (1 if ok else 0)
        if ok and kn == 'K16' and len(samples.get('K16', [])) < 5:
            samples.setdefault('K16', []).append((i, nb, pt))

print(f'响应对数: {n}')
for kn, c in sorted(stats.items(), key=lambda x: -x[1]):
    print(f'  {kn:12s}: {c}/{n} PKCS7 valid')
print()
for i, nb, pt in samples.get('K16', []):
    print(f'rec{i} padlen={nb} lastblock={pt!r}')
