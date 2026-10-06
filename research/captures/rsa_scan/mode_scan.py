# -*- coding: utf-8 -*-
# 1) device-base 响应 K16 是否含 live 回放 K16 (K16<-请求绑定?)
# 2) key=K16 流模式 oracle: CTR/CFB/OFB/ECB, iv=K16/0
import json, base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util import Counter

CUST = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
TR = str.maketrans(CUST, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')

def cb64(s):
    t = s.translate(TR)
    return base64.b64decode(t + '=' * (-len(t) % 4))

priv = RSA.import_key(open('priv_from_go.pem', 'rb').read())
cp = PKCS1_v1_5.new(priv)
bodies = [json.loads(l) for l in open('bodies_now.jsonl', encoding='utf-8')]

target = b'3ME483VJDBQTEHD6'
ks = []
for o in bodies:
    if 'device-base' not in o.get('req', ''):
        continue
    rh = o.get('resp_body_hex')
    if not rh:
        continue
    txt = bytes.fromhex(rh).decode('ascii', 'replace')
    if '.' not in txt:
        continue
    k = cp.decrypt(cb64(txt.split('.')[0]), None)
    ks.append(k)
print('device-base K16s:', [x.decode() if x else None for x in ks[:8]])
print('live K16 =', target.decode(), ' 在捕获中?', target in ks)

pairs = []
for o in bodies:
    rh = o.get('resp_body_hex')
    if not rh:
        continue
    txt = bytes.fromhex(rh).decode('ascii', 'replace')
    if '.' not in txt:
        continue
    k = cp.decrypt(cb64(txt.split('.')[0]), None)
    p1 = cb64(txt.split('.')[1])
    if k and len(p1) >= 16 and len(p1) % 16 == 0:
        pairs.append((k, p1))
print('oracle 对:', len(pairs))

hits = 0
for k, p1 in pairs:
    for ivn, iv in (('K16', k), ('zero', b'\x00' * 16)):
        for mode in ('CTR', 'CFB', 'OFB'):
            try:
                if mode == 'CTR':
                    c = AES.new(k, AES.MODE_CTR,
                                counter=Counter.new(128, initial_value=int.from_bytes(iv, 'big')))
                else:
                    c = AES.new(k, getattr(AES, 'MODE_' + mode), iv=iv, segment_size=128)
            except Exception:
                continue
            d = c.decrypt(p1[:16])
            if d[0:1] == b'{' and all(32 <= ch < 127 for ch in d):
                print('STREAM HIT', mode, ivn, k, d)
                hits += 1
    d = AES.new(k, AES.MODE_ECB).decrypt(p1[:16])
    if d[0:1] == b'{' and all(32 <= ch < 127 for ch in d):
        print('ECB HIT', k, d)
        hits += 1
print('流模式/ECB 命中:', hits)
