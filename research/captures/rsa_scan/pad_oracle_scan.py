# -*- coding: utf-8 -*-
# dump 扫描 v3: 候选 key (任意16B可打印窗口) 用 响应P1 block2+block3 双可打印 (IV无关) 判据
# 真 key = 该响应对应请求的会话 key; 噪声 (0.74^16)^2 ≈ 5e-5/响应
import json, base64, glob
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

HERE = 'C:/Users/haige/Desktop/instruct/囧次元/research/captures/rsa_scan'
CUST = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
TR = str.maketrans(CUST, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')

def cb64(s):
    try:
        t = s.translate(TR)
        return base64.b64decode(t + '=' * (-len(t) % 4))
    except Exception:
        return b''

priv = RSA.import_key(open(HERE + '/priv_from_go.pem', 'rb').read())
cp = PKCS1_v1_5.new(priv)
bodies = [json.loads(l) for l in open(HERE + '/bodies_now.jsonl', encoding='utf-8')]
pairs = []
for idx, o in enumerate(bodies):
    rh = o.get('resp_body_hex')
    if not rh: continue
    txt = bytes.fromhex(rh).decode('ascii', 'replace')
    if '.' not in txt: continue
    p0 = cb64(txt.split('.')[0])
    if len(p0) != 256: continue
    k = cp.decrypt(p0, None)
    p1 = cb64(txt.split('.')[1])
    if k and len(p1) >= 64 and len(p1) % 16 == 0:
        pairs.append((idx, k, p1))
print('oracle 对(>=4块):', len(pairs))
probe = pairs[0]
C1, C2, C3 = probe[2][:16], probe[2][16:32], probe[2][32:48]

PRINT = set(range(0x20, 0x7f))
def pr16(b):
    return all(c in PRINT for c in b)

hits = []
tested = 0
for f in sorted(glob.glob(HERE + '/pair/p_*.bin')):
    data = open(f, 'rb').read()
    n = len(data)
    for i in range(n - 15):
        w = data[i:i + 16]
        if w[0] not in PRINT or w[7] not in PRINT or w[15] not in PRINT:
            continue
        ok = True
        for c in w:
            if c not in PRINT:
                ok = False
                break
        if not ok:
            continue
        tested += 1
        ecb = AES.new(w, AES.MODE_ECB)
        p2 = bytes(a ^ b for a, b in zip(ecb.decrypt(C2), C1))
        if not pr16(p2):
            continue
        p3 = bytes(a ^ b for a, b in zip(ecb.decrypt(C3), C2))
        if not pr16(p3):
            continue
        # 全量验证
        cnt = 0
        for idx, k, p1 in pairs:
            C1i, C2i, C3i = p1[:16], p1[16:32], p1[32:48]
            q2 = bytes(a ^ b for a, b in zip(ecb.decrypt(C2i), C1i))
            if not pr16(q2):
                continue
            q3 = bytes(a ^ b for a, b in zip(ecb.decrypt(C3i), C2i))
            if pr16(q3):
                cnt += 1
                if cnt == 1:
                    hits.append((f, i, w, idx, p2))
        print('CANDIDATE', f.split(chr(92))[-1] if chr(92) in f else f.split('/')[-1],
              hex(i), w, '全量命中', cnt)
print('probe 过双块判据的候选:', tested, '最终 hits:', len(hits))
for f, i, w, idx, p2 in hits[:10]:
    print(f, hex(i), w, 'rec', idx, 'p2=', p2[:24])
