# -*- coding: utf-8 -*-
# key store 扫描: 内存 dump 中找 32B 连续大写字母数字 (key+iv), 用响应 P1 JSON oracle 验证
# 模型: native key store 持久保存会话 key+iv, 请求/响应用同一对; RSA_public_encrypt 包 32B
import json, base64, re, glob, sys
from Crypto.Cipher import AES

HERE = 'C:/Users/haige/Desktop/instruct/囧次元/research/captures/rsa_scan'
CUST = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
TR = str.maketrans(CUST, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')

def cb64(s):
    t = s.translate(TR)
    return base64.b64decode(t + '=' * (-len(t) % 4))

# 取 3 条响应 P1 做 oracle (不同端点)
bodies = [json.loads(l) for l in open(HERE + '/bodies_now.jsonl', encoding='utf-8')]
tests = []
for o in bodies:
    rh = o.get('resp_body_hex')
    if not rh: continue
    rb = bytes.fromhex(rh)
    try: txt = rb.decode('ascii')
    except Exception: continue
    if '.' not in txt: continue
    p0s, p1s = txt.split('.', 1)
    try: p1 = cb64(p1s)
    except Exception: continue
    if len(p1) >= 48 and len(p1) % 16 == 0:
        tests.append((o['req'], p1))
    if len(tests) >= 3: break
print('oracle 响应:', [t[0] for t in tests])

pat = re.compile(rb'[A-Z0-9]{32,40}')
cands = set()
files = sorted(glob.glob(HERE + '/pair/p_*.bin'))
for f in files:
    data = open(f, 'rb').read()
    for m in pat.finditer(data):
        s = m.group()
        # 32 或 两个16 (允许 33-40 里滑窗取 32)
        for st in range(0, len(s) - 31):
            cands.add(s[st:st + 32])
    print(f'{f.split(chr(92))[-1]}: +{len(cands)} 累计候选')
print('总候选:', len(cands))

hits = []
for c in cands:
    k = c[:16]; iv = c[16:32]
    for key, ivv, tag in ((k, iv, 'k|iv'), (iv, k, 'iv|k'), (k, k, 'k|k'),
                          (k, b'\x00' * 16, 'k|0')):
        try:
            d = AES.new(key, AES.MODE_CBC, ivv).decrypt(tests[0][1][:16])
        except Exception:
            continue
        if d[0:1] == b'{' and all(32 <= ch < 127 for ch in d):
            hits.append((c, tag, d))
if hits:
    for c, tag, d in hits[:10]:
        print('HIT:', c, tag, d)
else:
    print('32B 连续窗口 0 命中 → 尝试宽松形态(含小写/分隔符)或 key 非 ASCII')
