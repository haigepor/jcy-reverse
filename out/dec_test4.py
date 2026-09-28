import json, base64, re
from Crypto.Cipher import AES
# key/iv 交叉组合全试
KS = [b'kFGTbLlOzFHQCIKp', b'F3q22XoM8l6T2Ydc', b'qPwClBj7j7ZQraSm', b'p3JdVQl3q7WQJIgG']
IVS = KS + [b'\x00'*16]
def score(pt):
    if not pt: return 0
    return sum(1 for c in pt[:64] if 32 <= c < 127)/min(64,len(pt))
recs = [json.loads(l) for l in open('out/key_log.jsonl', encoding='utf-8')]
targets = []
for r in recs:
    if r['t'] != 'apiDecrypt.enter': continue
    x1 = x2 = None
    for a in r['args']:
        if a['r']=='x1': x1=a
        if a['r']=='x2': x2=a
    if not x1 or not x1.get('hex'): continue
    b = bytes.fromhex(x1['hex'])
    m = re.match(rb'[\x20-\x7e]{100,}', b[16:])
    if not m: continue
    url = ''
    if x2 and x2.get('hex'):
        b2 = bytes.fromhex(x2['hex'])
        m2 = re.search(rb'/app/[\x20-\x7e]{5,}', b2)
        if m2: url = m2.group()[:40].decode()
    try: ct = base64.b64decode(m.group())
    except Exception: continue
    targets.append((url, ct))
print('targets:', [(u, len(c)) for u,c in targets[:6]])
hits = 0
for url, ct in targets:
    for k in KS:
        for iv in IVS:
            if len(ct)%16: continue
            pt = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
            if score(pt) > 0.75:
                print('*** HIT', url, k[:6], iv[:6], pt[:150]); hits += 1
print('cross hits:', hits)
