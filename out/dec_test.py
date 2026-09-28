import json, base64, re
from Crypto.Cipher import AES
def dec(ct, k, iv):
    if len(ct)%16 or not ct: return None
    pt = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if 1<=pad<=16 and pt[-pad:]==bytes([pad])*pad: pt=pt[:-pad]
    return pt
recs = [json.loads(l) for l in open('out/hex_log.jsonl', encoding='utf-8')]
k1 = b'cMFgrFtna4HeOf1h'; k2 = b'w36cqV5MvPSeij61'
n = 0
for r in recs:
    if r['t'] != 'apiDecrypt.enter': continue
    x1 = None; x2 = None
    for a in r['args']:
        if a['r'] == 'x1': x1 = a
        if a['r'] == 'x2': x2 = a
    if not x1 or not x1.get('hex'): continue
    b = bytes.fromhex(x1['hex'])
    m = re.match(rb'[A-Za-z0-9+/=]+', b[16:])
    if not m: continue
    try:
        ct = base64.b64decode(m.group())
    except Exception:
        continue
    for kn, k, iv in [('k1/iv2',k1,k2),('k2/iv1',k2,k1),('k1/k1',k1,k1),('k2/k2',k2,k2)]:
        pt = dec(ct,k,iv)
        if pt:
            pr = sum(1 for c in pt[:64] if 32<=c<127)/min(64,len(pt))
            print(kn, len(ct), round(pr,2), pt[:90])
    print('---')
    n += 1
    if n >= 4: break
print('done', n)
