import json, base64, re
from Crypto.Cipher import ARC4, AES
recs = [json.loads(l) for l in open('out/hex_log.jsonl', encoding='utf-8')]
k1 = b'cMFgrFtna4HeOf1h'; k2 = b'w36cqV5MvPSeij61'
KEYS = [('k1',k1),('k2',k2),('k1+k2',k1+k2),('k2+k1',k2+k1),
        ('kFGT',b'kFGTbLlOzFHQCIKp'),('kFGT+iv',b'kFGTbLlOzFHQCIKp'+b'F3q22XoM8l6T2Ydc')]
n = 0
for r in recs:
    if r['t'] != 'apiDecrypt.enter': continue
    x1 = None
    for a in r['args']:
        if a['r'] == 'x1': x1 = a
    if not x1 or not x1.get('hex'): continue
    b = bytes.fromhex(x1['hex'])
    m = re.match(rb'[\x20-\x7e]{100,}', b[16:])
    if not m: continue
    s = m.group()
    try: ct = base64.b64decode(s)
    except Exception: continue
    for kn, k in KEYS:
        pt = ARC4.new(k).decrypt(ct)
        pr = sum(1 for c in pt[:64] if 32 <= c < 127) / 64
        if pr > 0.7:
            print('***RC4 HIT', kn, len(ct), pt[:200])
    n += 1
    if n >= 4: break
print('rc4 tested:', n)
