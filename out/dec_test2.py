import json, base64, re
from Crypto.Cipher import AES

recs = [json.loads(l) for l in open('out/hex_log.jsonl', encoding='utf-8')]
k1 = b'cMFgrFtna4HeOf1h'; k2 = b'w36cqV5MvPSeij61'

def getstr(a):
    if not a.get('hex'): return None
    b = bytes.fromhex(a['hex'])
    if len(b) < 20: return None
    ln = int.from_bytes(b[8:12], 'little') >> 1
    if ln <= 0 or ln > 60000: return None
    return b[16:16+ln]

n = 0
for r in recs:
    if r['t'] != 'apiDecrypt.enter': continue
    x1 = x2 = None
    for a in r['args']:
        if a['r'] == 'x1': x1 = a
        if a['r'] == 'x2': x2 = a
    o1 = getstr(x1)
    if not o1 or len(o1) < 100: continue
    url = '(?)'
    o2 = getstr(x2)
    if o2:
        m2 = re.search(rb'https?://[\x20-\x7e]{10,}', o2)
        if m2: url = m2.group()[:60].decode()
    try:
        ct = base64.b64decode(o1)
    except Exception as e:
        print(url, 'b64err', len(o1), str(e)[:40]); continue
    if len(ct) % 16:
        print(url[:55], 'ctlen', len(ct), 'not mult 16'); continue
    for kn, k, iv in [('k1iv2',k1,k2),('k2iv1',k2,k1),('k1k1',k1,k1),('k2k2',k2,k2),('kFGT',b'kFGTbLlOzFHQCIKp',b'F3q22XoM8l6T2Ydc')]:
        pt = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
        pr = sum(1 for c in pt[:64] if 32 <= c < 127) / 64
        mark = '***HIT' if pr > 0.7 else '     '
        print(mark, url[:55], kn, round(pr,2), pt[:80])
    print()
    n += 1
    if n >= 4: break
print('tested:', n)
