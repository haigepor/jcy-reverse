import json, base64, re
from Crypto.Cipher import AES

KEY = b'kFGTbLlOzFHQCIKp'; IV = b'F3q22XoM8l6T2Ydc'
MON_K = b'qPwClBj7j7ZQraSm'; MON_IV = b'p3JdVQl3q7WQJIgG'

def dec_aes(ct, k=KEY, iv=IV):
    if len(ct) % 16 or not ct: return None
    pt = AES.new(k, AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad])*pad: pt = pt[:-pad]
    return pt

def getobj(a):
    if not a.get('hex'): return None
    b = bytes.fromhex(a['hex'])
    if len(b) < 20: return None
    # printable run from +12 or +16
    for start in (12, 16):
        m = re.match(rb'[\x20-\x7e]{20,}', b[start:])
        if m: return m.group()
    return None

recs = [json.loads(l) for l in open('out/key_log.jsonl', encoding='utf-8')]
from collections import Counter
print(Counter(r['t'] for r in recs))
print()

n = 0
for r in recs:
    t = r['t']
    if t == 'apiDecrypt.enter':
        x1 = x2 = None
        for a in r['args']:
            if a['r'] == 'x1': x1 = a
            if a['r'] == 'x2': x2 = a
        s1 = getobj(x1) if x1 else None
        s2 = getobj(x2) if x2 else None
        url = ''
        if s2:
            m2 = re.search(rb'https?://[\x20-\x7e]{10,}', s2)
            if m2: url = m2.group()[:75].decode()
        if not s1: continue
        print('=== apiDecrypt', url[:75])
        # try b64 inside
        m64 = re.search(rb'[A-Za-z0-9+/]{40,}', s1)
        if m64:
            try:
                ct = base64.b64decode(m64.group())
                pt = dec_aes(ct)
                if pt:
                    pr = sum(1 for c in pt[:80] if 32 <= c < 127)/min(80, len(pt))
                    print('    AES-kFGT:', round(pr,2), pt[:220])
                else:
                    print('    (not block aligned:', len(ct), ')')
            except Exception as e:
                print('    b64 err')
        else:
            # maybe plaintext json
            print('    raw:', s1[:200])
        n += 1
        if n >= 10: break
print('shown', n)
