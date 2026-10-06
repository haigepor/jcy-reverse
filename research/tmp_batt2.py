import sys, base64, hashlib
sys.path.insert(0, 'src')
from jcy_protocol.auth import custom_b64d as cb64d
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import unpad

rb = open('research/tmp_forge_resp2.txt').read().strip()
p1 = cb64d(rb.split('.',1)[1])
k16req = bytes.fromhex('4cf2596ab020d8d70edfaf1183417571')
k16resp = b'HWE2HYC3QRJNEVKS'

print('P1:', p1.hex())
# AES 家族全测
keys = {'k16req': k16req, 'k16resp': k16resp,
        'md5(k16req)': hashlib.md5(k16req).digest(),
        'md5(k16resp)': hashlib.md5(k16resp).digest(),
        'md5hex(k16req)': hashlib.md5(k16req).hexdigest()[:16].encode(),
        'md5hex(k16resp)': hashlib.md5(k16resp).hexdigest()[:16].encode(),
        'sha256(k16req)[:16]': hashlib.sha256(k16req).digest()[:16],
        'sha256(k16resp)[:16]': hashlib.sha256(k16resp).digest()[:16],
        }
ivs = {'zero': b'\0'*16, 'k16req': k16req, 'rev_k16req': k16req[::-1],
       'k16resp': k16resp, 'rev_k16resp': k16resp[::-1]}
hits = 0
for kn, k in keys.items():
    for mode in ('CBC','ECB','CFB','OFB','CTR'):
        for ivn, iv in ivs.items():
            if mode == 'ECB' and ivn != 'zero': continue
            try:
                if mode in ('CFB','OFB','CTR','CBC') :
                    c = AES.new(k, getattr(AES,'MODE_'+mode), nonce=b'', iv=iv) if mode!='CTR' else AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=iv)
                else:
                    c = AES.new(k, AES.MODE_ECB)
                pt = c.decrypt(p1)
            except Exception as ex:
                continue
            # 判定: 解出应当是 JSON/text
            try:
                t = pt.decode('utf-8')
                score = sum(1 for ch in t if 32 <= ord(ch) < 127 or ch in '\n\r\t')
                if score > len(pt)*0.85:
                    print('*** HIT %s %s iv=%s: %r' % (kn, mode, ivn, t[:80]))
                    hits += 1
            except Exception:
                pass
print('AES battery hits:', hits)
