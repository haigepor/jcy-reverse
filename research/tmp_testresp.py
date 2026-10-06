import sys, json
sys.path.insert(0, 'research/deliverables')
sys.path.insert(0, 'src')
from authgen_server import cb64d, _keys
from Crypto.Cipher import PKCS1_v1_5

# 1) 取一条响应
for ln in open('research/captures/proxy_bodies.jsonl', encoding='utf-8', errors='replace'):
    try: d = json.loads(ln)
    except Exception: continue
    if 'device-base' in (d.get('req') or '') and d.get('resp_status','').endswith('OK'):
        hx = d['resp_body_hex']; break
body = bytes.fromhex(hx).decode('latin1')
print('body head:', body[:80])
print('dot count:', body.count('.'))
p0 = cb64d(body.split('.',1)[0]); p1 = cb64d(body.split('.',1)[1])
print('p0 len:', len(p0), 'p1 len:', len(p1))
k = PKCS1_v1_5.new(_keys()[1]).decrypt(p0[:256], None)
print('k16resp:', k)
open('research/tmp_resp_sample.json','w').write(json.dumps({
  'k16resp': k.decode('latin1'), 'p1_hex': p1.hex()}))
print('saved research/tmp_resp_sample.json')
