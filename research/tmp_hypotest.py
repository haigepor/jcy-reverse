import sys, json
sys.path.insert(0, 'research/captures/rsa_scan')
from e_oracle import EOracle

s = json.load(open('research/tmp_resp_sample.json'))
k16 = s['k16resp'].encode('latin1')
p1 = bytes.fromhex(s['p1_hex'])
assert len(p1) % 16 == 0
iv = k16[::-1]
blocks = [p1[i:i+16] for i in range(0, len(p1), 16)]
# 构造喂给 E 的序列: x0 = c0^iv; x_i = c_i ^ c_{i-1}
feed = bytes(a^b for a,b in zip(blocks[0], iv))
for i in range(1, len(blocks)):
    feed += bytes(a^b for a,b in zip(blocks[i], blocks[i-1]))
print('feed:', feed.hex())
o = EOracle()
out = o.enc(feed, k16, iv)
print('E-chain output:', out)
print('as latin1:', out.decode('latin1', errors='replace'))
