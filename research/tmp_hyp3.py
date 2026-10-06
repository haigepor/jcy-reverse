import sys
sys.path.insert(0, 'research/captures/rsa_scan')
sys.path.insert(0, 'src')
from e_oracle import EOracle
from jcy_protocol.auth import custom_b64d as cb64d

rb = open('research/tmp_forge_resp2.txt').read().strip()
p1 = cb64d(rb.split('.',1)[1])
k16req = bytes.fromhex('4cf2596ab020d8d70edfaf1183417571')
blocks = [p1[i:i+16] for i in range(0, len(p1), 16)]
ivname = sys.argv[1]
iv = k16req[::-1] if ivname=='rev' else k16req
feed = bytes(a^b for a,b in zip(blocks[0], iv))
for i in range(1, len(blocks)):
    feed += bytes(a^b for a,b in zip(blocks[i], blocks[i-1]))
o = EOracle()   # 全新会话
out = o.enc(feed, k16req, iv)
print('iv=%s ->' % ivname, out[:48])
