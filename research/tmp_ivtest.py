import sys
sys.path.insert(0, 'research/captures/rsa_scan')
from e_oracle import EOracle
K = b'0123456789abcdef'
pt = b'A'*16
for name, key, iv in [
    ('K,iv1', K, b'1111111111111111'),
    ('K,iv2', K, b'2222222222222222'),
    ('K2,iv1', b'2222222222222222', b'1111111111111111'),
]:
    o = EOracle()
    out = o.enc(pt, key, iv)
    print(name, '->', out[:16].hex())
