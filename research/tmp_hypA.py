import sys, json
sys.path.insert(0, 'research/captures/rsa_scan')
sys.path.insert(0, 'src')
from e_oracle import EOracle
from jcy_protocol.auth import custom_b64d as cb64d

rb = open('research/tmp_forge_resp2.txt').read().strip()
p1 = cb64d(rb.split('.',1)[1])
k16req = bytes.fromhex('4cf2596ab020d8d70edfaf1183417571')
k16resp = b'HWE2HYC3QRJNEVKS'
blocks = [p1[i:i+16] for i in range(0, len(p1), 16)]
print('blocks:', len(blocks))

ZERO = b'\0'*16
def eraw(x, key):
    """E_raw(x): 单块, oracle iv=0 -> 首块输出即 E_raw(pt)"""
    o = EOracle()
    out = o.enc(x, key, ZERO)
    return out[:16]

for keyname, key in [('k16req', k16req), ('k16resp', k16resp)]:
    eraws = []
    for i, c in enumerate(blocks):
        eraws.append(eraw(c, key))
        print('%s E_raw(c%d) = %s' % (keyname, i, eraws[-1].hex()))
    for ivname, iv in [('rev', key[::-1]), ('same', key), ('zero', ZERO)]:
        pt = bytes(a^b for a,b in zip(eraws[0], iv))
        for i in range(1, len(blocks)):
            pt += bytes(a^b for a,b in zip(eraws[i], blocks[i-1]))
        printable = sum(1 for ch in pt if 32 <= ch < 127 or ch in (10,13,9))
        print('  [%s iv=%s] %s  printable=%d/%d' % (keyname, ivname, pt[:48], printable, len(pt)))
