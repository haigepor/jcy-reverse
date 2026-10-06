import sys, base64, hashlib, struct
sys.path.insert(0, 'src')
from jcy_protocol.auth import custom_b64d as cb64d

rb = open('research/tmp_forge_resp2.txt').read().strip()
p1 = cb64d(rb.split('.',1)[1])
k16req = bytes.fromhex('4cf2596ab020d8d70edfaf1183417571')
k16resp = b'HWE2HYC3QRJNEVKS'

SBOX = open('research/artifacts/device_libs/libcore.so','rb').read()[0x20b630:0x20b630+256]
# 自检：真SM4 SBOX[0]=0xd6
print('SBOX[0]=%02x (应为d6)' % SBOX[0])
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = []
for i in range(32):
    CK.append(bytes(((4*i+j)*(7+4*j)) % 256 for j in range(4)))
def rotl(x, n): return ((x << n) | (x >> (32-n))) & 0xffffffff
def tau(a): return (SBOX[(a>>24)&0xff]<<24)|(SBOX[(a>>16)&0xff]<<16)|(SBOX[(a>>8)&0xff]<<8)|SBOX[a&0xff]
def T(x):
    b = tau(x); return b ^ rotl(b,2) ^ rotl(b,10) ^ rotl(b,18) ^ rotl(b,24)
def T2(x):
    b = tau(x); return b ^ rotl(b,13) ^ rotl(b,23)
def sm4_ks(key):
    mk = struct.unpack('>4I', key); k = [mk[i]^FK[i] for i in range(4)]; rk=[]
    for i in range(32):
        nk = k[0] ^ T2(k[1]^k[2]^k[3]^struct.unpack('>I', CK[i])[0]); rk.append(nk); k = k[1:]+[nk]
    return rk
def sm4_dec(blk, rk):
    x = list(struct.unpack('>4I', blk))
    for i in range(32):
        nx = x[0] ^ T(x[1]^x[2]^x[3]^rk[31-i]); x = x[1:]+[nx]
    return struct.pack('>4I', *x[::-1])
# 标准向量自检: key/plaintext 0123456789abcdeffedcba9876543210 -> 681edf34d206965e86b3e94f536e4246
rk = sm4_ks(bytes.fromhex('0123456789abcdeffedcba9876543210'))
ct = sm4_dec(bytes.fromhex('681edf34d206965e86b3e94f536e4246'), rk[::-1])[0:0]  # noop
def sm4_enc(blk, rk):
    x = list(struct.unpack('>4I', blk))
    for i in range(32):
        nx = x[0] ^ T(x[1]^x[2]^x[3]^rk[i]); x = x[1:]+[nx]
    return struct.pack('>4I', *x[::-1])
v = sm4_enc(bytes.fromhex('0123456789abcdeffedcba9876543210'), sm4_ks(bytes.fromhex('0123456789abcdeffedcba9876543210')))
print('SM4 selftest: %s (应681edf34d206965e86b3e94f536e4246)' % v.hex())
assert v.hex() == '681edf34d206965e86b3e94f536e4246'

def score(b):
    try: t = b.decode('utf-8')
    except: return -1
    return sum(1 for ch in t if 32 <= ord(ch) < 127 or ch in '\n\r\t') / len(b)

keys = {'req': k16req, 'resp': k16resp, 'req_hex': k16req.hex().encode(), 'resp_hex': k16resp.hex().encode(),
        'md5(req)': hashlib.md5(k16req).digest(), 'md5hex(req)': hashlib.md5(k16req).hexdigest().encode(),
        'md5hex16(req)': hashlib.md5(k16req).hexdigest()[:16].encode()}
ivs = {'zero': b'\0'*16, 'req': k16req, 'reqrev': k16req[::-1], 'resp': k16resp, 'resprev': k16resp[::-1]}

hits = 0
for kn, k in keys.items():
    rk = sm4_ks(k)
    for mode in ('CBC','ECB'):
        for ivn, iv in ivs.items():
            if mode == 'ECB' and ivn != 'zero': continue
            pt = b''; prev = iv
            for i in range(0, len(p1), 16):
                d = sm4_dec(p1[i:i+16], rk)
                if mode == 'CBC':
                    pt += bytes(a^b for a,b in zip(d, prev)); prev = p1[i:i+16]
                else:
                    pt += d
            s = score(pt)
            print('SM4-%s %-14s iv=%-7s score=%.2f %r' % (mode, kn, ivn, s, pt[:48]))
            if s > 0.9: hits += 1
print('SM4 printable hits:', hits)
