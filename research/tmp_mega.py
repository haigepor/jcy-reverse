import sys, base64, hashlib
sys.path.insert(0, 'src')
from jcy_protocol.auth import custom_b64d as cb64d
from Crypto.Cipher import AES
import struct

rb = open('research/tmp_forge_resp2.txt').read().strip()
p1 = cb64d(rb.split('.',1)[1])
k16req = bytes.fromhex('4cf2596ab020d8d70edfaf1183417571')
k16resp = b'HWE2HYC3QRJNEVKS'
print('P1(%d): %s' % (len(p1), p1.hex()))

def score(b):
    try: t = b.decode('utf-8')
    except: return -1
    return sum(1 for ch in t if 32 <= ord(ch) < 127 or ch in '\n\r\t') / len(b)

def keyforms(k, label):
    forms = {label: k, label+'_hex': k.hex().encode(), label+'_HEX': k.hex().upper().encode(),
             'md5('+label+')': hashlib.md5(k).digest(), 'md5hex('+label+')': hashlib.md5(k).hexdigest().encode(),
             'sha256('+label+')': hashlib.sha256(k).digest(),
             'b64('+label+')': base64.b64encode(k), 'b64raw('+label+')': base64.b64encode(k).rstrip(b'=')}
    return forms

keys = {}
keys.update(keyforms(k16req, 'req'))
keys.update(keyforms(k16resp, 'resp'))
ivs = {'zero': b'\0'*16, 'req': k16req, 'reqrev': k16req[::-1], 'resp': k16resp, 'resprev': k16resp[::-1]}

hits = 0
for kn, k in keys.items():
    if len(k) not in (16, 24, 32): continue
    for mode in ('CBC','ECB','CFB','OFB','CTR'):
        for ivn, iv in ivs.items():
            if mode == 'ECB' and ivn != 'zero': continue
            try:
                if mode == 'CTR':
                    c = AES.new(k, AES.MODE_CTR, nonce=b'', initial_value=iv)
                elif mode == 'ECB':
                    c = AES.new(k, AES.MODE_ECB)
                else:
                    c = AES.new(k, getattr(AES,'MODE_'+mode), nonce=b'', iv=iv)
                pt = c.decrypt(p1)
            except Exception: continue
            s = score(pt)
            if s > 0.9:
                print('*** AES HIT %s %s iv=%s score=%.2f: %r' % (kn, mode, ivn, s, pt[:80]))
                hits += 1
print('AES hits:', hits)

# SM4
SBOX = open('research/artifacts/device_libs/libcore.so','rb').read()[0x20b630:0x20b630+256]
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [struct.pack('>4I', *[(4*i+j)*7 % 256 for j in range(4)]) for i in range(32)]
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
def sm4_dec_block(blk, rk):
    x = list(struct.unpack('>4I', blk))
    for i in range(32):
        nx = x[0] ^ T(x[1]^x[2]^x[3]^rk[31-i]); x = x[1:]+[nx]
    y = x[::-1]
    return struct.pack('>4I', *y)
hits2 = 0
for kn, k in keys.items():
    if len(k) != 16: continue
    rk = sm4_ks(k)
    for ivn, iv in ivs.items():
        prev = iv; pt = b''
        for i in range(0, len(p1), 16):
            pt += bytes(a^b for a,b in zip(sm4_dec_block(p1[i:i+16], rk), prev)); prev = p1[i:i+16]
        s = score(pt)
        if s > 0.9:
            print('*** SM4-CBC HIT %s iv=%s: %r' % (kn, ivn, pt[:80])); hits2 += 1
print('SM4 hits:', hits2)
