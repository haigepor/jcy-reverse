import sys, os
import struct
sys.path.insert(0, 'research/captures/rsa_scan')
lib = open('research/artifacts/device_libs/libcore.so','rb').read()
SBOX = lib[0x20b630:0x20b630+256]
assert len(SBOX) == 256

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [[(4*i+j)*7 % 256 for j in range(4)] for i in range(32)]
def rotl(x, n): return ((x << n) | (x >> (32-n))) & 0xffffffff
def tau(a):
    return (SBOX[(a>>24)&0xff]<<24) | (SBOX[(a>>16)&0xff]<<16) | (SBOX[(a>>8)&0xff]<<8) | SBOX[a&0xff]
def T(x):
    b = tau(x)
    return b ^ rotl(b,2) ^ rotl(b,10) ^ rotl(b,18) ^ rotl(b,24)
def T2(x):
    b = tau(x)
    return b ^ rotl(b,13) ^ rotl(b,23)
def sm4_key_expand(key):
    mk = list(struct.unpack(">4I", key))
    k = [mk[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        nk = k[0] ^ T2(k[1]^k[2]^k[3]^struct.unpack('>I', bytes(CK[i]))[0])
        rk.append(nk)
        k = k[1:] + [nk]
    return rk
def sm4_crypt_block(blk, rk):
    x = list(struct.unpack('>4I', blk))
    for i in range(32):
        nx = x[0] ^ T(x[1]^x[2]^x[3]^rk[i])
        x = x[1:] + [nx]
    y = x[::-1]
    return struct.pack('>4I', *y)

# 标准向量自检
key = bytes.fromhex('0123456789abcdeffedcba9876543210')
pt  = bytes.fromhex('0123456789abcdeffedcba9876543210')
rk = sm4_key_expand(key)
ct = sm4_crypt_block(pt, rk)
print('SM4 std vector:', ct.hex(), 'expect 681edf34d206965e86b3e94f536e4246', 'MATCH' if ct==bytes.fromhex('681edf34d206965e86b3e94f536e4246') else 'FAIL')

# e_oracle 对比: key/iv 自选 16B
from e_oracle import EOracle
o = EOracle()
K = b'0123456789abcdef'
IV = b'fedcba9876543210'
PT = b'A'*16
ct_o = o.enc(PT, K, IV)
print('oracle ct:', ct_o.hex() if isinstance(ct_o, bytes) else repr(ct_o))
rk2 = sm4_key_expand(K)
x = bytes(a^b for a,b in zip(PT, IV))
print('SM4-CBC blk0:', sm4_crypt_block(x, rk2).hex())
