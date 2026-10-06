import struct
lib = open('research/artifacts/device_libs/libcore.so','rb').read()
BASE = 0x200620
tbl = lib[BASE:BASE+4*18+4*1024]
P = list(struct.unpack('<18I', tbl[:72]))
S = list(struct.unpack('<1024I', tbl[72:72+4096]))
M = 0xffffffff
def f(x):
    a,b,c,d = (x>>24)&0xff, (x>>16)&0xff, (x>>8)&0xff, x&0xff
    return (((S[a] + S[256+b]) & M) ^ S[512+c]) + S[768+d] & M
def bf_key(key):
    keypos = 0
    for i in range(18):
        v = 0
        for _ in range(4):
            v = ((v<<8) | key[keypos]) & M
            keypos = (keypos+1) % len(key)
        P[i] ^= v
    l = r = 0
    for i in range(0, 18, 2):
        l, r = enc_words(l, r); P[i], P[i+1] = l, r
    for box in range(4):
        for i in range(0, 256, 2):
            l, r = enc_words(l, r); S[box*256+i], S[box*256+i+1] = l, r
def enc_words(l, r):
    for i in range(16):
        l ^= P[i]; r ^= f(l); l, r = r, l
    l, r = r, l
    r ^= P[16]; l ^= P[17]
    return l, r
def enc_block(blk):
    l, r = struct.unpack('>2I', blk)
    return struct.pack('>2I', *enc_words(l, r))
def dec_block(blk):
    l, r = struct.unpack('>2I', blk)
    # 逆: 反向 16 轮
    l ^= P[17]; r ^= P[16]
    l, r = r, l
    for i in range(15, -1, -1):
        l, r = r, l
        r ^= f(l); l ^= P[i]
    return struct.pack('>2I', l, r)

K = b'0123456789abcdef'
IV = b'fedcba9876543210'
PT = b'A'*16
bf_key(K)
# 8 字节 CBC
prev = IV
ct = b''
for i in range(0, 16, 8):
    x = bytes(a^b for a,b in zip(PT[i:i+8], prev))
    c = enc_block(x); ct += c; prev = c
print('BF8-CBC ct16:', ct.hex())
print('oracle ct32 : 686f934a09b35d07e02ebb75e4f10990 7ab8d41fe31b87cb2f67cd6e52c82386')
print('blk01 match:', ct.hex() == '686f934a09b35d07e02ebb75e4f10990')
# 逆函数自检
assert dec_block(ct[:8]) == bytes(a^b for a,b in zip(PT[:8], IV))
print('dec selftest OK')
