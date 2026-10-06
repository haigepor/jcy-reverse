import struct
lib = open('research/artifacts/device_libs/libcore.so','rb').read()
BASE = 0x200620
# 提取 P(18) + S(4*256) = 4168 bytes
tbl = lib[BASE:BASE+4*18+4*1024]
P = list(struct.unpack('<18I', tbl[:72]))
S = list(struct.unpack('<1024I', tbl[72:72+4096]))
print('P[0]=%08x P[17]=%08x S0[0]=%08x S3[255]=%08x' % (P[0], P[17], S[0], S[1023]))
# 标准 Blowfish 末尾校验: S3 最后应为 0x3ac372e6 (pi)
assert P[0] == 0x243f6a88 and P[17] == 0x8979fb1b, 'P 表异常'
assert S[1023] == 0x3ac372e6, 'S 末尾异常: %08x' % S[1023]

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
        l, r = bf_enc_words(l, r)
        P[i], P[i+1] = l, r
    for box in range(4):
        for i in range(0, 256, 2):
            l, r = bf_enc_words(l, r)
            S[box*256+i], S[box*256+i+1] = l, r
def bf_enc_words(l, r):
    for i in range(16):
        l ^= P[i]; r ^= f(l)
        l, r = r, l
    l, r = r, l
    r ^= P[16]; l ^= P[17]
    return l, r
def bf_enc_block(blk):
    l, r = struct.unpack('>2I', blk)
    l, r = bf_enc_words(l, r)
    return struct.pack('>2I', l, r)

K = b'0123456789abcdef'
IV = b'fedcba9876543210'
PT = b'A'*16
bf_key(K)
x = bytes(a^b for a,b in zip(PT, IV))
ct0 = bf_enc_block(x)
print('BF-CBC blk0:', ct0.hex())
print('oracle blk0: 686f934a09b35d07e02ebb75e4f10990')
print('MATCH' if ct0.hex()=='686f934a09b35d07e02ebb75e4f10990' else 'MISMATCH')
