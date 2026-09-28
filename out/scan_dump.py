# out/scan_dump.py — offline scan of memory dump: AES key schedules + needles
import json
import numpy as np

SBOX = bytes(bytearray([
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]))
SB = np.frombuffer(SBOX, dtype=np.uint8)
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def subword(t):
    b = int(t).to_bytes(4, 'big')
    return int.from_bytes(bytes(SBOX[x] for x in b), 'big')
def rotword(t):
    return ((int(t) << 8) & 0xffffffff) | (int(t) >> 24)

def subword_arr(w):
    w = w.astype(np.uint32)
    b0 = (w >> 24).astype(np.uint8); b1 = ((w >> 16) & 0xff).astype(np.uint8)
    b2 = ((w >> 8) & 0xff).astype(np.uint8); b3 = (w & 0xff).astype(np.uint8)
    return (SB[b0].astype(np.uint32) << 24) | (SB[b1].astype(np.uint32) << 16) | (SB[b2].astype(np.uint32) << 8) | SB[b3].astype(np.uint32)

def check128(words):
    for k in range(4, 44):
        t = words[k - 1]
        if (k & 3) == 0:
            t = subword(rotword(t)) ^ (RCON[(k >> 2) - 1] << 24)
        if ((words[k - 4] ^ t) & 0xffffffff) != (words[k] & 0xffffffff):
            return False
    return True
def check256(words):
    for k in range(8, 60):
        t = words[k - 1]
        if (k & 7) == 0:
            t = subword(rotword(t)) ^ (RCON[(k >> 3) - 1] << 24)
        elif (k & 7) == 4:
            t = subword(t)
        if ((words[k - 8] ^ t) & 0xffffffff) != (words[k] & 0xffffffff):
            return False
    return True

def words_from(arr_u32, c, n, smi=False, shift=1):
    if smi:
        return [(int(x) >> shift) & 0xffffffff for x in arr_u32[c:c+n]]
    return [int(x) & 0xffffffff for x in arr_u32[c:c+n]]

def scan(path):
    idx = json.load(open(path + '.idx'))
    data = np.fromfile(path, dtype=np.uint8)
    blob = data.tobytes()
    print('dump: %.1f MB' % (len(blob) / 1048576))
    hits = []

    print('=== needles ===')
    for name, needle in [('appid', b'4150439554430529'), ('authb64', b'6MsfEg71'),
                         ('ts', b'17905'), ('monitor_key', b'qPwClBj7j7ZQraSm')]:
        pos = 0; cnt = 0
        while cnt < 25:
            i = blob.find(needle, pos)
            if i < 0: break
            sec = next((s for s in idx if s['file_off'] <= i < s['file_off'] + s['size']), None)
            ctx = blob[max(0,i-32):i+64]
            printable = all(32 <= c < 127 for c in ctx)
            tag = sec['tag'] if sec else '?'
            if name == 'ts':
                # only show if 13-digit context
                seg = blob[i:i+20]
                m = __import__('re').match(rb'\d{13}', seg)
                if not m: pos = i + 5; continue
                print('NEEDLE %-11s @%s+0x%-8x %r' % (name, tag, i - (sec['file_off'] if sec else 0), blob[max(0,i-24):i+40]))
            else:
                print('NEEDLE %-11s @%s+0x%-8x %r' % (name, tag, i - (sec['file_off'] if sec else 0), blob[max(0,i-16):i+48]))
            cnt += 1
            pos = i + 1
        if cnt == 0: print('NEEDLE %-11s none' % name)

    print('=== key schedules ===')
    for s in idx:
        seg = blob[s['file_off']:s['file_off'] + s['size']]
        if len(seg) < 1024: continue
        for order, dt, keyorder in (('<u4 LE', '<u4', 'little'), ('>u4 BE', '>u4', 'big')):
            w = np.frombuffer(seg, dtype=dt).astype(np.uint64)
            n = len(w)
            if n < 60: continue
            # AES-128 filter
            w0 = w[0:n-44]; w3 = w[3:n-41]; w4 = w[4:n-40]
            rw = ((w3.astype(np.uint32) << 8) & np.uint32(0xffffffff)) | (w3 >> 24)
            sw = subword_arr(rw)
            pred = (w0 ^ sw.astype(np.uint64) ^ np.uint64(0x01000000)) & np.uint64(0xffffffff)
            cand = np.where(pred == (w4 & np.uint64(0xffffffff)))[0]
            for c in cand:
                words = [int(x) & 0xffffffff for x in w[c:c+44]]
                if check128(words):
                    key = b''.join(x.to_bytes(4, keyorder) for x in words[:4])
                    print('HIT KS128 %s @%s+0x%x key=%s ascii=%r' % (order, s['tag'], c*4, key.hex(), key))
                    hits.append(('KS128', order, s['tag'], c*4, key))
            # AES-256 filter
            if n >= 76:
                w7 = w[7:n-53]; w8 = w[8:n-52]; w11 = w[11:n-49]; w12 = w[12:n-48]; w0b = w[0:n-60]; w4b = w[4:n-56]
                rw7 = ((w7.astype(np.uint32) << 8) & np.uint32(0xffffffff)) | (w7 >> 24)
                t1 = subword_arr(rw7).astype(np.uint64) ^ np.uint64(0x01000000)
                m1 = ((w0b ^ t1) & np.uint64(0xffffffff)) == (w8 & np.uint64(0xffffffff))
                sw11 = subword_arr(w11.astype(np.uint32))
                m2 = ((w4b ^ sw11.astype(np.uint64)) & np.uint64(0xffffffff)) == (w12 & np.uint64(0xffffffff))
                cand = np.where(m1 & m2)[0]
                for c in cand:
                    words = [int(x) & 0xffffffff for x in w[c:c+60]]
                    if check256(words):
                        key = b''.join(x.to_bytes(4, keyorder) for x in words[:8])
                        print('HIT KS256 %s @%s+0x%x key=%s' % (order, s['tag'], c*4, key.hex()))
                        hits.append(('KS256', order, s['tag'], c*4, key))
        print('  sec %s done' % s['tag'])
    return hits

if __name__ == '__main__':
    scan('out/mem_dump.bin')
