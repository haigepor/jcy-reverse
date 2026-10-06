// gg_memscan.js — per-range memory forensics (fault-tolerant)
'use strict';

const CM_SRC = `
#include <stdint.h>

static const unsigned char SBOX[256] = {
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
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static const unsigned char RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

#define MAXHITS 512
struct Hit { uint64_t ptr; uint32_t kind; uint32_t len; };
static struct Hit hits[MAXHITS];
static uint32_t hit_count = 0;

static void my_memcpy(unsigned char *d, const unsigned char *s, unsigned n) {
    unsigned i; for (i = 0; i < n; i++) d[i] = s[i];
}
static int my_eq(const unsigned char *a, const unsigned char *b, unsigned n) {
    unsigned i; for (i = 0; i < n; i++) if (a[i] != b[i]) return 0; return 1;
}
static void add_hit(uint64_t p, uint32_t kind, uint32_t len) {
    if (hit_count < MAXHITS) { hits[hit_count].ptr = p; hits[hit_count].kind = kind; hits[hit_count].len = len; }
    hit_count++;
}

static int ks128_ok(const unsigned char *k) {
    unsigned char w[176];
    unsigned r, c, i;
    /* quick reject: check round-1 derivation only (~10 ops) */
    if ((unsigned char)(k[16] ^ SBOX[k[13]] ^ RCON[1]) != k[0]) return 0;
    if ((unsigned char)(k[17] ^ SBOX[k[14]]) != k[1]) return 0;
    if ((unsigned char)(k[18] ^ SBOX[k[15]]) != k[2]) return 0;
    if ((unsigned char)(k[19] ^ SBOX[k[12]]) != k[3]) return 0;
    my_memcpy(w, k, 16);
    for (r = 1; r <= 10; r++) {
        unsigned char t[4];
        t[0] = SBOX[w[16*r-3]]; t[1] = SBOX[w[16*r-2]];
        t[2] = SBOX[w[16*r-1]]; t[3] = SBOX[w[16*r-4]];
        t[0] ^= RCON[r];
        for (c = 0; c < 4; c++) {
            for (i = 0; i < 4; i++) {
                unsigned char x = (c == 0) ? t[i] : w[16*r + 4*(c-1) + i];
                w[16*r + 4*c + i] = w[16*(r-1) + 4*c + i] ^ x;
            }
        }
    }
    return my_eq(w, k, 176);
}

static int ks256_ok(const unsigned char *k) {
    unsigned char w[240];
    unsigned i, r;
    if ((unsigned char)(k[32] ^ SBOX[k[29]] ^ RCON[1]) != k[0]) return 0;
    if ((unsigned char)(k[33] ^ SBOX[k[30]]) != k[1]) return 0;
    if ((unsigned char)(k[34] ^ SBOX[k[31]]) != k[2]) return 0;
    if ((unsigned char)(k[35] ^ SBOX[k[28]]) != k[3]) return 0;
    my_memcpy(w, k, 32);
    for (i = 8; i < 60; i++) {
        unsigned char t[4];
        my_memcpy(t, w + (i-1)*4, 4);
        if (i % 8 == 0) {
            unsigned char a = t[0];
            t[0] = SBOX[t[1]]; t[1] = SBOX[t[2]]; t[2] = SBOX[t[3]]; t[3] = SBOX[a];
            t[0] ^= RCON[i/8];
        } else if (i % 8 == 4) {
            t[0] = SBOX[t[0]]; t[1] = SBOX[t[1]]; t[2] = SBOX[t[2]]; t[3] = SBOX[t[3]];
        }
        for (r = 0; r < 4; r++) w[i*4 + r] = w[(i-8)*4 + r] ^ t[r];
    }
    return my_eq(w, k, 240);
}

void scan_range(const unsigned char *start, unsigned long size) {
    unsigned long i;
    if (size < 240) return;
    for (i = 0; i + 240 <= size; i++) {
        if (ks128_ok(start + i)) add_hit((uint64_t)(start + i), 1, 176);
        if (ks256_ok(start + i)) add_hit((uint64_t)(start + i), 2, 240);
    }
}

uint32_t find_needle(const unsigned char *start, unsigned long size,
                     const unsigned char *needle, uint32_t nlen, uint32_t kind) {
    uint32_t found = 0;
    unsigned long i;
    if (size < nlen) return 0;
    for (i = 0; i + nlen <= size; i++) {
        if (start[i] == needle[0] && my_eq(start + i, needle, nlen)) {
            add_hit((uint64_t)(start + i), kind, nlen);
            found++;
            if (found > 32) break;
        }
    }
    return found;
}

uint32_t get_hit_count(void) { return hit_count; }
void reset_hits(void) { hit_count = 0; }
struct Hit *get_hits(void) { return (struct Hit *)&hits; }
`;

const cm = new CModule(CM_SRC);
const scanRange = new NativeFunction(cm.scan_range, 'void', ['pointer', 'ulong']);
const findNeedle = new NativeFunction(cm.find_needle, 'uint32', ['pointer', 'ulong', 'pointer', 'uint32', 'uint32']);
const getHits = new NativeFunction(cm.get_hits, 'pointer', []);
const getHitCount = new NativeFunction(cm.get_hit_count, 'uint32', []);
const resetHits = new NativeFunction(cm.reset_hits, 'void', []);

let RANGES = [];
let NEEDLE_BUFS = [];
let ACC = [];

function dumpHex(p, n) {
    try {
        const buf = Memory.readByteArray(p, n);
        return Array.from(new Uint8Array(buf)).map(x => x.toString(16).padStart(2, '0')).join('');
    } catch (e) { return null; }
}

rpc.exports = {
    init: function (needleSpecs) {
        RANGES = Process.enumerateRanges('rw-').filter(r => r.size <= 512 * 1024 * 1024);
        NEEDLE_BUFS = [];
        for (const s of needleSpecs) {
            const arr = [];
            for (let i = 0; i < s.length; i++) arr.push(s.charCodeAt(i) & 0xff);
            const buf = Memory.alloc(arr.length);
            buf.writeByteArray(arr);
            NEEDLE_BUFS.push({ buf: buf, len: arr.length });
        }
        ACC = [];
        return RANGES.length;
    },
    nranges: function () { return RANGES.length; },
    scanidx: function (i) {
        if (i < 0 || i >= RANGES.length) return { err: 'oor' };
        const r = RANGES[i];
        resetHits();
        const CH = 262144;
        const scratch = Memory.alloc(CH);
        for (let off = 0; off < r.size; off += CH) {
            const n = Math.min(CH, r.size - off);
            let buf = null;
            try { buf = r.base.add(off).readByteArray(n); } catch (e) { continue; }
            if (!buf) continue;
            scratch.writeByteArray(buf);
            try { scanRange(scratch, n); } catch (e) {}
            for (let ni = 0; ni < NEEDLE_BUFS.length; ni++) {
                const nb = NEEDLE_BUFS[ni];
                try { findNeedle(scratch, n, nb.buf, nb.len, 100 + ni); } catch (e) {}
            }
        }
        const n = getHitCount();
        const hp = getHits();
        const found = [];
        for (let j = 0; j < n && j < 512; j++) {
            const p = hp.add(j * 24).readPointer();
            const kind = hp.add(j * 24 + 8).readU32();
            const len = hp.add(j * 24 + 12).readU32();
            found.push({ ptr: p.toString(), kind: kind, len: len });
        }
        ACC.push(...found);
        return { idx: i, base: r.base.toString(), size: r.size, found: found };
    },
    dump: function (addr, len) {
        return dumpHex(ptr(addr), len);
    },
    results: function () { return ACC; }
};

console.log('[*] gg_memscan v2 ready');
