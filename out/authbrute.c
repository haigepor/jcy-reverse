// authbrute.c — offline AES key scanner for authentication header (112B = 15B const prefix + 1B gen + 96B ct)
// Oracle: two auth samples with different ts share most plaintext (only ts digits differ).
//   CBC: P_i = D(K, C_i) ^ C_{i-1}  (i>=1)  — IV-free
//   ECB: P_i = D(K, C_i)             (i>=0)
//   Correct key => many full-block equalities between two samples' P_i.
//   Wrong key   => block equality prob 2^-128 each.
// Usage: authbrute.exe <file.so> <samples.txt>
//   samples.txt: lines of 224-hex (112B) auth blobs (raw b64-decoded)
// Build: gcc -O3 -march=native -o authbrute.exe authbrute.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static uint8_t SBOX[256], ISBOX[256];
static uint8_t M9[256], M11[256], M13[256], M14[256];

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void init_tables(void) {
    for (int i = 0; i < 256; i++) {
        uint8_t inv = 0;
        if (i != 0) {
            uint8_t result = 1, base = (uint8_t)i;
            int e = 254;
            while (e) {
                if (e & 1) result = gmul(result, base);
                base = gmul(base, base);
                e >>= 1;
            }
            inv = result;
        }
        uint8_t x = inv;
        uint8_t b = (uint8_t)(x ^ ((x << 1) | (x >> 7)) ^ ((x << 2) | (x >> 6)) ^
                              ((x << 3) | (x >> 5)) ^ ((x << 4) | (x >> 4)) ^ 0x63);
        SBOX[i] = b;
    }
    for (int i = 0; i < 256; i++) ISBOX[SBOX[i]] = (uint8_t)i;
    for (int i = 0; i < 256; i++) {
        M9[i]  = gmul((uint8_t)i, 9);
        M11[i] = gmul((uint8_t)i, 11);
        M13[i] = gmul((uint8_t)i, 13);
        M14[i] = gmul((uint8_t)i, 14);
    }
}

static const uint8_t RCON[15] = {0,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d};

static void expand_key128(const uint8_t *key, uint8_t *rk) {  // 176 bytes
    memcpy(rk, key, 16);
    for (int i = 1; i <= 10; i++) {
        uint8_t *w = rk + 16 * i;
        const uint8_t *prev = w - 16;
        uint8_t t[4];
        t[0] = rk[16*i - 4 + 1];
        t[1] = rk[16*i - 4 + 2];
        t[2] = rk[16*i - 4 + 3];
        t[3] = rk[16*i - 4];
        for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];
        t[0] ^= RCON[i];
        for (int j = 0; j < 4; j++)  w[j] = prev[j] ^ t[j];
        for (int j = 4; j < 16; j++) w[j] = w[j-4] ^ prev[j];
    }
}

static void expand_key256(const uint8_t *key, uint8_t *rk) {  // 240 bytes
    memcpy(rk, key, 32);
    for (int i = 8; i < 60; i++) {
        uint8_t t[4];
        t[0] = rk[4*(i-1)+0]; t[1] = rk[4*(i-1)+1];
        t[2] = rk[4*(i-1)+2]; t[3] = rk[4*(i-1)+3];
        if (i % 8 == 0) {
            uint8_t u = t[0];
            t[0] = SBOX[t[1]] ^ RCON[i/8];
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[u];
        } else if (i % 8 == 4) {
            t[0] = SBOX[t[0]]; t[1] = SBOX[t[1]];
            t[2] = SBOX[t[2]]; t[3] = SBOX[t[3]];
        }
        rk[4*i+0] = rk[4*(i-8)+0] ^ t[0];
        rk[4*i+1] = rk[4*(i-8)+1] ^ t[1];
        rk[4*i+2] = rk[4*(i-8)+2] ^ t[2];
        rk[4*i+3] = rk[4*(i-8)+3] ^ t[3];
    }
}

static void aes_dec_block(const uint8_t *rk, int rounds, const uint8_t *in, uint8_t *out) {
    uint8_t st[16];
    memcpy(st, in, 16);
    for (int i = 0; i < 16; i++) st[i] ^= rk[rounds * 16 + i];
    for (int round = rounds - 1; round >= 1; round--) {
        uint8_t t, u;
        t = st[1];  st[1] = st[13]; st[13] = st[9]; st[9] = st[5]; st[5] = t;
        t = st[2];  u = st[6];  st[2] = st[10]; st[6] = st[14]; st[10] = t; st[14] = u;
        t = st[3];  st[3] = st[7]; st[7] = st[11]; st[11] = st[15]; st[15] = t;
        for (int i = 0; i < 16; i++) st[i] = ISBOX[st[i]];
        for (int i = 0; i < 16; i++) st[i] ^= rk[round * 16 + i];
        for (int c = 0; c < 4; c++) {
            uint8_t a0 = st[4*c], a1 = st[4*c+1], a2 = st[4*c+2], a3 = st[4*c+3];
            st[4*c]   = (uint8_t)(M14[a0] ^ M11[a1] ^ M13[a2] ^ M9 [a3]);
            st[4*c+1] = (uint8_t)(M9 [a0] ^ M14[a1] ^ M11[a2] ^ M13[a3]);
            st[4*c+2] = (uint8_t)(M13[a0] ^ M9 [a1] ^ M14[a2] ^ M11[a3]);
            st[4*c+3] = (uint8_t)(M11[a0] ^ M13[a1] ^ M9 [a2] ^ M14[a3]);
        }
    }
    uint8_t t, u;
    t = st[1];  st[1] = st[13]; st[13] = st[9]; st[9] = st[5]; st[5] = t;
    t = st[2];  u = st[6];  st[2] = st[10]; st[6] = st[14]; st[10] = t; st[14] = u;
    t = st[3];  st[3] = st[7]; st[7] = st[11]; st[11] = st[15]; st[15] = t;
    for (int i = 0; i < 16; i++) st[i] = ISBOX[st[i]];
    for (int i = 0; i < 16; i++) st[i] ^= rk[i];
    memcpy(out, st, 16);
}

static void selftest(void) {
    uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t ct[16]  = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t rk[240], out[16];
    expand_key128(key, rk);
    aes_dec_block(rk, 10, ct, out);
    if (memcmp(out, pt, 16) != 0) { fprintf(stderr, "SELFTEST128 FAILED\n"); exit(1); }
    printf("selftest OK\n");
}

#define MAXSAMPLES 8
#define NBLOCKS 7   // 112 bytes

static uint8_t samples[MAXSAMPLES][112];
static int nsamples = 0;

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <file> <samples.txt>\n", argv[0]); return 1; }
    init_tables();
    selftest();

    // load samples
    FILE *sf = fopen(argv[2], "r");
    if (!sf) { perror("samples"); return 1; }
    char line[512];
    while (fgets(line, sizeof line, sf) && nsamples < MAXSAMPLES) {
        size_t n = strlen(line);
        while (n && (line[n-1]=='\n' || line[n-1]=='\r' || line[n-1]==' ')) line[--n] = 0;
        if (n < 224) continue;
        int ok = 1;
        for (int i = 0; i < 112; i++) {
            int h = hexval(line[2*i]), l = hexval(line[2*i+1]);
            if (h < 0 || l < 0) { ok = 0; break; }
            samples[nsamples][i] = (uint8_t)(h * 16 + l);
        }
        if (ok) nsamples++;
    }
    fclose(sf);
    printf("samples loaded: %d\n", nsamples);
    if (nsamples < 2) { fprintf(stderr, "need >= 2 samples\n"); return 1; }

    // load target file
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz);
    if (fread(buf, 1, sz, f) != (size_t)sz) { perror("read"); return 1; }
    fclose(f);
    printf("file: %s (%ld bytes)\n", argv[1], sz);

    // precompute CBC XOR-operand blocks for each sample: for oracle P_i = D(C_i) ^ C_{i-1}
    // blocks: C_0..C_6 (112B). CBC-checkable: i=1..6. ECB-checkable: i=0..6.

    uint8_t rk[240];
    uint8_t d0[NBLOCKS][16], d1[NBLOCKS][16];
    long found = 0;
    clock_t t0 = clock();

    for (long off = 0; off + 32 <= sz; off++) {
        // ---- AES-128 ----
        expand_key128(buf + off, rk);
        for (int i = 0; i < NBLOCKS; i++)
            aes_dec_block(rk, 10, samples[0] + 16*i, d0[i]);
        for (int i = 0; i < NBLOCKS; i++)
            aes_dec_block(rk, 10, samples[1] + 16*i, d1[i]);
        // CBC score: P_i = d_[i] ^ C_{i-1}
        int cbc = 0, ecb = 0;
        for (int i = 1; i < NBLOCKS; i++) {
            uint8_t p0[16], p1[16];
            for (int j = 0; j < 16; j++) {
                p0[j] = d0[i][j] ^ samples[0][16*(i-1)+j];
                p1[j] = d1[i][j] ^ samples[1][16*(i-1)+j];
            }
            if (memcmp(p0, p1, 16) == 0) cbc++;
        }
        for (int i = 0; i < NBLOCKS; i++)
            if (memcmp(d0[i], d1[i], 16) == 0) ecb++;
        if (cbc >= 1 || ecb >= 1) {
            printf("[AES128] off=0x%lx cbc_eq=%d ecb_eq=%d key=", off, cbc, ecb);
            for (int j = 0; j < 16; j++) printf("%02x", buf[off+j]);
            printf("\n"); fflush(stdout);
            found++;
        }
        // ---- AES-256 ----
        expand_key256(buf + off, rk);
        for (int i = 0; i < NBLOCKS; i++)
            aes_dec_block(rk, 14, samples[0] + 16*i, d0[i]);
        for (int i = 0; i < NBLOCKS; i++)
            aes_dec_block(rk, 14, samples[1] + 16*i, d1[i]);
        cbc = 0; ecb = 0;
        for (int i = 1; i < NBLOCKS; i++) {
            uint8_t p0[16], p1[16];
            for (int j = 0; j < 16; j++) {
                p0[j] = d0[i][j] ^ samples[0][16*(i-1)+j];
                p1[j] = d1[i][j] ^ samples[1][16*(i-1)+j];
            }
            if (memcmp(p0, p1, 16) == 0) cbc++;
        }
        for (int i = 0; i < NBLOCKS; i++)
            if (memcmp(d0[i], d1[i], 16) == 0) ecb++;
        if (cbc >= 1 || ecb >= 1) {
            printf("[AES256] off=0x%lx cbc_eq=%d ecb_eq=%d key=", off, cbc, ecb);
            for (int j = 0; j < 32; j++) printf("%02x", buf[off+j]);
            printf("\n"); fflush(stdout);
            found++;
        }
    }
    double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;
    printf("done: %ld hits in %.1fs\n", found, secs);
    return 0;
}
