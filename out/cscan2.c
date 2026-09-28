// cscan2.c — binary window key scanner: AES-128, AES-256, SM4
// Engine: C (MinGW g++ -O3) | Language: C11
// Build: g++ -O3 -march=native -o cscan2.exe cscan2.c
// Run:   cscan2.exe <dumpfile> <ct_hex_file> [more ct_hex_files...]
//
// Cipher   | Block | Key   | Rounds
// AES-128  |  16B  |  16B  | 10
// AES-256  |  16B  |  32B  | 14
// SM4      |  16B  |  16B  | 32 (rk reversed for decrypt)
//
// Oracles (no IV needed):
//   CBC:  P_i = D(K, C_i) ^ C_{i-1}, i >= 1      ECB: P_i = D(K, C_i)
//   AUTH samples (112B): all decrypted blocks printable ASCII
//   P1/BODY samples:     all middle blocks printable + last block valid PKCS7
// SM4 self-test: GB/T 32907-2016 Appendix A vector.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint8_t SBOX[256], ISBOX[256];
static uint8_t M9[256], M11[256], M13[256], M14[256];
static const uint8_t SM4_SBOX[256] = {
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};
static const uint32_t SM4_FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};
static uint32_t SM4_CK[32];

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
    for (int i = 0; i < 32; i++) {
        uint32_t ck = 0;
        for (int j = 0; j < 4; j++) ck |= (uint32_t)((4*i + j) * 7 % 256) << (24 - 8*j);
        SM4_CK[i] = ck;
    }
}

static const uint8_t RCON[15] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d};

// AES key expansion: nr = 10 (16B key, rk 176B) or 14 (32B key, rk 240B)
static void aes_expand_key(const uint8_t *key, int nr, uint8_t *rk) {
    int nk = (nr == 10) ? 4 : 8;
    int nb4 = 4 * (nr + 1);   // total words
    memcpy(rk, key, nk * 4);
    for (int w = nk; w < nb4; w++) {
        uint8_t t[4];
        memcpy(t, rk + 4*(w-1), 4);
        if (w % nk == 0) {
            uint8_t tmp = t[0];
            t[0] = SBOX[t[1]] ^ RCON[w/nk];
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
        } else if (nk > 6 && w % nk == 4) {
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];
        }
        for (int j = 0; j < 4; j++) rk[4*w + j] = rk[4*(w-nk) + j] ^ t[j];
    }
}

static void aes_dec_block(const uint8_t *rk, int nr, const uint8_t *in, uint8_t *out) {
    uint8_t st[16];
    memcpy(st, in, 16);
    for (int i = 0; i < 16; i++) st[i] ^= rk[nr*16 + i];
    for (int round = nr - 1; round >= 1; round--) {
        uint8_t t, u;
        t = st[1];  st[1]  = st[13]; st[13] = st[9];  st[9]  = st[5];  st[5]  = t;
        t = st[2];  u = st[6];  st[2] = st[10]; st[6] = st[14]; st[10] = t;  st[14] = u;
        t = st[3];  st[3]  = st[7];  st[7]  = st[11]; st[11] = st[15]; st[15] = t;
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
    t = st[1];  st[1]  = st[13]; st[13] = st[9];  st[9]  = st[5];  st[5]  = t;
    t = st[2];  u = st[6];  st[2] = st[10]; st[6] = st[14]; st[10] = t;  st[14] = u;
    t = st[3];  st[3]  = st[7];  st[7]  = st[11]; st[11] = st[15]; st[15] = t;
    for (int i = 0; i < 16; i++) st[i] = ISBOX[st[i]];
    for (int i = 0; i < 16; i++) st[i] ^= rk[i];
    memcpy(out, st, 16);
}

// ---- SM4 ----
static uint32_t sm4_tau(uint32_t x) {
    return ((uint32_t)SM4_SBOX[(x >> 24) & 0xff] << 24) |
           ((uint32_t)SM4_SBOX[(x >> 16) & 0xff] << 16) |
           ((uint32_t)SM4_SBOX[(x >>  8) & 0xff] <<  8) |
           ((uint32_t)SM4_SBOX[ x        & 0xff]);
}
static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sm4_expand_key(const uint8_t *key, uint32_t *rk) {
    uint32_t MK[4], K[36];
    for (int i = 0; i < 4; i++)
        MK[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
                ((uint32_t)key[4*i+2] << 8) | key[4*i+3];
    for (int i = 0; i < 4; i++) K[i] = MK[i] ^ SM4_FK[i];
    for (int i = 0; i < 32; i++) {
        uint32_t x = K[i+1] ^ K[i+2] ^ K[i+3] ^ SM4_CK[i];
        uint32_t t = sm4_tau(x);
        t = t ^ rotl32(t, 13) ^ rotl32(t, 23);
        K[i+4] = K[i] ^ t;
        rk[i] = K[i+4];
    }
}

static void sm4_dec_block(const uint32_t *rk, const uint8_t *in, uint8_t *out) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++)
        X[i] = ((uint32_t)in[4*i] << 24) | ((uint32_t)in[4*i+1] << 16) |
               ((uint32_t)in[4*i+2] << 8) | in[4*i+3];
    for (int i = 0; i < 32; i++) {
        uint32_t x = X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[31 - i];   // reversed for decrypt
        uint32_t t = sm4_tau(x);
        t = t ^ rotl32(t, 2) ^ rotl32(t, 10) ^ rotl32(t, 18) ^ rotl32(t, 24);
        X[i+4] = X[i] ^ t;
    }
    for (int i = 0; i < 4; i++) {
        uint32_t w = X[35 - i];
        out[4*i]   = (uint8_t)(w >> 24);
        out[4*i+1] = (uint8_t)(w >> 16);
        out[4*i+2] = (uint8_t)(w >> 8);
        out[4*i+3] = (uint8_t)w;
    }
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static void selftest(void) {
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t ct[16]  = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t rk[240], out[16];
    aes_expand_key(key, 10, rk);
    aes_dec_block(rk, 10, ct, out);
    if (memcmp(out, pt, 16)) { fprintf(stderr, "AES128 SELFTEST FAILED\n"); exit(1); }

    uint8_t k256[32];
    for (int i = 0; i < 32; i++) k256[i] = (uint8_t)i;
    uint8_t ct256[16] = {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
    uint8_t pt256[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    aes_expand_key(k256, 14, rk);
    aes_dec_block(rk, 14, ct256, out);
    if (memcmp(out, pt256, 16)) { fprintf(stderr, "AES256 SELFTEST FAILED\n"); exit(1); }

    // SM4 GB/T 32907-2016 Appendix A
    const char *mk_hex = "0123456789abcdeffedcba9876543210";
    const char *sm4_pt_hex = "0123456789abcdeffedcba9876543210";
    const char *sm4_ct_hex = "681edf34d206965e86b3e94f536e4246";
    uint8_t mk[16], spt[16], sct[16];
    for (int i = 0; i < 16; i++) {
        mk[i]  = (uint8_t)((hexv(mk_hex[2*i]) << 4) | hexv(mk_hex[2*i+1]));
        spt[i] = (uint8_t)((hexv(sm4_pt_hex[2*i]) << 4) | hexv(sm4_pt_hex[2*i+1]));
        sct[i] = (uint8_t)((hexv(sm4_ct_hex[2*i]) << 4) | hexv(sm4_ct_hex[2*i+1]));
    }
    uint32_t srk[32];
    sm4_expand_key(mk, srk);
    sm4_dec_block(srk, sct, out);
    if (memcmp(out, spt, 16)) { fprintf(stderr, "SM4 SELFTEST FAILED\n"); exit(1); }

    printf("selftest OK (AES-128 FIPS-197 B, AES-256, SM4 GB/T 32907)\n");
}
// ---------- sample loading ----------
typedef struct {
    char name[64];
    uint8_t *ct;
    int len, blocks, is_auth;
} CT;
static CT cts[64];
static int ncts = 0;

static void load_ct(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *hex = (char*)malloc(sz + 1);
    fread(hex, 1, sz, f);
    hex[sz] = 0;
    fclose(f);
    long hl = 0;
    for (long i = 0; i < sz; i++)
        if (hexv(hex[i]) >= 0) hex[hl++] = hex[i];
    int blen = (int)(hl / 2);
    if (blen < 32 || blen % 16 != 0) { fprintf(stderr, "skip %s (len %d)\n", path, blen); return; }
    CT *ct = &cts[ncts];
    ct->ct = (uint8_t*)malloc(blen);
    for (int i = 0; i < blen; i++)
        ct->ct[i] = (uint8_t)((hexv(hex[2*i]) << 4) | hexv(hex[2*i+1]));
    ct->len = blen; ct->blocks = blen / 16;
    const char *base = strrchr(path, '\\');
    if (!base) base = strrchr(path, '/');
    base = base ? base + 1 : path;
    snprintf(ct->name, 63, "%s", base); ct->name[63] = 0;
    ct->is_auth = (strstr(ct->name, "AUTH") != NULL);
    ncts++;
    free(hex);
}

static int pkcs7_ok(const uint8_t *p) {
    uint8_t n = p[15];
    if (n < 1 || n > 16) return 0;
    for (int i = 15; i >= 16 - n; i--) if (p[i] != n) return 0;
    return 1;
}
static int printable16(const uint8_t *p) {
    for (int i = 0; i < 16; i++) {
        uint8_t c = p[i];
        if (!((c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\n' || c == '\r')) return 0;
    }
    return 1;
}

static long long total_hits = 0;
static void report_hit(const char *src, unsigned long long off, const uint8_t *key, int klen,
                       CT *ct, const char *cipher, const char *mode, const uint8_t *preview) {
    char khs[65];
    for (int i = 0; i < klen; i++) sprintf(khs + 2*i, "%02x", key[i]);
    printf("HIT src=%s off=%llu key=%s cipher=%s sample=%s mode=%s plain=",
           src, off, khs, cipher, ct->name, mode);
    for (int i = 0; i < 16; i++)
        putchar((preview[i] >= 0x20 && preview[i] <= 0x7e) ? preview[i] : '.');
    printf("\n");
    fflush(stdout);
    total_hits++;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <dump> <ct.hex>...\n", argv[0]); return 1; }
    init_tables();
    selftest();
    for (int i = 2; i < argc; i++) load_ct(argv[i]);
    printf("loaded %d ciphertext samples\n", ncts);

    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open dump %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    long long dlen = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *dump = (uint8_t*)malloc(dlen);
    if (fread(dump, 1, dlen, f) != (size_t)dlen) { fprintf(stderr, "read fail\n"); return 1; }
    fclose(f);
    printf("dump %s: %lld bytes, %lld windows\n", argv[1], dlen, dlen - 15);

    uint8_t rk240[240], p16[16], pb[16];
    uint32_t srk[32];

    for (long long off = 0; off + 32 <= dlen; off++) {   // +32 covers AES-256 key window
        // ---- AES-128 (window at off, 16B) ----
        if (off + 16 <= dlen) {
            aes_expand_key(dump + off, 10, rk240);
            for (int c = 0; c < ncts; c++) {
                CT *ct = &cts[c];
                if (ct->is_auth) {
                    int ok = 1;
                    for (int b = 1; b < ct->blocks && ok; b++) {
                        aes_dec_block(rk240, 10, ct->ct + b*16, p16);
                        for (int i = 0; i < 16; i++) p16[i] ^= ct->ct[(b-1)*16 + i];
                        if (!printable16(p16)) ok = 0;
                    }
                    if (ok) report_hit(argv[1], off, dump + off, 16, ct, "AES128", "cbc-auth", p16);
                    ok = 1;
                    for (int b = 0; b < ct->blocks && ok; b++) {
                        aes_dec_block(rk240, 10, ct->ct + b*16, p16);
                        if (!printable16(p16)) ok = 0;
                    }
                    if (ok) report_hit(argv[1], off, dump + off, 16, ct, "AES128", "ecb-auth", p16);
                } else {
                    int ok = 1;
                    for (int b = 1; b < ct->blocks - 1 && ok; b++) {
                        aes_dec_block(rk240, 10, ct->ct + b*16, pb);
                        for (int i = 0; i < 16; i++) pb[i] ^= ct->ct[(b-1)*16 + i];
                        if (!printable16(pb)) ok = 0;
                    }
                    if (ok) {
                        aes_dec_block(rk240, 10, ct->ct + (ct->blocks-1)*16, p16);
                        for (int i = 0; i < 16; i++) p16[i] ^= ct->ct[(ct->blocks-2)*16 + i];
                        if (pkcs7_ok(p16)) report_hit(argv[1], off, dump + off, 16, ct, "AES128", "cbc-full", p16);
                    }
                    ok = 1;
                    for (int b = 0; b < ct->blocks - 1 && ok; b++) {
                        aes_dec_block(rk240, 10, ct->ct + b*16, pb);
                        if (!printable16(pb)) ok = 0;
                    }
                    if (ok) {
                        aes_dec_block(rk240, 10, ct->ct + (ct->blocks-1)*16, p16);
                        if (pkcs7_ok(p16)) report_hit(argv[1], off, dump + off, 16, ct, "AES128", "ecb-full", p16);
                    }
                }
            }
        }
        // ---- AES-256 (window at off, 32B) ----
        aes_expand_key(dump + off, 14, rk240);
        for (int c = 0; c < ncts; c++) {
            CT *ct = &cts[c];
            if (ct->is_auth) {
                int ok = 1;
                for (int b = 1; b < ct->blocks && ok; b++) {
                    aes_dec_block(rk240, 14, ct->ct + b*16, p16);
                    for (int i = 0; i < 16; i++) p16[i] ^= ct->ct[(b-1)*16 + i];
                    if (!printable16(p16)) ok = 0;
                }
                if (ok) report_hit(argv[1], off, dump + off, 32, ct, "AES256", "cbc-auth", p16);
                ok = 1;
                for (int b = 0; b < ct->blocks && ok; b++) {
                    aes_dec_block(rk240, 14, ct->ct + b*16, p16);
                    if (!printable16(p16)) ok = 0;
                }
                if (ok) report_hit(argv[1], off, dump + off, 32, ct, "AES256", "ecb-auth", p16);
            } else {
                int ok = 1;
                for (int b = 1; b < ct->blocks - 1 && ok; b++) {
                    aes_dec_block(rk240, 14, ct->ct + b*16, pb);
                    for (int i = 0; i < 16; i++) pb[i] ^= ct->ct[(b-1)*16 + i];
                    if (!printable16(pb)) ok = 0;
                }
                if (ok) {
                    aes_dec_block(rk240, 14, ct->ct + (ct->blocks-1)*16, p16);
                    for (int i = 0; i < 16; i++) p16[i] ^= ct->ct[(ct->blocks-2)*16 + i];
                    if (pkcs7_ok(p16)) report_hit(argv[1], off, dump + off, 32, ct, "AES256", "cbc-full", p16);
                }
                ok = 1;
                for (int b = 0; b < ct->blocks - 1 && ok; b++) {
                    aes_dec_block(rk240, 14, ct->ct + b*16, pb);
                    if (!printable16(pb)) ok = 0;
                }
                if (ok) {
                    aes_dec_block(rk240, 14, ct->ct + (ct->blocks-1)*16, p16);
                    if (pkcs7_ok(p16)) report_hit(argv[1], off, dump + off, 32, ct, "AES256", "ecb-full", p16);
                }
            }
        }
        // ---- SM4 (window at off, 16B) ----
        sm4_expand_key(dump + off, srk);
        for (int c = 0; c < ncts; c++) {
            CT *ct = &cts[c];
            if (ct->is_auth) {
                int ok = 1;
                for (int b = 1; b < ct->blocks && ok; b++) {
                    sm4_dec_block(srk, ct->ct + b*16, p16);
                    for (int i = 0; i < 16; i++) p16[i] ^= ct->ct[(b-1)*16 + i];
                    if (!printable16(p16)) ok = 0;
                }
                if (ok) report_hit(argv[1], off, dump + off, 16, ct, "SM4", "cbc-auth", p16);
                ok = 1;
                for (int b = 0; b < ct->blocks && ok; b++) {
                    sm4_dec_block(srk, ct->ct + b*16, p16);
                    if (!printable16(p16)) ok = 0;
                }
                if (ok) report_hit(argv[1], off, dump + off, 16, ct, "SM4", "ecb-auth", p16);
            } else {
                int ok = 1;
                for (int b = 1; b < ct->blocks - 1 && ok; b++) {
                    sm4_dec_block(srk, ct->ct + b*16, pb);
                    for (int i = 0; i < 16; i++) pb[i] ^= ct->ct[(b-1)*16 + i];
                    if (!printable16(pb)) ok = 0;
                }
                if (ok) {
                    sm4_dec_block(srk, ct->ct + (ct->blocks-1)*16, p16);
                    for (int i = 0; i < 16; i++) p16[i] ^= ct->ct[(ct->blocks-2)*16 + i];
                    if (pkcs7_ok(p16)) report_hit(argv[1], off, dump + off, 16, ct, "SM4", "cbc-full", p16);
                }
                ok = 1;
                for (int b = 0; b < ct->blocks - 1 && ok; b++) {
                    sm4_dec_block(srk, ct->ct + b*16, pb);
                    if (!printable16(pb)) ok = 0;
                }
                if (ok) {
                    sm4_dec_block(srk, ct->ct + (ct->blocks-1)*16, p16);
                    if (pkcs7_ok(p16)) report_hit(argv[1], off, dump + off, 16, ct, "SM4", "ecb-full", p16);
                }
            }
        }
        if ((off & 0xFFFFFF) == 0)
            fprintf(stderr, "progress %lld / %lld  hits=%lld\n", off, dlen, total_hits);
    }
    printf("DONE, total hits = %lld\n", total_hits);
    return 0;
}
