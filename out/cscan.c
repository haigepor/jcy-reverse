// cscan.c — binary 16-byte window AES-128 key scanner
// Engine: C (MinGW g++ -O3) | Language: C11
// Build: g++ -O3 -march=native -o cscan.exe cscan.c
// Run:   cscan.exe <dumpfile> <ct_hex_file> [more ct_hex_files...]
//
// Oracle (no IV needed):
//   CBC:  P_i = D(K, C_i) ^ C_{i-1}   for i >= 1  (block 0 skipped, IV unknown)
//   ECB:  P_i = D(K, C_i)
//   padded samples  -> last block must have valid PKCS7 padding
//   AUTH samples    -> decrypted blocks must be printable ASCII
// Self-tests against FIPS-197 Appendix B vectors at startup.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static void expand_key(const uint8_t *key, uint8_t *rk) {  // rk: 176 bytes
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

static void aes128_dec_block(const uint8_t *rk, const uint8_t *in, uint8_t *out) {
    uint8_t st[16];
    memcpy(st, in, 16);
    // AddRoundKey round 10
    for (int i = 0; i < 16; i++) st[i] ^= rk[160 + i];
    for (int round = 9; round >= 1; round--) {
        // InvShiftRows
        uint8_t t, u;
        t = st[1];  st[1]  = st[13]; st[13] = st[9];  st[9]  = st[5];  st[5]  = t;   // row1 rot-right 1
        t = st[2];  u = st[6];  st[2] = st[10]; st[6] = st[14]; st[10] = t;  st[14] = u; // row2 rot-right 2
        t = st[3];  st[3]  = st[7];  st[7]  = st[11]; st[11] = st[15]; st[15] = t;  // row3 rot-right 3
        // InvSubBytes
        for (int i = 0; i < 16; i++) st[i] = ISBOX[st[i]];
        // AddRoundKey
        for (int i = 0; i < 16; i++) st[i] ^= rk[round * 16 + i];
        // InvMixColumns
        for (int c = 0; c < 4; c++) {
            uint8_t a0 = st[4*c], a1 = st[4*c+1], a2 = st[4*c+2], a3 = st[4*c+3];
            st[4*c]   = (uint8_t)(M14[a0] ^ M11[a1] ^ M13[a2] ^ M9 [a3]);
            st[4*c+1] = (uint8_t)(M9 [a0] ^ M14[a1] ^ M11[a2] ^ M13[a3]);
            st[4*c+2] = (uint8_t)(M13[a0] ^ M9 [a1] ^ M14[a2] ^ M11[a3]);
            st[4*c+3] = (uint8_t)(M11[a0] ^ M13[a1] ^ M9 [a2] ^ M14[a3]);
        }
    }
    // final round
    uint8_t t, u;
    t = st[1];  st[1]  = st[13]; st[13] = st[9];  st[9]  = st[5];  st[5]  = t;
    t = st[2];  u = st[6];  st[2] = st[10]; st[6] = st[14]; st[10] = t;  st[14] = u;
    t = st[3];  st[3]  = st[7];  st[7]  = st[11]; st[11] = st[15]; st[15] = t;
    for (int i = 0; i < 16; i++) st[i] = ISBOX[st[i]];
    for (int i = 0; i < 16; i++) st[i] ^= rk[i];
    memcpy(out, st, 16);
}

// ---------- self test ----------
static void selftest(void) {
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t ct[16]  = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t rk[176], out[16];
    expand_key(key, rk);
    aes128_dec_block(rk, ct, out);
    if (memcmp(out, pt, 16) != 0) {
        fprintf(stderr, "SELFTEST FAILED\n");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", out[i]);
        fprintf(stderr, "\n");
        exit(1);
    }
    printf("selftest OK (FIPS-197 B)\n");
}

// ---------- sample loading ----------
typedef struct {
    char name[64];
    uint8_t *ct;
    int len;      // total bytes
    int blocks;   // len/16
    int is_auth;  // 1 = printable oracle, 0 = pkcs7 oracle
} CT;

static CT cts[64];
static int ncts = 0;

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

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
    // strip whitespace
    long hl = 0;
    for (long i = 0; i < sz; i++)
        if (hexval(hex[i]) >= 0) hex[hl++] = hex[i];
    int blen = (int)(hl / 2);
    if (blen < 32 || blen % 16 != 0) { fprintf(stderr, "skip %s (len %d)\n", path, blen); return; }
    CT *ct = &cts[ncts];
    ct->ct = (uint8_t*)malloc(blen);
    for (int i = 0; i < blen; i++)
        ct->ct[i] = (uint8_t)((hexval(hex[2*i]) << 4) | hexval(hex[2*i+1]));
    ct->len = blen;
    ct->blocks = blen / 16;
    // name: basename
    const char *base = strrchr(path, '\\');
    if (!base) base = strrchr(path, '/');
    base = base ? base + 1 : path;
    snprintf(ct->name, 63, "%s", base);
    ct->name[63] = 0;
    ct->is_auth = (strstr(ct->name, "AUTH") != NULL);
    ncts++;
    free(hex);
}

// ---------- oracles ----------
static int pkcs7_ok(const uint8_t *p16) {  // p16 = last decrypted plaintext block
    uint8_t n = p16[15];
    if (n < 1 || n > 16) return 0;
    for (int i = 15; i >= 16 - n; i--)
        if (p16[i] != n) return 0;
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

static void report_hit(const char *src, unsigned long long off, const uint8_t *key,
                       CT *ct, const char *mode, const uint8_t *preview) {
    char khs[33];
    for (int i = 0; i < 16; i++) sprintf(khs + 2*i, "%02x", key[i]);
    printf("HIT src=%s off=%llu key=%s sample=%s mode=%s plain=",
           src, off, khs, ct->name, mode);
    for (int i = 0; i < 16; i++)
        putchar((preview[i] >= 0x20 && preview[i] <= 0x7e) ? preview[i] : '.');
    printf("\n");
    fflush(stdout);
    total_hits++;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <dump> <ct.hex> [ct.hex...]\n", argv[0]);
        return 1;
    }
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

    uint8_t rk[176], p16[16];
    for (long long off = 0; off + 16 <= dlen; off++) {
        const uint8_t *w = dump + off;
        expand_key(w, rk);
        for (int c = 0; c < ncts; c++) {
            CT *ct = &cts[c];
            if (ct->is_auth) {
                // printable oracle, blocks 1..blocks-1 CBC + all ECB; 80+ printable bytes = no false positives
                int ok_all = 1;
                for (int b = 1; b < ct->blocks && ok_all; b++) {
                    aes128_dec_block(rk, ct->ct + b*16, p16);
                    for (int i = 0; i < 16; i++) p16[i] ^= ct->ct[(b-1)*16 + i];
                    if (!printable16(p16)) ok_all = 0;
                }
                if (ok_all) report_hit(argv[1], off, w, ct, "cbc-auth", p16);
                ok_all = 1;
                for (int b = 0; b < ct->blocks && ok_all; b++) {
                    aes128_dec_block(rk, ct->ct + b*16, p16);
                    if (!printable16(p16)) ok_all = 0;
                }
                if (ok_all) report_hit(argv[1], off, w, ct, "ecb-auth", p16);
            } else {
                // STRONG oracle: ALL middle blocks printable + last block valid PKCS7
                // CBC: P_i = D(C_i) ^ C_{i-1};  ECB: P_i = D(C_i)
                uint8_t pb[16];
                int ok;
                // CBC
                ok = 1;
                for (int b = 1; b < ct->blocks - 1 && ok; b++) {
                    aes128_dec_block(rk, ct->ct + b*16, pb);
                    for (int i = 0; i < 16; i++) pb[i] ^= ct->ct[(b-1)*16 + i];
                    if (!printable16(pb)) ok = 0;
                }
                if (ok) {
                    aes128_dec_block(rk, ct->ct + (ct->blocks-1)*16, p16);
                    for (int i = 0; i < 16; i++) p16[i] ^= ct->ct[(ct->blocks-2)*16 + i];
                    if (pkcs7_ok(p16)) report_hit(argv[1], off, w, ct, "cbc-full", p16);
                }
                // ECB
                ok = 1;
                for (int b = 0; b < ct->blocks - 1 && ok; b++) {
                    aes128_dec_block(rk, ct->ct + b*16, pb);
                    if (!printable16(pb)) ok = 0;
                }
                if (ok) {
                    aes128_dec_block(rk, ct->ct + (ct->blocks-1)*16, p16);
                    if (pkcs7_ok(p16)) report_hit(argv[1], off, w, ct, "ecb-full", p16);
                }
            }
        }
        if ((off & 0xFFFFFF) == 0) {
            fprintf(stderr, "progress %lld / %lld  hits=%lld\n", off, dlen, total_hits);
        }
    }
    printf("DONE windows scanned, total hits = %lld\n", total_hits);
    return 0;
}
