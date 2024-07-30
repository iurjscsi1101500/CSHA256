#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x) (ROTR32((x), 7) ^ ROTR32((x), 18) ^ ((x) >> 3))
#define S1(x) (ROTR32((x), 17) ^ ROTR32((x), 19) ^ ((x) >> 10))
#define E0(x) (ROTR32((x), 2) ^ ROTR32((x), 13) ^ ROTR32((x), 22))
#define E1(x) (ROTR32((x), 6) ^ ROTR32((x), 11) ^ ROTR32((x), 25))

static unsigned long K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    int t;

    for (t = 0; t < 16; ++t) {
        W[t] = (data[t * 4] << 24) | (data[t * 4 + 1] << 16) | (data[t * 4 + 2] << 8) | data[t * 4 + 3];
    }
    for (t = 16; t < 64; ++t) {
        W[t] = S1(W[t - 2]) + W[t - 7] + S0(W[t - 15]) + W[t - 16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (t = 0; t < 64; ++t) {
        uint32_t T1 = h + E1(e) + CH(e, f, g) + K[t] + W[t];
        uint32_t T2 = E0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    uint32_t state[8];
    uint32_t bitlen[2];
    uint8_t buffer[64];
    size_t i;

    memcpy(state, H, sizeof(state));

    for (i = 0; i + 64 <= len; i += 64) {
        sha256_transform(state, data + i);
    }

    size_t remaining = len - i;
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, data + i, remaining);
    buffer[remaining] = 0x80;

    if (remaining >= 56) {
        sha256_transform(state, buffer);
        memset(buffer, 0, sizeof(buffer));
    }

    bitlen[0] = (uint32_t)(len >> 29);
    bitlen[1] = (uint32_t)(len << 3);
    buffer[56] = (bitlen[0] >> 24) & 0xff;
    buffer[57] = (bitlen[0] >> 16) & 0xff;
    buffer[58] = (bitlen[0] >> 8) & 0xff;
    buffer[59] = bitlen[0] & 0xff;
    buffer[60] = (bitlen[1] >> 24) & 0xff;
    buffer[61] = (bitlen[1] >> 16) & 0xff;
    buffer[62] = (bitlen[1] >> 8) & 0xff;
    buffer[63] = bitlen[1] & 0xff;

    sha256_transform(state, buffer);

    for (i = 0; i < 8; ++i) {
        hash[i * 4] = (state[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xff;
        hash[i * 4 + 3] = state[i] & 0xff;
    }
}

void print_hash(uint8_t hash[]) {
    for (int i = 0; i < 32; ++i)
        printf("%02x", hash[i]);
    printf("\n");
}
int check_sha256(uint8_t hash1[32], char *input2) {
    uint8_t hash2[32];
    sha256((const uint8_t *)input2, strlen(input2), hash2);

    for (int i = 0; i < 32; ++i) {
        if (hash1[i] != hash2[i]) {
            return -1;
        }
    }
    return 0;
}
