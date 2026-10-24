#include <string.h>
#include "SHA3.h"

#define RATE 136   

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};


static const int ROTC[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};


static const int PILN[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}


static void keccak_f(uint64_t st[25]) {
    uint64_t bc[5], t;
    int i, j, r;

    for (r = 0; r < 24; r++) {
   
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        t = st[1];
        for (i = 0; i < 24; i++) {
            j = PILN[i];
            bc[0] = st[j];
            st[j] = rotl64(t, ROTC[i]);
            t = bc[0];
        }

        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        st[0] ^= RC[r];
    }
}


static void absorb_block(uint64_t st[25], const uint8_t* block) {
    int i, k;
    for (i = 0; i < RATE / 8; i++) {
        uint64_t lane = 0;
        for (k = 0; k < 8; k++)
            lane |= (uint64_t)block[i * 8 + k] << (8 * k);
        st[i] ^= lane;
    }
}

int sha3_256(const uint8_t* data, size_t len, uint8_t* out) {
    uint64_t st[25];
    uint8_t block[RATE];
    int i, k;

    if (out == NULL || (data == NULL && len != 0))
        return -1;

    memset(st, 0, sizeof(st));

    while (len >= RATE) {
        absorb_block(st, data);
        keccak_f(st);
        data += RATE;
        len -= RATE;
    }


    memset(block, 0, RATE);
    if (len > 0)
        memcpy(block, data, len);
    block[len] ^= 0x06;
    block[RATE - 1] ^= 0x80;
    absorb_block(st, block);
    keccak_f(st);


    for (i = 0; i < SHA3_256_DIGEST_LEN / 8; i++)
        for (k = 0; k < 8; k++)
            out[i * 8 + k] = (uint8_t)(st[i] >> (8 * k));

    return 0;
}