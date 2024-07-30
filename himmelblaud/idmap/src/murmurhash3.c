/* This file is based on the public domain MurmurHash3 from Austin Appleby:
 * http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
 *
 * We use only the 32 bit variant because the 2 produce different result while
 * we need to produce the same result regardless of the architecture as
 * clients can be both 64 or 32 bit at the same time.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "config.h"
#include "murmurhash3.h"
#include "util.h"

static uint32_t rotl(uint32_t x, int8_t r)
{
    return (x << r) | (x >> (32 - r));
}

/* slower than original but is endian neutral and handles platforms that
 * do only aligned reads */
__attribute__((always_inline))
static inline uint32_t getblock(const uint8_t *p, int i)
{
    uint32_t r;
    size_t size = sizeof(uint32_t);

    memcpy(&r, &p[i * size], size);

    return le32toh(r);
}

/*
 * Finalization mix - force all bits of a hash block to avalanche
 */

__attribute__((always_inline))
static inline uint32_t fmix(uint32_t h)
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}


uint32_t murmurhash3(const char *key, int len, uint32_t seed)
{
    const uint8_t *blocks;
    const uint8_t *tail;
    int nblocks;
    uint32_t h1;
    uint32_t k1;
    uint32_t c1;
    uint32_t c2;
    int i;

    blocks = (const uint8_t *)key;
    nblocks = len / 4;
    h1 = seed;
    c1 = 0xcc9e2d51;
    c2 = 0x1b873593;

    /* body */

    for (i = 0; i < nblocks; i++) {

        k1 = getblock(blocks, i);

        k1 *= c1;
        k1 = rotl(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = rotl(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    /* tail */

    tail = (const uint8_t *)key + nblocks * 4;

    k1 = 0;

    switch (len & 3) {
    case 3:
        k1 ^= tail[2] << 16;
        SSS_ATTRIBUTE_FALLTHROUGH;
    case 2:
        k1 ^= tail[1] << 8;
        SSS_ATTRIBUTE_FALLTHROUGH;
    case 1:
        k1 ^= tail[0];
        k1 *= c1;
        k1 = rotl(k1, 15);
        k1 *= c2;
        h1 ^= k1;
        break;
    default:
        break;
    }

    /* finalization */

    h1 ^= len;
    h1 = fmix(h1);

    return h1;
}
