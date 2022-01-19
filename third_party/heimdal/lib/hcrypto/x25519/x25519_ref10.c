/*
 * ISC License
 *
 * Copyright (c) 2013-2019
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stddef.h>
#include <stdint.h>

#include "ed25519_ref10.h"
#include "x25519_ref10.h"
#include "align.h"

/*
 * Reject small order points early to mitigate the implications of
 * unexpected optimizations that would affect the ref10 code.
 * See https://eprint.iacr.org/2017/806.pdf for reference.
 */
static int
has_small_order(const unsigned char s[32])
{
    CRYPTO_ALIGN(16)
    static const unsigned char blacklist[][32] = {
        /* 0 (order 4) */
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /* 1 (order 1) */
        { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /* 325606250916557431795983626356110631294008115727848805560023387167927233504
           (order 8) */
        { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
          0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
          0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
        /* 39382357235489614581723060781553021112529911719440698176882885853963445705823
           (order 8) */
        { 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
          0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
          0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
        /* p-1 (order 2) */
        { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        /* p (=0, order 4) */
        { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        /* p+1 (=1, order 1) */
        { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
    };
    unsigned char c[7] = { 0 };
    unsigned int  k;
    size_t        i, j;

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

    COMPILER_ASSERT(7 == sizeof blacklist / sizeof blacklist[0]);
    for (j = 0; j < 31; j++) {
        for (i = 0; i < sizeof blacklist / sizeof blacklist[0]; i++) {
            c[i] |= s[j] ^ blacklist[i][j];
        }
    }
    for (i = 0; i < sizeof blacklist / sizeof blacklist[0]; i++) {
        c[i] |= (s[j] & 0x7f) ^ blacklist[i][j];
    }
    k = 0;
    for (i = 0; i < sizeof blacklist / sizeof blacklist[0]; i++) {
        k |= (c[i] - 1);
    }
    return (int) ((k >> 8) & 1);
}

static int
crypto_scalarmult_curve25519_ref10(unsigned char *q,
				   const unsigned char *n,
				   const unsigned char *p)
{
    unsigned char *t = q;
    unsigned int   i;
    fe25519        x1;
    fe25519        x2;
    fe25519        z2;
    fe25519        x3;
    fe25519        z3;
    fe25519        tmp0;
    fe25519        tmp1;
    int            pos;
    unsigned int   swap;
    unsigned int   b;

    if (has_small_order(p)) {
        return -1;
    }
    for (i = 0; i < 32; i++) {
        t[i] = n[i];
    }
    t[0] &= 248;
    t[31] &= 127;
    t[31] |= 64;
    fe25519_frombytes(x1, p);
    fe25519_1(x2);
    fe25519_0(z2);
    fe25519_copy(x3, x1);
    fe25519_1(z3);

    swap = 0;
    for (pos = 254; pos >= 0; --pos) {
        b = t[pos / 8] >> (pos & 7);
        b &= 1;
        swap ^= b;
        fe25519_cswap(x2, x3, swap);
        fe25519_cswap(z2, z3, swap);
        swap = b;
        fe25519_sub(tmp0, x3, z3);
        fe25519_sub(tmp1, x2, z2);
        fe25519_add(x2, x2, z2);
        fe25519_add(z2, x3, z3);
        fe25519_mul(z3, tmp0, x2);
        fe25519_mul(z2, z2, tmp1);
        fe25519_sq(tmp0, tmp1);
        fe25519_sq(tmp1, x2);
        fe25519_add(x3, z3, z2);
        fe25519_sub(z2, z3, z2);
        fe25519_mul(x2, tmp1, tmp0);
        fe25519_sub(tmp1, tmp1, tmp0);
        fe25519_sq(z2, z2);
        fe25519_scalar_product(z3, tmp1, 121666);
        fe25519_sq(x3, x3);
        fe25519_add(tmp0, tmp0, z3);
        fe25519_mul(z3, x1, z2);
        fe25519_mul(z2, tmp1, tmp0);
    }
    fe25519_cswap(x2, x3, swap);
    fe25519_cswap(z2, z3, swap);

    fe25519_invert(z2, z2);
    fe25519_mul(x2, x2, z2);
    fe25519_tobytes(q, x2);

    return 0;
}

static void
edwards_to_montgomery(fe25519 montgomeryX, const fe25519 edwardsY, const fe25519 edwardsZ)
{
    fe25519 tempX;
    fe25519 tempZ;

    fe25519_add(tempX, edwardsZ, edwardsY);
    fe25519_sub(tempZ, edwardsZ, edwardsY);
    fe25519_invert(tempZ, tempZ);
    fe25519_mul(montgomeryX, tempX, tempZ);
}

int
crypto_scalarmult_curve25519_base(unsigned char *q,
				  const unsigned char *n)
{
    unsigned char *t = q;
    ge25519_p3     A;
    fe25519        pk;
    unsigned int   i;

    for (i = 0; i < 32; i++) {
        t[i] = n[i];
    }
    t[0] &= 248;
    t[31] &= 127;
    t[31] |= 64;
    ge25519_scalarmult_base(&A, t);
    edwards_to_montgomery(pk, A.Y, A.Z);
    fe25519_tobytes(q, pk);

    return 0;
}

int
crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                             const unsigned char *p)
{
    size_t                 i;
    volatile unsigned char d = 0;

    if (crypto_scalarmult_curve25519_ref10(q, n, p) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    for (i = 0; i < crypto_scalarmult_curve25519_BYTES; i++) {
        d |= q[i];
    }
    return -(1 & ((d - 1) >> 8));
}

