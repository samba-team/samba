/*
 * Copyright (c) 2006 - 2007, 2010 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>
#include <roken.h>
#include <krb5-types.h>
#include <assert.h>

#include <rsa.h>

#include "tommath.h"

#define CHECK(f)                                                        \
    do { where = __LINE__ + 1; if (ret == MP_OKAY && ((ret = f)) != MP_OKAY) { goto out; } } while (0)
#define FIRST(e) do { ret = (e); } while (0)
#define FIRST_ALLOC(e)                                                  \
    do { where = __LINE__; ret = ((e)) ? MP_OKAY : MP_MEM; } while (0)
#define THEN_MP(e)                                                      \
    do { where = __LINE__ + 1; if (ret == MP_OKAY) ret = (e); } while (0)
#define THEN_IF_MP(cond, e)                                             \
    do { where = __LINE__ + 1; if (ret == MP_OKAY && (cond)) ret = (e); } while (0)
#define THEN_IF_VOID(cond, e)                                           \
    do { where = __LINE__ + 1; if (ret == MP_OKAY && (cond)) e; } while (0)
#define THEN_VOID(e)                                                    \
    do { where = __LINE__ + 1; if (ret == MP_OKAY) e; } while (0)
#define THEN_ALLOC(e)                                                   \
    do { where = __LINE__ + 1; if (ret == MP_OKAY) ret = ((e)) ? MP_OKAY : MP_MEM; } while (0)

static mp_err
random_num(mp_int *num, size_t len)
{
    unsigned char *p;
    mp_err ret = MP_MEM;

    len = (len + 7) / 8; /* bits to bytes */
    if ((p = malloc(len)) && RAND_bytes(p, len) != 1)
        ret = MP_ERR;
    if (p)
        ret = mp_from_ubin(num, p, len);
    free(p);
    return ret;
}

static mp_err
BN2mpz(mp_int *s, const BIGNUM *bn)
{
    size_t len;
    mp_err ret = MP_MEM;
    void *p;

    len = BN_num_bytes(bn);
    p = malloc(len);
    if (p) {
        BN_bn2bin(bn, p);
        ret = mp_from_ubin(s, p, len);
    }
    free(p);
    return ret;
}

static mp_err
setup_blind(mp_int *n, mp_int *b, mp_int *bi)
{
    mp_err ret;

    ret = random_num(b, mp_count_bits(n));
    if (ret == MP_OKAY) ret = mp_mod(b, n, b);
    if (ret == MP_OKAY) ret = mp_invmod(b, n, bi);
    return ret;
}

static mp_err
blind(mp_int *in, mp_int *b, mp_int *e, mp_int *n)
{
    mp_err ret;
    mp_int t1;

    ret = mp_init(&t1);
    /* in' = (in * b^e) mod n */
    if (ret == MP_OKAY) ret = mp_exptmod(b, e, n, &t1);
    if (ret == MP_OKAY) ret = mp_mul(&t1, in, in);
    if (ret == MP_OKAY) ret = mp_mod(in, n, in);
    mp_clear(&t1);
    return ret;
}

static mp_err
unblind(mp_int *out, mp_int *bi, mp_int *n)
{
    mp_err ret;

    /* out' = (out * 1/b) mod n */
    ret = mp_mul(out, bi, out);
    if (ret == MP_OKAY) ret = mp_mod(out, n, out);
    return ret;
}

static mp_err
ltm_rsa_private_calculate(mp_int * in, mp_int * p,  mp_int * q,
			  mp_int * dmp1, mp_int * dmq1, mp_int * iqmp,
			  mp_int * out)
{
    mp_err ret;
    mp_int vp, vq, u;
    int where HEIMDAL_UNUSED_ATTRIBUTE = 0;

    FIRST(mp_init_multi(&vp, &vq, &u, NULL));

    /* vq = c ^ (d mod (q - 1)) mod q */
    /* vp = c ^ (d mod (p - 1)) mod p */
    THEN_MP(mp_mod(in, p, &u));
    THEN_MP(mp_exptmod(&u, dmp1, p, &vp));
    THEN_MP(mp_mod(in, q, &u));
    THEN_MP(mp_exptmod(&u, dmq1, q, &vq));

    /* C2 = 1/q mod p  (iqmp) */
    /* u = (vp - vq)C2 mod p. */
    THEN_MP(mp_sub(&vp, &vq, &u));
    THEN_IF_MP(mp_isneg(&u), mp_add(&u, p, &u));
    THEN_MP(mp_mul(&u, iqmp, &u));
    THEN_MP(mp_mod(&u, p, &u));

    /* c ^ d mod n = vq + u q */
    THEN_MP(mp_mul(&u, q, &u));
    THEN_MP(mp_add(&u, &vq, out));

    mp_clear_multi(&vp, &vq, &u, NULL);
    return ret;
}

/*
 *
 */

static int
ltm_rsa_public_encrypt(int flen, const unsigned char* from,
			unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *p = NULL, *p0 = NULL;
    size_t size, ssize, padlen;
    mp_int enc, dec, n, e;
    mp_err ret;
    int where = __LINE__;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    FIRST(mp_init_multi(&n, &e, &enc, &dec, NULL));

    size = RSA_size(rsa);
    THEN_IF_MP((size < RSA_PKCS1_PADDING_SIZE ||
                size - RSA_PKCS1_PADDING_SIZE < flen),
               MP_ERR);
    THEN_MP(BN2mpz(&n, rsa->n));
    THEN_MP(BN2mpz(&e, rsa->e));
    THEN_IF_MP((mp_cmp_d(&e, 3) == MP_LT), MP_ERR);
    THEN_ALLOC((p = p0 = malloc(size - 1)));

    if (ret == MP_OKAY) {
        padlen = size - flen - 3;
        *p++ = 2;
    }
    THEN_IF_MP((RAND_bytes(p, padlen) != 1), MP_ERR);

    if (ret == MP_OKAY) {
        while (padlen) {
            if (*p == 0)
                *p = 1;
            padlen--;
            p++;
        }
        *p++ = 0;
        memcpy(p, from, flen);
        p += flen;
        assert((p - p0) == size - 1);
    }

    THEN_MP(mp_from_ubin(&dec, p0, size - 1));
    THEN_MP(mp_exptmod(&dec, &e, &n, &enc));
    THEN_VOID(ssize = mp_ubin_size(&enc));
    THEN_VOID(assert(size >= ssize));
    THEN_MP(mp_to_ubin(&enc, to, SIZE_MAX, NULL));
    THEN_VOID(size = ssize);

    mp_clear_multi(&dec, &e, &n, NULL);
    mp_clear(&enc);
    free(p0);
    return ret == MP_OKAY ? size : -where;
}

static int
ltm_rsa_public_decrypt(int flen, const unsigned char* from,
		       unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *p;
    mp_err ret;
    size_t size;
    mp_int s, us, n, e;
    int where = __LINE__;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    if (flen > RSA_size(rsa))
	return -2;

    FIRST(mp_init_multi(&e, &n, &s, &us, NULL));
    THEN_MP(BN2mpz(&n, rsa->n));
    THEN_MP(BN2mpz(&e, rsa->e));
    THEN_MP((mp_cmp_d(&e, 3) == MP_LT) ? MP_ERR : MP_OKAY);
    THEN_MP(mp_from_ubin(&s, rk_UNCONST(from), (size_t)flen));
    THEN_MP((mp_cmp(&s, &n) >= 0) ? MP_ERR : MP_OKAY);
    THEN_MP(mp_exptmod(&s, &e, &n, &us));

    THEN_VOID(p = to);
    THEN_VOID(size = mp_ubin_size(&us));
    THEN_VOID(assert(size <= RSA_size(rsa)));
    THEN_MP(mp_to_ubin(&us, p, SIZE_MAX, NULL));

    mp_clear_multi(&e, &n, &s, NULL);
    mp_clear(&us);

    if (ret != MP_OKAY || size == 0)
        return -where;

    /* head zero was skipped by mp_to_unsigned_bin */
    if (*p == 0)
        return -where;
    if (*p != 1)
        return -(where + 1);
    size--; p++;
    while (size && *p == 0xff) {
        size--; p++;
    }
    if (size == 0 || *p != 0)
        return -(where + 2);
    size--; p++;
    memmove(to, p, size);
    return size;
}

static int
ltm_rsa_private_encrypt(int flen, const unsigned char* from,
			unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *ptr, *ptr0 = NULL;
    mp_err ret;
    mp_int in, out, n, e;
    mp_int bi, b;
    size_t size;
    int blinding = (rsa->flags & RSA_FLAG_NO_BLINDING) == 0;
    int do_unblind = 0;
    int where = __LINE__;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    FIRST(mp_init_multi(&e, &n, &in, &out, &b, &bi, NULL));

    size = RSA_size(rsa);
    if (size < RSA_PKCS1_PADDING_SIZE || size - RSA_PKCS1_PADDING_SIZE < flen)
	return -2;

    THEN_ALLOC((ptr0 = ptr = malloc(size)));
    if (ret == MP_OKAY) {
        *ptr++ = 0;
        *ptr++ = 1;
        memset(ptr, 0xff, size - flen - 3);
        ptr += size - flen - 3;
        *ptr++ = 0;
        memcpy(ptr, from, flen);
        ptr += flen;
        assert((ptr - ptr0) == size);
    }

    THEN_MP(BN2mpz(&n, rsa->n));
    THEN_MP(BN2mpz(&e, rsa->e));
    THEN_IF_MP((mp_cmp_d(&e, 3) == MP_LT), MP_ERR);
    THEN_MP(mp_from_ubin(&in, ptr0, size));
    free(ptr0);

    THEN_IF_MP((mp_isneg(&in) || mp_cmp(&in, &n) >= 0), MP_ERR);

    if (blinding) {
	THEN_MP(setup_blind(&n, &b, &bi));
	THEN_MP(blind(&in, &b, &e, &n));
	do_unblind = 1;
    }

    if (ret == MP_OKAY && rsa->p && rsa->q && rsa->dmp1 && rsa->dmq1 &&
        rsa->iqmp) {
	mp_int p, q, dmp1, dmq1, iqmp;

	FIRST(mp_init_multi(&p, &q, &dmp1, &dmq1, &iqmp, NULL));
	THEN_MP(BN2mpz(&p, rsa->p));
	THEN_MP(BN2mpz(&q, rsa->q));
	THEN_MP(BN2mpz(&dmp1, rsa->dmp1));
	THEN_MP(BN2mpz(&dmq1, rsa->dmq1));
	THEN_MP(BN2mpz(&iqmp, rsa->iqmp));
        THEN_MP(ltm_rsa_private_calculate(&in, &p, &q, &dmp1, &dmq1, &iqmp,
                                          &out));
	mp_clear_multi(&p, &q, &dmp1, &dmq1, &iqmp, NULL);
	if (ret != MP_OKAY) goto out;
    } else if (ret == MP_OKAY) {
	mp_int d;

	THEN_MP(BN2mpz(&d, rsa->d));
	THEN_MP(mp_exptmod(&in, &d, &n, &out));
	mp_clear(&d);
	if (ret != MP_OKAY) goto out;
    }

    if (do_unblind)
	THEN_MP(unblind(&out, &bi, &n));

    if (ret == MP_OKAY && size > 0) {
	size_t ssize;

	ssize = mp_ubin_size(&out);
	assert(size >= ssize);
	THEN_MP(mp_to_ubin(&out, to, SIZE_MAX, NULL));
	size = ssize;
    }

 out:
    mp_clear_multi(&e, &n, &in, &out, &b, &bi, NULL);
    return ret == MP_OKAY ? size : -where;
}

static int
ltm_rsa_private_decrypt(int flen, const unsigned char* from,
			unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *ptr;
    size_t size;
    mp_err ret;
    mp_int in, out, n, e, b, bi;
    int blinding = (rsa->flags & RSA_FLAG_NO_BLINDING) == 0;
    int do_unblind = 0;
    int where = __LINE__;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    size = RSA_size(rsa);
    if (flen > size)
	return -2;

    FIRST(mp_init_multi(&in, &n, &e, &out, &b, &bi, NULL));
    THEN_MP(BN2mpz(&n, rsa->n));
    THEN_MP(BN2mpz(&e, rsa->e));
    THEN_IF_MP((mp_cmp_d(&e, 3) == MP_LT), MP_ERR);
    THEN_MP(mp_from_ubin(&in, rk_UNCONST(from), flen));
    THEN_IF_MP((mp_isneg(&in) || mp_cmp(&in, &n) >= 0), MP_ERR);

    if (blinding) {
	THEN_MP(setup_blind(&n, &b, &bi));
	THEN_MP(blind(&in, &b, &e, &n));
	do_unblind = 1;
    }

    if (ret == MP_OKAY && rsa->p && rsa->q && rsa->dmp1 && rsa->dmq1 &&
        rsa->iqmp) {
	mp_int p, q, dmp1, dmq1, iqmp;

	THEN_MP(mp_init_multi(&p, &q, &dmp1, &dmq1, &iqmp, NULL));
	THEN_MP(BN2mpz(&p, rsa->p));
	THEN_MP(BN2mpz(&q, rsa->q));
	THEN_MP(BN2mpz(&dmp1, rsa->dmp1));
	THEN_MP(BN2mpz(&dmq1, rsa->dmq1));
	THEN_MP(BN2mpz(&iqmp, rsa->iqmp));
	THEN_MP(ltm_rsa_private_calculate(&in, &p, &q, &dmp1, &dmq1, &iqmp, &out));
	mp_clear_multi(&p, &q, &dmp1, &dmq1, &iqmp, NULL);
	if (ret != MP_OKAY) goto out;
    } else if (ret == MP_OKAY) {
	mp_int d;

	THEN_IF_MP((mp_isneg(&in) || mp_cmp(&in, &n) >= 0), MP_ERR);
	THEN_MP(BN2mpz(&d, rsa->d));
	THEN_MP(mp_exptmod(&in, &d, &n, &out));
	mp_clear(&d);
	if (ret != MP_OKAY) goto out;
    }

    if (do_unblind)
	THEN_MP(unblind(&out, &bi, &n));

    if (ret == MP_OKAY) {
        size_t ssize;

        ptr = to;
        ssize = mp_ubin_size(&out);
        assert(size >= ssize);
        ret = mp_to_ubin(&out, ptr, SIZE_MAX, NULL);
        if (ret != MP_OKAY) goto out;
	size = ssize;

        /* head zero was skipped by mp_int_to_unsigned */
        if (*ptr != 2) {
            where = __LINE__;
            goto out;
        }
        size--; ptr++;
        while (size && *ptr != 0) {
            size--; ptr++;
        }
        if (size == 0) {
            where = __LINE__;
            goto out;
        }
        size--; ptr++;
        memmove(to, ptr, size);
    }

 out:
    mp_clear_multi(&e, &n, &in, &out, &b, &bi, NULL);
    return (ret == MP_OKAY) ? size : -where;
}

static BIGNUM *
mpz2BN(mp_int *s)
{
    size_t size;
    BIGNUM *bn;
    mp_err ret;
    void *p;

    size = mp_ubin_size(s);
    if (size == 0)
	return NULL;

    p = malloc(size);
    if (p == NULL)
	return NULL;

    ret = mp_to_ubin(s, p, SIZE_MAX, NULL);
    if (ret == MP_OKAY)
        bn = BN_bin2bn(p, size, NULL);
    free(p);
    return (ret == MP_OKAY) ? bn : NULL;
}

enum gen_pq_type { GEN_P, GEN_Q };

static int
gen_p(int bits, enum gen_pq_type pq_type, uint8_t nibble_pair, mp_int *p, mp_int *e, BN_GENCB *cb)
{
    unsigned char *buf = NULL;
    mp_bool res;
    mp_err ret = MP_MEM;
    mp_int t1, t2;
    size_t len = (bits + 7) / 8;
    int trials = mp_prime_rabin_miller_trials(bits);
    int counter = 0;
    int where HEIMDAL_UNUSED_ATTRIBUTE = 0;


    FIRST(mp_init_multi(&t1, &t2, NULL));
    if (ret == MP_OKAY && (buf = malloc(len))) do {
        BN_GENCB_call(cb, 2, counter++);
        /* random bytes */
        ret = (RAND_bytes(buf, len) == 1) ? MP_OKAY : MP_ERR;

        /* make it odd */
        buf[len - 1] |= 1;

        /* ensure the high nibble of the product is at least 128 */
        if (pq_type == GEN_P)
            buf[0] = (nibble_pair & 0xf0)         | (buf[0] & 0x0f);
        else
            buf[0] = ((nibble_pair & 0x0f) << 4)  | (buf[0] & 0x0f);

        /* load number */
        THEN_MP(mp_from_ubin(p, buf, len));

        /* test primality; repeat if not */
        THEN_MP(mp_prime_is_prime(p, trials, &res));
        if (ret == MP_OKAY && res == MP_NO) continue;

        /* check gcd(p - 1, e) == 1 */
	THEN_MP(mp_sub_d(p, 1, &t1));
	THEN_MP(mp_gcd(&t1, e, &t2));
    } while (ret == MP_OKAY && mp_cmp_d(&t2, 1) != MP_EQ);

    mp_clear_multi(&t1, &t2, NULL);
    free(buf);
    return ret;
}

static uint8_t pq_high_nibble_pairs[] = {
0x9f, 0xad, 0xae, 0xaf, 0xbc, 0xbd, 0xbe, 0xbf, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf9,
0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

static int
ltm_rsa_generate_key(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    mp_int el, p, q, n, d, dmp1, dmq1, iqmp, t1, t2, t3;
    mp_err ret;
    uint8_t high_nibbles = 0;
    int bitsp;
    int where = __LINE__;

    if (bits < 789)
	return -1;

    bitsp = (bits + 1) / 2;

    FIRST(mp_init_multi(&el, &p, &q, &n, &d,
                        &dmp1, &dmq1, &iqmp,
                        &t1, &t2, &t3, NULL));
    THEN_MP(BN2mpz(&el, e));

    /*
     * randomly pick a pair of high nibbles for p and q to ensure the product's
     * high nibble is at least 128
     */
    if (ret == MP_OKAY)
        ret = (RAND_bytes(&high_nibbles, 1) == 1) ? MP_OKAY : MP_ERR;
    high_nibbles %= sizeof(pq_high_nibble_pairs);
    high_nibbles = pq_high_nibble_pairs[high_nibbles];

    /* generate p and q so that p != q and bits(pq) ~ bits */
    THEN_MP(gen_p(bitsp, GEN_P, high_nibbles, &p, &el, cb));
    BN_GENCB_call(cb, 3, 0);
    THEN_MP(gen_p(bitsp, GEN_Q, high_nibbles, &q, &el, cb));

    /* make p > q */
    if (mp_cmp(&p, &q) < 0) {
	mp_int c;
	c = p;
	p = q;
	q = c;
    }

    BN_GENCB_call(cb, 3, 1);

    /* calculate n,  		n = p * q */
    THEN_MP(mp_mul(&p, &q, &n));

    /* calculate d, 		d = 1/e mod (p - 1)(q - 1) */
    THEN_MP(mp_sub_d(&p, 1, &t1));
    THEN_MP(mp_sub_d(&q, 1, &t2));
    THEN_MP(mp_mul(&t1, &t2, &t3));
    THEN_MP(mp_invmod(&el, &t3, &d));

    /* calculate dmp1		dmp1 = d mod (p-1) */
    THEN_MP(mp_mod(&d, &t1, &dmp1));
    /* calculate dmq1		dmq1 = d mod (q-1) */
    THEN_MP(mp_mod(&d, &t2, &dmq1));
    /* calculate iqmp 		iqmp = 1/q mod p */
    THEN_MP(mp_invmod(&q, &p, &iqmp));

    /* fill in RSA key */

    if (ret == MP_OKAY) {
        rsa->e = mpz2BN(&el);
        rsa->p = mpz2BN(&p);
        rsa->q = mpz2BN(&q);
        rsa->n = mpz2BN(&n);
        rsa->d = mpz2BN(&d);
        rsa->dmp1 = mpz2BN(&dmp1);
        rsa->dmq1 = mpz2BN(&dmq1);
        rsa->iqmp = mpz2BN(&iqmp);
    }

    mp_clear_multi(&el, &p, &q, &n, &d,
		   &dmp1, &dmq1, &iqmp,
		   &t1, &t2, &t3, NULL);
    return (ret == MP_OKAY) ? 1 : -where;
}

static int
ltm_rsa_init(RSA *rsa)
{
    return 1;
}

static int
ltm_rsa_finish(RSA *rsa)
{
    return 1;
}

const RSA_METHOD hc_rsa_ltm_method = {
    "hcrypto ltm RSA",
    ltm_rsa_public_encrypt,
    ltm_rsa_public_decrypt,
    ltm_rsa_private_encrypt,
    ltm_rsa_private_decrypt,
    NULL,
    NULL,
    ltm_rsa_init,
    ltm_rsa_finish,
    0,
    NULL,
    NULL,
    NULL,
    ltm_rsa_generate_key
};

const RSA_METHOD *
RSA_ltm_method(void)
{
    return &hc_rsa_ltm_method;
}
