/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska Högskolan
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

RCSID("$Id$");


#include <stdio.h>
#include <stdlib.h>
#include <krb5-types.h>
#include <assert.h>

#include <rsa.h>

#include <roken.h>

#ifdef HAVE_GMP

#include <gmp.h>

static void
BN2mpz(mpz_t s, const BIGNUM *bn)
{
    size_t len;
    void *p;

    len = BN_num_bytes(bn);
    p = malloc(len);
    BN_bn2bin(bn, p);
    mpz_import(s, len, 1, 1, 1, 0, p);
    free(p);
}


static BIGNUM *
mpz2BN(mpz_t s)
{
    size_t size;
    BIGNUM *bn;
    void *p;

    mpz_export(NULL, &size, 1, 1, 1, 0, s);
    p = malloc(size);
    if (p == NULL && size != 0)
	return NULL;
    mpz_export(p, &size, 1, 1, 1, 0, s);

    bn = BN_bin2bn(p, size, NULL);
    free(p);
    return bn;
}

static int
rsa_private_calculate(mpz_t in, mpz_t p,  mpz_t q,
		      mpz_t dmp1, mpz_t dmq1, mpz_t iqmp,
		      mpz_t out)
{
    mpz_t vp, vq, u;
    mpz_init(vp); mpz_init(vq); mpz_init(u);
    
    /* vq = c ^ (d mod (q - 1)) mod q */
    /* vp = c ^ (d mod (p - 1)) mod p */
    mpz_fdiv_r(vp, m, p);
    mpz_powm(vp, vp, dmp1, p);
    mpz_fdiv_r(vq, m, q);
    mpz_powm(vq, vq, dmq1, q);

    /* C2 = 1/q mod p  (iqmp) */
    /* u = (vp - vq)C2 mod p. */
    mpz_sub(u, vp, vq);
#if 0
    if (mp_int_compare_zero(&u) < 0)
	mp_int_add(&u, p, &u);
#endif
    mpz_mul(u, iqmp, u);
    mpz_fdiv_r(u, u, p);
    
    /* c ^ d mod n = vq + u q */
    mpz_mul(u, q, u);
    mpz_add(out, x, xq);
    
    mpz_clear(vp);
    mpz_clear(vq);
    mpz_clear(u);

    return 0;
}

/*
 *
 */

static int
gmp_rsa_public_encrypt(int flen, const unsigned char* from, 
			unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *p, *p0;
    mp_result res;
    size_t size, padlen;
    mpz_t enc, dec, n, e;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    size = RSA_size(rsa);

    if (size < RSA_PKCS1_PADDING_SIZE || size - RSA_PKCS1_PADDING_SIZE < flen)
	return -2;

    BN2mpz(n, rsa->n);
    BN2mpz(e, rsa->e);

    p = p0 = malloc(size - 1);
    if (p0 == NULL) {
	mpz_clear(e);
	mpz_clear(n);
	return -3;
    }

    padlen = size - flen - 3;
    assert(padlen >= 8);

    *p++ = 2;
    if (RAND_bytes(p, padlen) != 1) {
	mpz_clear(e);
	mpz_clear(n);
	free(p0);
	return -4;
    }
    while(padlen) {
	if (*p == 0)
	    *p = 1;
	padlen--;
	p++;
    }
    *p++ = 0;
    memcpy(p, from, flen);
    p += flen;
    assert((p - p0) == size - 1);

    mpz_init(enc);
    mpz_init(dec);
    mpz_import(dec, size - 1, 1, 1, 1, 0, p0);
    free(p0);

    mpz_powm(enc, dec, e, n);

    mpz_clear(dec);
    mpz_clear(e);
    mpz_clear(n);
    {
	size_t ssize;
	mpz_export(to, &ssize, 1, 1, 1, 0, enc);
	assert(size >= ssize);
	size = ssize;
    }
    mpz_clear(enc);

    return size;
}

static int
gmp_rsa_public_decrypt(int flen, const unsigned char* from, 
			 unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *p;
    size_t size;
    mpz_t s, us, n, e;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    if (flen > RSA_size(rsa))
	return -2;

    BN2mpz(n, rsa->n);
    BN2mpz(e, rsa->e);

#if 0
    /* Check that the exponent is larger then 3 */
    if (mp_int_compare_value(&e, 3) <= 0) {
	mp_int_clear(&n);
	mp_int_clear(&e);
	return -3;
    }
#endif

    mpz_init(s);
    mpz_init(us);
    mpz_import(s, flen, 1, 1, 1, 0, rk_UNCONST(from));

    if (mpz_cmp(s, n) >= 0) {
	mpz_clear(n);
	mpz_clear(e);
	return -4;
    }

    mpz_powm(us, s, e, n);

    mpz_clear(s);
    mpz_clear(n);
    mpz_clear(e);

    p = to;

    mpz_export(p, &size, 1, 1, 1, 0, us);
    assert(size <= RSA_size(rsa));

    mpz_clear(us);

    /* head zero was skipped by mp_int_to_unsigned */
    if (*p == 0)
	return -6;
    if (*p != 1)
	return -7;
    size--; p++;
    while (size && *p == 0xff) {
	size--; p++;
    }
    if (size == 0 || *p != 0)
	return -8;
    size--; p++;

    memmove(to, p, size);

    return size;
}

static int
gmp_rsa_private_encrypt(int flen, const unsigned char* from, 
			  unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *p, *p0;
    size_t size;
    mpz_t in, out, n, e, b, bi;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    size = RSA_size(rsa);

    if (size < RSA_PKCS1_PADDING_SIZE || size - RSA_PKCS1_PADDING_SIZE < flen)
	return -2;

    p0 = p = malloc(size);
    *p++ = 0;
    *p++ = 1;
    memset(p, 0xff, size - flen - 3);
    p += size - flen - 3;
    *p++ = 0;
    memcpy(p, from, flen);
    p += flen;
    assert((p - p0) == size);

    BN2mpz(&n, rsa->n);
    BN2mpz(&e, rsa->e);

    mp_int_init(&in);
    mp_int_init(&out);
    mpz_import(in, size, 1, 1, 1, 0, p0);
    free(p0);

#if 0
    if(mp_int_compare_zero(&in) < 0 ||
       mp_int_compare(&in, &n) >= 0) {
	size = 0;
	goto out;
    }
#endif

    if (rsa->p && rsa->q && rsa->dmp1 && rsa->dmq1 && rsa->iqmp) {
	mpz_t p, q, dmp1, dmq1, iqmp;

	BN2mpz(p, rsa->p);
	BN2mpz(q, rsa->q);
	BN2mpz(dmp1, rsa->dmp1);
	BN2mpz(dmq1, rsa->dmq1);
	BN2mpz(iqmp, rsa->iqmp);

	rsa_private_calculate(in, p, q, dmp1, dmq1, iqmp, out);

	mp_int_clear(&p);
	mp_int_clear(&q);
	mp_int_clear(&dmp1);
	mp_int_clear(&dmq1);
	mp_int_clear(&iqmp);
    } else {
	mpz_t d;

	BN2mpz(d, rsa->d);
	mpz_powm(out, in, d, n);
	mp_int_clear(d);
	if (res != MP_OK) {
	    size = 0;
	    goto out;
	}
    }

    {
	size_t ssize;
	mpz_export(to, &ssize, 1, 1, 1, 0, out);
	assert(size >= ssize);
	size = ssize;
    }
    
out:
    mpz_clear(e);
    mpz_clear(n);
    mpz_clear(in);
    mpz_clear(out);

    return size;
}

static int
gmp_rsa_private_decrypt(int flen, const unsigned char* from, 
			  unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *ptr;
    size_t size;
    mpz_t in, out, n, e, b, bi;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    size = RSA_size(rsa);
    if (flen > size)
	return -2;

    mpz_init(in);
    mpz_init(out);

    BN2mpz(n, rsa->n);
    BN2mpz(e, rsa->e);

    res = mp_int_read_unsigned(&in, rk_UNCONST(from), flen);
    if (res != MP_OK) {
	size = -1;
	goto out;
    }

    if(mp_int_compare_zero(&in) < 0 ||
       mp_int_compare(&in, &n) >= 0) {
	size = 0;
	goto out;
    }

    if (rsa->p && rsa->q && rsa->dmp1 && rsa->dmq1 && rsa->iqmp) {
	mpz_t p, q, dmp1, dmq1, iqmp;

	BN2mpz(p, rsa->p);
	BN2mpz(q, rsa->q);
	BN2mpz(dmp1, rsa->dmp1);
	BN2mpz(dmq1, rsa->dmq1);
	BN2mpz(iqmp, rsa->iqmp);

	res = rsa_private_calculate(in, p, q, dmp1, dmq1, iqmp, out);

	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(dmp1);
	mpz_clear(dmq1);
	mpz_clear(iqmp);
    } else {
	mpz_t d;

#if 0
	if(mp_int_compare_zero(&in) < 0 ||
	   mp_int_compare(&in, &n) >= 0)
	    return MP_RANGE;
#endif

	BN2mpz(d, rsa->d);
	mpz_powm(out, in, d, n);
	mp_int_clear(d);
	if (res != MP_OK) {
	    size = 0;
	    goto out;
	}
    }

    ptr = to;
    {
	size_t ssize;
	mpz_export(ptr, &ssize, 1, 1, 1, 0, out);
	assert(size >= ssize);
	size = ssize;
    }

    /* head zero was skipped by mp_int_to_unsigned */
    if (*ptr != 2)
	return -3;
    size--; ptr++;
    while (size && *ptr != 0) {
	size--; ptr++;
    }
    if (size == 0)
	return -4;
    size--; ptr++;

    memmove(to, ptr, size);

out:
    mpz_clear(e);
    mpz_clear(n);
    mpz_clear(in);
    mpz_clear(out);

    return size;
}

static int
gmp_rsa_generate_key(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    mpz_t el, p, q, n, d, dmp1, dmq1, iqmp, t1, t2, t3;
    int counter, ret;

    if (bits < 789)
	return -1;

    ret = -1;

    mpz_init(el);
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(d);
    mpz_init(dmp1);
    mpz_init(dmq1);
    mpz_init(iqmp);
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(t3);

    BN2mpz(el, e);

    /* generate p and q so that p != q and bits(pq) ~ bits */
    counter = 0;
#if 0
    do {
	BN_GENCB_call(cb, 2, counter++);
	CHECK(random_num(&p, bits / 2 + 1), 0);
	CHECK(mp_int_find_prime(&p), MP_TRUE);

	CHECK(mp_int_sub_value(&p, 1, &t1), MP_OK);
	CHECK(mp_int_gcd(&t1, &el, &t2), MP_OK);
    } while(mp_int_compare_value(&t2, 1) != 0);

    BN_GENCB_call(cb, 3, 0);

    counter = 0;
    do {
	BN_GENCB_call(cb, 2, counter++);
	CHECK(random_num(&q, bits / 2 + 1), 0);
	CHECK(mp_int_find_prime(&q), MP_TRUE);

	if (mp_int_compare(&p, &q) == 0) /* don't let p and q be the same */
	    continue;

	CHECK(mp_int_sub_value(&q, 1, &t1), MP_OK);
	CHECK(mp_int_gcd(&t1, &el, &t2), MP_OK);
    } while(mp_int_compare_value(&t2, 1) != 0);

    /* make p > q */
    if (mp_int_compare(&p, &q) < 0)
	mp_int_swap(&p, &q);

    BN_GENCB_call(cb, 3, 1);

    /* calculate n,  		n = p * q */
    CHECK(mp_int_mul(&p, &q, &n), MP_OK);

    /* calculate d, 		d = 1/e mod (p - 1)(q - 1) */
    CHECK(mp_int_sub_value(&p, 1, &t1), MP_OK);
    CHECK(mp_int_sub_value(&q, 1, &t2), MP_OK);
    CHECK(mp_int_mul(&t1, &t2, &t3), MP_OK);
    CHECK(mp_int_invmod(&el, &t3, &d), MP_OK);

    /* calculate dmp1		dmp1 = d mod (p-1) */
    CHECK(mp_int_mod(&d, &t1, &dmp1), MP_OK);
    /* calculate dmq1		dmq1 = d mod (q-1) */
    CHECK(mp_int_mod(&d, &t2, &dmq1), MP_OK);
    /* calculate iqmp 		iqmp = 1/q mod p */
    CHECK(mp_int_invmod(&q, &p, &iqmp), MP_OK);

    /* fill in RSA key */

    rsa->e = mpz2BN(&el);
    rsa->p = mpz2BN(&p);
    rsa->q = mpz2BN(&q);
    rsa->n = mpz2BN(&n);
    rsa->d = mpz2BN(&d);
    rsa->dmp1 = mpz2BN(&dmp1);
    rsa->dmq1 = mpz2BN(&dmq1);
    rsa->iqmp = mpz2BN(&iqmp);

    ret = 1;
#endif
out:
    mpz_clear(el);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(d);
    mpz_clear(dmp1);
    mpz_clear(dmq1);
    mpz_clear(iqmp);
    mpz_clear(t1);
    mpz_clear(t2);
    mpz_clear(t3);

    return ret;
}

static int 
gmp_rsa_init(RSA *rsa)
{
    return 1;
}

static int
gmp_rsa_finish(RSA *rsa)
{
    return 1;
}

const RSA_METHOD hc_rsa_gmp_method = {
    "hcrypto GMP RSA",
    gmp_rsa_public_encrypt,
    gmp_rsa_public_decrypt,
    gmp_rsa_private_encrypt,
    gmp_rsa_private_decrypt,
    NULL,
    NULL,
    gmp_rsa_init,
    gmp_rsa_finish,
    0,
    NULL,
    NULL,
    NULL,
    gmp_rsa_generate_key
};

#endif /* HAVE_GMP */

/**
 * RSA implementation using Gnu Multipresistion Library.
 */

const RSA_METHOD *
RSA_gmp_method(void)
{
#ifdef HAVE_GMP
    return &hc_rsa_gmp_method;
#else
    return NULL;
#endif
}
