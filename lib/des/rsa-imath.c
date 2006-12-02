/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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

#include "imath/imath.h"
#include "imath/rsamath.h"

static void
BN2mpz(mpz_t *s, const BIGNUM *bn)
{
    size_t len;
    void *p;

    mp_int_init(s);

    len = BN_num_bytes(bn);
    p = malloc(len);
    BN_bn2bin(bn, p);
    mp_int_read_unsigned(s, p, len);
    free(p);
}

static int
imath_rsa_public_encrypt(int flen, const unsigned char* from, 
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

    BN2mpz(&n, rsa->n);
    BN2mpz(&e, rsa->e);

    p = p0 = malloc(size - 1);
    if (p0 == NULL) {
	mp_int_clear(&e);
	mp_int_clear(&n);
	return -3;
    }

    padlen = size - flen - 3;
    assert(padlen >= 8);

    *p++ = 2;
    if (RAND_bytes(p, padlen) != 1) {
	mp_int_clear(&e);
	mp_int_clear(&n);
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

    mp_int_init(&enc);
    mp_int_init(&dec);
    mp_int_read_unsigned(&dec, p0, size - 1);
    free(p0);

    res = rsa_rsaep(&dec, &e, &n, &enc);
    mp_int_clear(&dec);
    mp_int_clear(&e);
    mp_int_clear(&n);
    {
	size_t ssize;
	ssize = mp_int_unsigned_len(&enc);
	assert(size >= ssize);
	mp_int_to_unsigned(&enc, to, ssize);
	size = ssize;
    }
    mp_int_clear(&enc);

    return size;
}

static int
imath_rsa_public_decrypt(int flen, const unsigned char* from, 
			 unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *p;
    mp_result res;
    size_t size;
    mpz_t s, us, n, e;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    if (flen > RSA_size(rsa))
	return -2;

    BN2mpz(&n, rsa->n);
    BN2mpz(&e, rsa->e);

#if 0
    /* Check that the exponent is larger then 3 */
    if (mp_int_compare_value(&e, 3) <= 0) {
	mp_int_clear(&n);
	mp_int_clear(&e);
	return -3;
    }
#endif

    mp_int_init(&s);
    mp_int_init(&us);
    mp_int_read_unsigned(&s, rk_UNCONST(from), flen);

    if (mp_int_compare(&s, &n) >= 0) {
	mp_int_clear(&n);
	mp_int_clear(&e);
	return -4;
    }

    res = rsa_rsavp(&s, &e, &n, &us);
    mp_int_clear(&s);
    mp_int_clear(&n);
    mp_int_clear(&e);

    if (res != MP_OK)
	return -5;
    p = to;


    size = mp_int_unsigned_len(&us);
    assert(size <= RSA_size(rsa));
    mp_int_to_unsigned(&us, p, size);

    mp_int_clear(&us);

    /* head zero was skipped by mp_int_to_unsigned */
    if (*p == 0)
	return -7;
    if (*p != 1)
	return -6;
    size--; p++;
    while (size && *p == 0xff) {
	size--; p++;
    }
    if (size == 0 || *p != 0)
	return -7;
    size--; p++;

    memmove(to, p, size);

    return size;
}

static int
imath_rsa_private_encrypt(int flen, const unsigned char* from, 
			  unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *p, *p0;
    mp_result res;
    size_t size;
    mpz_t s, us, n, d;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    size = RSA_size(rsa);

    if (size < RSA_PKCS1_PADDING_SIZE || size - RSA_PKCS1_PADDING_SIZE < flen)
	return -2;

    BN2mpz(&n, rsa->n);
    BN2mpz(&d, rsa->d);

    p0 = p = malloc(size);
    *p++ = 0;
    *p++ = 1;
    memset(p, 0xff, size - flen - 3);
    p += size - flen - 3;
    *p++ = 0;
    memcpy(p, from, flen);
    p += flen;
    assert((p - p0) == size);

    mp_int_init(&s);
    mp_int_init(&us);
    mp_int_read_unsigned(&us, p0, size);
    free(p0);

    /* XXX insert pre-image keyblinding here */

    res = rsa_rsasp(&us, &d, &n, &s);

    /* XXX insert post-image keyblinding here */

    mp_int_clear(&d);
    mp_int_clear(&n);
    mp_int_clear(&us);
    {
	size_t ssize;
	ssize = mp_int_unsigned_len(&s);
	assert(size >= ssize);
	mp_int_to_unsigned(&s, to, size);
    }
    mp_int_clear(&s);

    return size;
}

static int
imath_rsa_private_decrypt(int flen, const unsigned char* from, 
			  unsigned char* to, RSA* rsa, int padding)
{
    unsigned char *p;
    mp_result res;
    size_t size;
    mpz_t enc, dec, n, d;

    if (padding != RSA_PKCS1_PADDING)
	return -1;

    size = RSA_size(rsa);
    if (flen > size)
	return -2;

    mp_int_init(&enc);
    mp_int_init(&dec);

    BN2mpz(&n, rsa->n);
    BN2mpz(&d, rsa->d);

    res = mp_int_read_unsigned(&enc, rk_UNCONST(from), flen);

    /* XXX insert pre-image keyblinding here */

    res = rsa_rsadp(&enc, &d, &n, &dec);

    /* XXX insert post-image keyblinding here */

    mp_int_clear(&enc);
    mp_int_clear(&d);
    mp_int_clear(&n);

    p = to;
    {
	size_t ssize;
	ssize = mp_int_unsigned_len(&dec);
	assert(size >= ssize);
	mp_int_to_unsigned(&dec, p, ssize);
	size = ssize;
    }
    mp_int_clear(&dec);

    /* head zero was skipped by mp_int_to_unsigned */
    if (*p != 2)
	return -3;
    size--; p++;
    while (size && *p != 0) {
	size--; p++;
    }
    if (size == 0)
	return -4;
    size--; p++;

    memmove(to, p, size);

    return size;
}


static int 
imath_rsa_init(RSA *rsa)
{
    return 1;
}

static int
imath_rsa_finish(RSA *rsa)
{
    return 1;
}

const RSA_METHOD hc_rsa_imath_method = {
    "hcrypto imath RSA",
    imath_rsa_public_encrypt,
    imath_rsa_public_decrypt,
    imath_rsa_private_encrypt,
    imath_rsa_private_decrypt,
    NULL,
    NULL,
    imath_rsa_init,
    imath_rsa_finish,
    0,
    NULL,
    NULL,
    NULL
};

const RSA_METHOD *
RSA_imath_method(void)
{
    return &hc_rsa_imath_method;
}
