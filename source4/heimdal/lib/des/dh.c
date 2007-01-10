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

RCSID("$Id: dh.c,v 1.10 2006/10/19 17:31:51 lha Exp $");

#include <stdio.h>
#include <stdlib.h>
#include <dh.h>

#include <roken.h>

/*
 *
 */

DH *
DH_new(void)
{
    return DH_new_method(NULL);
}

DH *
DH_new_method(ENGINE *engine)
{
    DH *dh;

    dh = calloc(1, sizeof(*dh));
    if (dh == NULL)
	return NULL;

    dh->references = 1;

    if (engine) {
	ENGINE_up_ref(engine);
	dh->engine = engine;
    } else {
	dh->engine = ENGINE_get_default_DH();
    }

    if (dh->engine) {
	dh->meth = ENGINE_get_DH(dh->engine);
	if (dh->meth == NULL) {
	    ENGINE_finish(engine);
	    free(dh);
	    return 0;
	}
    }

    if (dh->meth == NULL)
	dh->meth = DH_get_default_method();

    (*dh->meth->init)(dh);

    return dh;
}

void
DH_free(DH *dh)
{
    if (dh->references <= 0)
	abort();

    if (--dh->references > 0)
	return;

    (*dh->meth->finish)(dh);

    if (dh->engine)
	ENGINE_finish(dh->engine);

#define free_if(f) if (f) { BN_free(f); }
    free_if(dh->p);
    free_if(dh->g);
    free_if(dh->pub_key);
    free_if(dh->priv_key);
    free_if(dh->q);
    free_if(dh->j);
    free_if(dh->counter);
#undef free_if

    memset(dh, 0, sizeof(*dh));
    free(dh);
}    

int
DH_up_ref(DH *dh)
{
    return ++dh->references;
}

int
DH_size(const DH *dh)
{
    return BN_num_bytes(dh->p);
}

int
DH_set_ex_data(DH *dh, int idx, void *data)
{
    dh->ex_data.sk = data;
    return 1;
}

void *
DH_get_ex_data(DH *dh, int idx)
{
    return dh->ex_data.sk;
}

int
DH_generate_parameters_ex(DH *dh, int prime_len, int generator, BN_GENCB *cb)
{
    if (dh->meth->generate_params)
	return dh->meth->generate_params(dh, prime_len, generator, cb);
    return 0;
}

/*
 * Check that
 *
 * 	pub_key > 1    and    pub_key < p - 1
 *
 * to avoid small subgroups attack.
 */

int
DH_check_pubkey(const DH *dh, const BIGNUM *pub_key, int *codes)
{
    BIGNUM *bn = NULL, *sum = NULL;
    int ret = 0;

    *codes = 0;

    bn = BN_new();
    if (bn == NULL)
	goto out;

    if (!BN_set_word(bn, 1))
	goto out;

    if (BN_cmp(bn, pub_key) >= 0)
	*codes |= DH_CHECK_PUBKEY_TOO_SMALL;

    sum = BN_new();
    if (sum == NULL)
	goto out;

    BN_uadd(sum, pub_key, bn);

    if (BN_cmp(sum, dh->p) >= 0)
	*codes |= DH_CHECK_PUBKEY_TOO_LARGE;

    ret = 1;
out:
    if (bn)
	BN_free(bn);
    if (sum)
	BN_free(sum);

    return ret;
}

int
DH_generate_key(DH *dh)
{
    return dh->meth->generate_key(dh);
}

int
DH_compute_key(unsigned char *shared_key,
	       const BIGNUM *peer_pub_key, DH *dh)
{
    int codes;

    if (!DH_check_pubkey(dh, peer_pub_key, &codes) || codes != 0)
	return -1;

    return dh->meth->compute_key(shared_key, peer_pub_key, dh);
}

int
DH_set_method(DH *dh, const DH_METHOD *method)
{
    (*dh->meth->finish)(dh);
    if (dh->engine) {
	ENGINE_finish(dh->engine);
	dh->engine = NULL;
    }
    dh->meth = method;
    (*dh->meth->init)(dh);
    return 1;
}

/*
 *
 */

static int
dh_null_generate_key(DH *dh)
{
    return 0;
}

static int
dh_null_compute_key(unsigned char *shared,const BIGNUM *pub, DH *dh)
{
    return 0;
}

static int
dh_null_init(DH *dh)
{
    return 1;
}

static int
dh_null_finish(DH *dh)
{
    return 1;
}

static int
dh_null_generate_params(DH *dh, int prime_num, int len, BN_GENCB *cb)
{
    return 0;
}

static const DH_METHOD dh_null_method = {
    "hcrypto null DH",
    dh_null_generate_key,
    dh_null_compute_key,
    NULL,
    dh_null_init,
    dh_null_finish,
    0,
    NULL,
    dh_null_generate_params
};

extern const DH_METHOD hc_dh_imath_method;
static const DH_METHOD *dh_default_method = &hc_dh_imath_method;

const DH_METHOD *
DH_null_method(void)
{
    return &dh_null_method;
}

void
DH_set_default_method(const DH_METHOD *meth)
{
    dh_default_method = meth;
}

const DH_METHOD *
DH_get_default_method(void)
{
    return dh_default_method;
}

