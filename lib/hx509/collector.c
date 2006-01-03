/*
 * Copyright (c) 2004 - 2006 Kungliga Tekniska Högskolan
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

#include "hx_locl.h"
RCSID("$Id$");
#include <openssl/evp.h>

struct private_key {
    AlgorithmIdentifier alg;
    void *private_key;
    heim_octet_string data;
    heim_octet_string localKeyId;
};

struct hx509_collector {
    hx509_lock lock;
    hx509_certs unenvelop_certs;
    hx509_certs certs;
    struct {
	struct private_key **data;
	size_t len;
    } val;
};


struct hx509_collector *
_hx509_collector_alloc(hx509_lock lock)
{
    struct hx509_collector *c;

    c = calloc(1, sizeof(*c));
    if (c == NULL)
	return NULL;
    c->lock = lock;

    hx509_certs_init("MEMORY:dummy", 0, NULL, &c->unenvelop_certs);
    c->val.data = NULL;
    c->val.len = 0;
    hx509_certs_init("MEMORY:collector-tmp-store", 0, NULL, &c->certs);

    return c;
}

hx509_lock
_hx509_collector_get_lock(struct hx509_collector *c)
{
    return c->lock;
}


int
_hx509_collector_certs_add(struct hx509_collector *c, hx509_cert cert)
{
    return hx509_certs_add(c->certs, cert);
}

static void
free_private_key(struct private_key *key)
{
    free_AlgorithmIdentifier(&key->alg);
    if (key->private_key)
	EVP_PKEY_free(key->private_key);
    free_octet_string(&key->data);
    free_octet_string(&key->localKeyId);
    free(key);
}

int
_hx509_collector_private_key_add(struct hx509_collector *c, 
				 const AlgorithmIdentifier *alg,
				 void *private_key,
				 const heim_octet_string *key_data,
				 const heim_octet_string *localKeyId)
{
    struct private_key *key;
    void *d;
    int ret;

    key = calloc(1, sizeof(*key));
    if (key == NULL)
	return ENOMEM;

    d = realloc(c->val.data, (c->val.len + 1) * sizeof(c->val.data[0]));
    if (d == NULL) {
	free(key);
	return ENOMEM;
    }
    c->val.data = d;
	
    ret = copy_AlgorithmIdentifier(alg, &key->alg);
    if (ret)
	goto out;
    if (private_key) {
	key->private_key = private_key;
    } else {
	ret = copy_octet_string(key_data, &key->data);
	if (ret)
	    goto out;
    }
    ret = copy_octet_string(localKeyId, &key->localKeyId);
    if (ret)
	goto out;

    c->val.data[c->val.len] = key;
    c->val.len++;

out:
    if (ret)
	free_private_key(key);

    return ret;
}

int
_hx509_collector_collect(struct hx509_collector *c, hx509_certs *ret_certs)
{
    hx509_certs certs;
    hx509_cert cert;
    hx509_query q;
    int i, ret;

    *ret_certs = NULL;

    ret = hx509_certs_init("MEMORY:collector-store", 0, NULL, &certs);
    if (ret)
	return ret;

    ret = hx509_certs_merge(certs, c->certs);
    if (ret) {
	hx509_certs_free(&certs);
	return ret;
    }

    for (i = 0; i < c->val.len; i++) {

	_hx509_query_clear(&q);
	q.match |= HX509_QUERY_MATCH_LOCAL_KEY_ID;

	q.local_key_id = &c->val.data[i]->localKeyId;

	ret = _hx509_certs_find(certs, &q, &cert);
	if (ret == 0) {
	    hx509_private_key key;

	    if (c->val.data[i]->private_key) {
		ret = _hx509_new_private_key(&key);
		if (ret == 0) {
		    _hx509_private_key_assign_ptr(key,
						  c->val.data[i]->private_key);
		    c->val.data[i]->private_key = NULL;
		}
	    } else {
		ret = _hx509_parse_private_key(&c->val.data[i]->alg.algorithm,
					       c->val.data[i]->data.data,
					       c->val.data[i]->data.length,
					       &key);
		if (ret == 0)
		    _hx509_cert_assign_key(cert, key);
	    }
	    hx509_certs_add(certs, cert);
	    hx509_cert_free(cert);
	}
    }

    *ret_certs = certs;

    return 0;
}

void
_hx509_collector_free(struct hx509_collector *c)
{
    int i;

    if (c->unenvelop_certs)
	hx509_certs_free(&c->unenvelop_certs);
    if (c->certs)
	hx509_certs_free(&c->certs);
    for (i = 0; i < c->val.len; i++)
	free_private_key(c->val.data[i]);
    if (c->val.data)
	free(c->val.data);
    free(c);
}
