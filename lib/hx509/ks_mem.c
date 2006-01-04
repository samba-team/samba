/*
 * Copyright (c) 2005 Kungliga Tekniska Högskolan
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
RCSID("Id$");

struct mem_data {
    char *name;
    unsigned long len;
    hx509_cert *val;
};

static int
mem_init(hx509_context context,
	 hx509_certs certs, void **data, int flags,
	 const char *residue, hx509_lock lock)
{
    struct mem_data *mem;
    mem = calloc(1, sizeof(*mem));
    if (mem == NULL)
	return ENOMEM;
    if (residue == NULL || residue[0] == '\0')
	residue = "anonymous";
    mem->name = strdup(residue);
    if (mem->name == NULL) {
	free(mem);
	return ENOMEM;
    }
    *data = mem;
    return 0;
}

static int
mem_free(hx509_certs certs, void *data)
{
    struct mem_data *mem = data;
    unsigned long i;
    
    for (i = 0; i < mem->len; i++)
	hx509_cert_free(mem->val[i]);
    free(mem->val);
    free(mem->name);
    free(mem);

    return 0;
}

static int 
mem_add(hx509_context context, hx509_certs certs, void *data, hx509_cert c)
{
    struct mem_data *mem = data;
    hx509_cert *val;

    val = realloc(mem->val, (mem->len + 1) * sizeof(mem->val[0]));
    if (val == NULL)
	return ENOMEM;

    mem->val = val;
    mem->val[mem->len] = hx509_cert_ref(c);
    mem->len++;

    return 0;
}

static int 
mem_iter_start(hx509_context context,
	       hx509_certs certs,
	       void *data,
	       void **cursor)
{
    unsigned long *iter = malloc(sizeof(*iter));

    if (iter == NULL)
	return ENOMEM;

    *iter = 0;
    *cursor = iter;

    return 0;
}

static int
mem_iter(hx509_context contexst,
	 hx509_certs certs,
	 void *data, 
	 void *cursor,
	 hx509_cert *cert)
{
    unsigned long *iter = cursor;
    struct mem_data *mem = data;

    if (*iter >= mem->len) {
	*cert = NULL;
	return 0;
    }

    *cert = hx509_cert_ref(mem->val[*iter]);
    (*iter)++;
    return 0;
}

static int
mem_iter_end(hx509_context context,
	     hx509_certs certs,
	     void *data,
	     void *cursor)
{
    free(cursor);
    return 0;
}

static struct hx509_keyset_ops keyset_mem = {
    "MEMORY",
    0,
    mem_init,
    mem_free,
    mem_add,
    NULL,
    mem_iter_start,
    mem_iter,
    mem_iter_end
};

void
_hx509_ks_mem_register(hx509_context context)
{
    _hx509_ks_register(context, &keyset_mem);
}
