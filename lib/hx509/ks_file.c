/*
 * Copyright (c) 2005 - 2006 Kungliga Tekniska Högskolan
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

struct ks_file {
    hx509_certs certs;
};

static int
parse_file_pem(const char *fn, Certificate *t)
{
    char buf[1024];
    void *data = NULL;
    size_t size, len = 0;
    int in_cert = 0;
    FILE *f;
    int i, ret;

    memset(t, 0, sizeof(*t));

    if ((f = fopen(fn, "r")) == NULL)
	return ENOENT;

    while (fgets(buf, sizeof(buf), f) != NULL) {
	char *p;

	i = strcspn(buf, "\n");
	if (buf[i] == '\n') {
	    buf[i] = '\0';
	    if (i > 0)
		i--;
	}
	if (buf[i] == '\r') {
	    buf[i] = '\0';
	    if (i > 0)
		i--;
	}
	    
	if (i == 26
	    && strcmp("-----BEGIN CERTIFICATE-----", buf) == 0)
	{
	    in_cert = 1;
	    continue;
	} else if (i == 24 &&
		   strcmp("-----END CERTIFICATE-----", buf) == 0)
	{
	    in_cert = 0;
	    continue;
	}
	if (in_cert == 0)
	    continue;

	p = malloc(i);
	i = base64_decode(buf, p);
	    
	data = erealloc(data, len + i);
	memcpy(((char *)data) + len, p, i);
	free(p);
	len += i;
    }

    fclose(f);

    if (data == NULL)
	return ENOENT;

    if (data && in_cert) {
	free(data);
	return EINVAL;
    }

    ret = decode_Certificate(data, len, t, &size);
    free(data);
    return ret;
}

static int
parse_file_der(const char *fn, Certificate *t)
{
    size_t length, size;
    void *data;
    int ret;

    ret = _hx509_map_file(fn, &data, &length);
    if (ret)
	return ret;

    ret = decode_Certificate(data, length, t, &size);
    _hx509_unmap_file(data, length);
    return ret;
}

int
_hx509_file_to_cert(hx509_context context, const char *certfn, hx509_cert *cert)
{
    Certificate t;
    int ret;
    
    ret = parse_file_pem(certfn, &t);
    if (ret)
	ret = parse_file_der(certfn, &t);
    if (ret)
	return ret;
    
    ret = hx509_cert_init(context, &t, cert);
    free_Certificate(&t);

    return ret;
}


static int
file_init(hx509_context context,
	  hx509_certs certs, void **data, int flags, 
	  const char *residue, hx509_lock lock)
{
    char *certfn = NULL, *keyfn, *friendlyname = NULL;
    hx509_cert cert;
    int ret;
    struct ks_file *f;
    struct hx509_collector *c;

    *data = NULL;

    if (lock == NULL)
	lock = _hx509_empty_lock;

    c = _hx509_collector_alloc(context, lock);
    if (c == NULL)
	return ENOMEM;

    f = calloc(1, sizeof(*f));
    if (f == NULL) {
	ret = ENOMEM;
	goto out;
    }

    certfn = strdup(residue);
    if (certfn == NULL)
	return ENOMEM;
    keyfn = strchr(certfn, ',');
    if (keyfn) {
	*keyfn++ = '\0';
	friendlyname = strchr(keyfn, ',');
	if (friendlyname)
	    *friendlyname++ = '\0';
    }

    ret = _hx509_file_to_cert(context, certfn, &cert);
    if (ret)
	goto out;

    _hx509_collector_certs_add(context, c, cert);

    if (keyfn) {
	ret = _hx509_cert_assign_private_key_file(cert, lock, keyfn);
	if (ret)
	    goto out;
    }
    if (friendlyname) {
	ret = hx509_cert_set_friendly_name(cert, friendlyname);
	if (ret)
	    goto out;
    }

    ret = _hx509_collector_collect(context, c, &f->certs);
    if (ret == 0)
	*data = f;
out:
    _hx509_collector_free(c);
    if (certfn)
	free(certfn);

    if (ret) {
	if (f->certs)
	    hx509_certs_free(&f->certs);
	free(f);
    }

    return ret;
}

static int
file_free(hx509_certs certs, void *data)
{
    struct ks_file *f = data;
    hx509_certs_free(&f->certs);
    free(f);
    return 0;
}



static int 
file_iter_start(hx509_context context,
		hx509_certs certs, void *data, void **cursor)
{
    struct ks_file *f = data;
    return hx509_certs_start_seq(context, f->certs, cursor);
}

static int
file_iter(hx509_context context,
	  hx509_certs certs, void *data, void *iter, hx509_cert *cert)
{
    struct ks_file *f = data;
    return hx509_certs_next_cert(context, f->certs, iter, cert);
}

static int
file_iter_end(hx509_context context,
	      hx509_certs certs,
	      void *data,
	      void *cursor)
{
    struct ks_file *f = data;
    return hx509_certs_end_seq(context, f->certs, cursor);
}


static struct hx509_keyset_ops keyset_file = {
    "FILE",
    0,
    file_init,
    file_free,
    NULL,
    NULL,
    file_iter_start,
    file_iter,
    file_iter_end
};

void
_hx509_ks_file_register(hx509_context context)
{
    _hx509_ks_register(context, &keyset_file);
}
