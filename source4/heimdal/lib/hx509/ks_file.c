/*
 * Copyright (c) 2005 - 2007 Kungliga Tekniska Högskolan
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
RCSID("$Id: ks_file.c,v 1.31 2007/01/09 10:52:08 lha Exp $");

struct ks_file {
    hx509_certs certs;
    char *fn;
};

struct header {
    char *header;
    char *value;
    struct header *next;
};

static int
add_headers(struct header **headers, const char *header, const char *value)
{
    struct header *h;
    h = calloc(1, sizeof(*h));
    if (h == NULL)
	return ENOMEM;
    h->header = strdup(header);
    if (h->header == NULL) {
	free(h);
	return ENOMEM;
    }
    h->value = strdup(value);
    if (h->value == NULL) {
	free(h->header);
	free(h);
	return ENOMEM;
    }

    h->next = *headers;
    *headers = h;

    return 0;
}

static void
free_headers(struct header *headers)
{
    struct header *h;
    while (headers) {
	h = headers;
	headers = headers->next;
	free(h->header);
	free(h->value);
	free(h);
    }
}

static const char *
find_header(const struct header *headers, const char *header)
{
    while(headers) {
	if (strcmp(header, headers->header) == 0)
	    return headers->value;
	headers = headers->next;
    }
    return NULL;
}

/*
 *
 */

static int
parse_certificate(hx509_context context, const char *fn, 
		  struct hx509_collector *c, 
		  const struct header *headers,
		  const void *data, size_t len)
{
    hx509_cert cert;
    Certificate t;
    size_t size;
    int ret;

    ret = decode_Certificate(data, len, &t, &size);
    if (ret) {
	hx509_set_error_string(context, 0, ret, 
			       "Failed to parse certificate in %s",
			       fn);
	return ret;
    }

    ret = hx509_cert_init(context, &t, &cert);
    free_Certificate(&t);
    if (ret)
	return ret;

    ret = _hx509_collector_certs_add(context, c, cert);
    hx509_cert_free(cert);
    return ret;
}

static int
try_decrypt(hx509_context context,
	    struct hx509_collector *collector,
	    const AlgorithmIdentifier *alg,
	    const EVP_CIPHER *c,
	    const void *ivdata,
	    const void *password,
	    size_t passwordlen,
	    const void *cipher,
	    size_t len)
{
    heim_octet_string clear;
    size_t keylen;
    void *key;
    int ret;

    keylen = EVP_CIPHER_key_length(c);

    key = malloc(keylen);
    if (key == NULL) {
	hx509_clear_error_string(context);
	return ENOMEM;
    }

    ret = EVP_BytesToKey(c, EVP_md5(), ivdata,
			 password, passwordlen,
			 1, key, NULL);
    if (ret <= 0) {
	hx509_set_error_string(context, 0, HX509_CRYPTO_INTERNAL_ERROR,
			       "Failed to do string2key for private key");
	return HX509_CRYPTO_INTERNAL_ERROR;
    }

    clear.data = malloc(len);
    if (clear.data == NULL) {
	hx509_set_error_string(context, 0, ENOMEM,
			       "Out of memory to decrypt for private key");
	ret = ENOMEM;
	goto out;
    }
    clear.length = len;

    {
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, c, NULL, key, ivdata, 0);
	EVP_Cipher(&ctx, clear.data, cipher, len);
	EVP_CIPHER_CTX_cleanup(&ctx);
    }	

    ret = _hx509_collector_private_key_add(context,
					   collector,
					   alg,
					   NULL,
					   &clear,
					   NULL);

    memset(clear.data, 0, clear.length);
    free(clear.data);
out:
    memset(key, 0, keylen);
    free(key);
    return ret;
}

static int
parse_rsa_private_key(hx509_context context, const char *fn,
		      struct hx509_collector *c, 
		      const struct header *headers,
		      const void *data, size_t len)
{
    int ret = 0;
    const char *enc;

    enc = find_header(headers, "Proc-Type");
    if (enc) {
	const char *dek;
	char *type, *iv;
	ssize_t ssize, size;
	void *ivdata;
	const EVP_CIPHER *cipher;
	const struct _hx509_password *pw;
	hx509_lock lock;
	int i, decrypted = 0;

	lock = _hx509_collector_get_lock(c);
	if (lock == NULL) {
	    hx509_set_error_string(context, 0, HX509_ALG_NOT_SUPP,
				   "Failed to get password for "
				   "password protected file %s", fn);
	    return HX509_ALG_NOT_SUPP;
	}

	if (strcmp(enc, "4,ENCRYPTED") != 0) {
	    hx509_set_error_string(context, 0, HX509_PARSING_KEY_FAILED,
				   "RSA key encrypted in unknown method %s "
				   "in file",
				   enc, fn);
	    hx509_clear_error_string(context);
	    return HX509_PARSING_KEY_FAILED;
	}

	dek = find_header(headers, "DEK-Info");
	if (dek == NULL) {
	    hx509_set_error_string(context, 0, HX509_PARSING_KEY_FAILED,
				   "Encrypted RSA missing DEK-Info");
	    return HX509_PARSING_KEY_FAILED;
	}

	type = strdup(dek);
	if (type == NULL) {
	    hx509_clear_error_string(context);
	    return ENOMEM;
	}

	iv = strchr(type, ',');
	if (iv)
	    *iv++ = '\0';

	size = strlen(iv);
	ivdata = malloc(size);
	if (ivdata == NULL) {
	    hx509_clear_error_string(context);
	    free(type);
	    return ENOMEM;
	}

	cipher = EVP_get_cipherbyname(type);
	if (cipher == NULL) {
	    free(ivdata);
	    hx509_set_error_string(context, 0, HX509_ALG_NOT_SUPP,
				   "RSA key encrypted with "
				   "unsupported cipher: %s",
				   type);
	    free(type);
	    return HX509_ALG_NOT_SUPP;
	}

#define PKCS5_SALT_LEN 8

	ssize = hex_decode(iv, ivdata, size);
	free(type);
	type = NULL;
	iv = NULL;

	if (ssize < 0 || ssize < PKCS5_SALT_LEN || ssize < EVP_CIPHER_iv_length(cipher)) {
	    free(ivdata);
	    hx509_set_error_string(context, 0, HX509_PARSING_KEY_FAILED,
				   "Salt have wrong length in RSA key file");
	    return HX509_PARSING_KEY_FAILED;
	}
	
	pw = _hx509_lock_get_passwords(lock);
	if (pw != NULL) {
	    const void *password;
	    size_t passwordlen;

	    for (i = 0; i < pw->len; i++) {
		password = pw->val[i];
		passwordlen = strlen(password);
		
		ret = try_decrypt(context, c, hx509_signature_rsa(),
				  cipher, ivdata, password, passwordlen,
				  data, len);
		if (ret == 0) {
		    decrypted = 1;
		    break;
		}
	    }
	}
	if (!decrypted) {
	    hx509_prompt prompt;
	    char password[128];

	    memset(&prompt, 0, sizeof(prompt));

	    prompt.prompt = "Password for keyfile: ";
	    prompt.type = HX509_PROMPT_TYPE_PASSWORD;
	    prompt.reply.data = password;
	    prompt.reply.length = sizeof(password);

	    ret = hx509_lock_prompt(lock, &prompt);
	    if (ret == 0)
		ret = try_decrypt(context, c, hx509_signature_rsa(),
				  cipher, ivdata, password, strlen(password),
				  data, len);
	    /* XXX add password to lock password collection ? */
	    memset(password, 0, sizeof(password));
	}
	free(ivdata);

    } else {
	heim_octet_string keydata;

	keydata.data = rk_UNCONST(data);
	keydata.length = len;

	ret = _hx509_collector_private_key_add(context,
					       c,
					       hx509_signature_rsa(),
					       NULL,
					       &keydata,
					       NULL);
    }

    return ret;
}


struct pem_formats {
    const char *name;
    int (*func)(hx509_context, const char *, struct hx509_collector *, 
		const struct header *, const void *, size_t);
} formats[] = {
    { "CERTIFICATE", parse_certificate },
    { "RSA PRIVATE KEY", parse_rsa_private_key }
};


static int
parse_pem_file(hx509_context context, 
	       const char *fn,
	       struct hx509_collector *c,
	       int *found_data)
{
    struct header *headers = NULL;
    char *type = NULL;
    void *data = NULL;
    size_t len = 0;
    char buf[1024];
    int ret;
    FILE *f;


    enum { BEFORE, SEARCHHEADER, INHEADER, INDATA, DONE } where;

    where = BEFORE;
    *found_data = 0;

    if ((f = fopen(fn, "r")) == NULL) {
	hx509_set_error_string(context, 0, ENOENT, 
			       "Failed to open PEM file \"%s\": %s", 
			       fn, strerror(errno));
	return ENOENT;
    }
    ret = 0;

    while (fgets(buf, sizeof(buf), f) != NULL) {
	char *p;
	int i;

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
	    
	switch (where) {
	case BEFORE:
	    if (strncmp("-----BEGIN ", buf, 11) == 0) {
		type = strdup(buf + 11);
		if (type == NULL)
		    break;
		p = strchr(type, '-');
		if (p)
		    *p = '\0';
		*found_data = 1;
		where = SEARCHHEADER;
	    }
	    break;
	case SEARCHHEADER:
	    p = strchr(buf, ':');
	    if (p == NULL) {
		where = INDATA;
		goto indata;
	    }
	    /* FALLTHOUGH */
	case INHEADER:
	    if (buf[0] == '\0') {
		where = INDATA;
		break;
	    }
	    p = strchr(buf, ':');
	    if (p) {
		*p++ = '\0';
		while (isspace((int)*p))
		    p++;
		add_headers(&headers, buf, p);
	    }
	    break;
	case INDATA:
	indata:

	    if (strncmp("-----END ", buf, 9) == 0) {
		where = DONE;
		break;
	    }

	    p = emalloc(i);
	    i = base64_decode(buf, p);
	    if (i < 0) {
		free(p);
		goto out;
	    }
	    
	    data = erealloc(data, len + i);
	    memcpy(((char *)data) + len, p, i);
	    free(p);
	    len += i;
	    break;
	case DONE:
	    abort();
	}

	if (where == DONE) {
	    int j;

	    for (j = 0; j < sizeof(formats)/sizeof(formats[0]); j++) {
		const char *q = formats[j].name;
		if (strcasecmp(type, q) == 0) {
		    ret = (*formats[j].func)(context, fn, c, 
					     headers, data, len);
		    break;
		}
	    }
	    if (j == sizeof(formats)/sizeof(formats[0])) {
		ret = HX509_UNSUPPORTED_OPERATION;
		hx509_set_error_string(context, 0, ret,
				       "Found no matching PEM format for %s",
				       type);
	    }
	out:
	    free(data);
	    data = NULL;
	    len = 0;
	    free(type);
	    type = NULL;
	    where = BEFORE;
	    free_headers(headers);
	    headers = NULL;
	    if (ret)
		break;
	}
    }

    fclose(f);

    if (where != BEFORE) {
	hx509_set_error_string(context, 0, HX509_PARSING_KEY_FAILED,
			       "File ends before end of PEM end tag");
	ret = HX509_PARSING_KEY_FAILED;
    }
    if (data)
	free(data);
    if (type)
	free(type);
    if (headers)
	free_headers(headers);

    return ret;
}

/*
 *
 */

static int
file_init(hx509_context context,
	  hx509_certs certs, void **data, int flags, 
	  const char *residue, hx509_lock lock)
{
    char *p, *pnext;
    struct ks_file *f = NULL;
    struct hx509_collector *c = NULL;
    hx509_private_key *keys = NULL;
    int ret;

    *data = NULL;

    if (lock == NULL)
	lock = _hx509_empty_lock;

    f = calloc(1, sizeof(*f));
    if (f == NULL) {
	hx509_clear_error_string(context);
	return ENOMEM;
    }

    f->fn = strdup(residue);
    if (f->fn == NULL) {
	hx509_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }

    /* 
     * XXX this is broken, the function should parse the file before
     * overwriting it
     */

    if (flags & HX509_CERTS_CREATE) {
	ret = hx509_certs_init(context, "MEMORY:ks-file-create", 
			       0, lock, &f->certs);
	if (ret)
	    goto out;
	*data = f;
	return 0;
    }

    c = _hx509_collector_alloc(context, lock);
    if (c == NULL) {
	ret = ENOMEM;
	hx509_set_error_string(context, 0, ret, "out of memory");
	goto out;
    }

    for (p = f->fn; p != NULL; p = pnext) {
	int found_data;

	pnext = strchr(p, ',');
	if (pnext)
	    *pnext++ = '\0';
	
	ret = parse_pem_file(context, p, c, &found_data);
	if (ret)
	    goto out;

	if (!found_data) {
	    size_t length;
	    void *ptr;
	    int i;

	    ret = _hx509_map_file(p, &ptr, &length, NULL);
	    if (ret) {
		hx509_clear_error_string(context);
		goto out;
	    }

	    for (i = 0; i < sizeof(formats)/sizeof(formats[0]); i++) {
		ret = (*formats[i].func)(context, p, c, NULL, ptr, length);
		if (ret == 0)
		    break;
	    }
	    _hx509_unmap_file(ptr, length);
	    if (ret)
		goto out;
	}
    }

    ret = _hx509_collector_collect_certs(context, c, &f->certs);
    if (ret)
	goto out;

    ret = _hx509_collector_collect_private_keys(context, c, &keys);
    if (ret == 0) {
	int i;

	for (i = 0; keys[i]; i++)
	    _hx509_certs_keys_add(context, f->certs, keys[i]);
	_hx509_certs_keys_free(context, keys);
    }

out:
    if (ret == 0)
	*data = f;
    else {
	if (f->fn)
	    free(f->fn);
	free(f);
    }
    if (c)
	_hx509_collector_free(c);
    return ret;
}

static int
file_free(hx509_certs certs, void *data)
{
    struct ks_file *f = data;
    hx509_certs_free(&f->certs);
    free(f->fn);
    free(f);
    return 0;
}

static void
pem_header(FILE *f, const char *type, const char *str)
{
    fprintf(f, "-----%s %s-----\n", type, str);
}

static int
dump_pem_file(hx509_context context, const char *header,
	      FILE *f, const void *data, size_t size)
{
    const char *p = data;
    size_t length;
    char *line;

#define ENCODE_LINE_LENGTH	54
    
    pem_header(f, "BEGIN", header);

    while (size > 0) {
	ssize_t l;
	
	length = size;
	if (length > ENCODE_LINE_LENGTH)
	    length = ENCODE_LINE_LENGTH;
	
	l = base64_encode(p, length, &line);
	if (l < 0) {
	    hx509_set_error_string(context, 0, ENOMEM,
				   "malloc - out of memory");
	    return ENOMEM;
	}
	size -= length;
	fprintf(f, "%s\n", line);
	p += length;
	free(line);
    }

    pem_header(f, "END", header);

    return 0;
}

static int
store_private_key(hx509_context context, FILE *f, hx509_private_key key)
{
    heim_octet_string data;
    int ret;

    ret = _hx509_private_key_export(context, key, &data);
    if (ret == 0)
	dump_pem_file(context, _hx509_private_pem_name(key), f,
		      data.data, data.length);
    free(data.data);
    return ret;
}

static int
store_func(hx509_context context, void *ctx, hx509_cert c)
{
    FILE *f = (FILE *)ctx;
    size_t size;
    heim_octet_string data;
    int ret;

    ASN1_MALLOC_ENCODE(Certificate, data.data, data.length, 
		       _hx509_get_cert(c), &size, ret);
    if (ret)
	return ret;
    if (data.length != size)
	_hx509_abort("internal ASN.1 encoder error");
    
    dump_pem_file(context, "CERTIFICATE", f, data.data, data.length);
    free(data.data);

    if (_hx509_cert_private_key_exportable(c))
	store_private_key(context, f, _hx509_cert_private_key(c));

    return 0;
}

static int
file_store(hx509_context context, 
	   hx509_certs certs, void *data, int flags, hx509_lock lock)
{
    struct ks_file *f = data;
    FILE *fh;
    int ret;

    fh = fopen(f->fn, "w");
    if (fh == NULL) {
	hx509_set_error_string(context, 0, ENOENT,
			       "Failed to open file %s for writing");
	return ENOENT;
    }

    ret = hx509_certs_iter(context, f->certs, store_func, fh);
    fclose(fh);
    return ret;
}

static int 
file_add(hx509_context context, hx509_certs certs, void *data, hx509_cert c)
{
    struct ks_file *f = data;
    return hx509_certs_add(context, f->certs, c);
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

static int
file_getkeys(hx509_context context,
	     hx509_certs certs,
	     void *data,
	     hx509_private_key **keys)
{
    struct ks_file *f = data;
    return _hx509_certs_keys_get(context, f->certs, keys);
}

static int
file_addkey(hx509_context context,
	     hx509_certs certs,
	     void *data,
	     hx509_private_key key)
{
    struct ks_file *f = data;
    return _hx509_certs_keys_add(context, f->certs, key);
}

static struct hx509_keyset_ops keyset_file = {
    "FILE",
    0,
    file_init,
    file_store,
    file_free,
    file_add,
    NULL,
    file_iter_start,
    file_iter,
    file_iter_end,
    NULL,
    file_getkeys,
    file_addkey
};

void
_hx509_ks_file_register(hx509_context context)
{
    _hx509_ks_register(context, &keyset_file);
}
