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

struct ks_pkcs12 {
    hx509_certs certs;
};

typedef int (*collector_func)(hx509_context,
			      struct hx509_collector *,
			      const void *, size_t,
			      const PKCS12_Attributes *);

struct type {
    const heim_oid * (*oid)(void);
    collector_func func;
};

static void
parse_pkcs12_type(hx509_context, struct hx509_collector *, const heim_oid *, 
		  const void *, size_t, const PKCS12_Attributes *);


static const PKCS12_Attribute *
find_attribute(const PKCS12_Attributes *attrs, const heim_oid *oid)
{
    int i;
    if (attrs == NULL)
	return NULL;
    for (i = 0; i < attrs->len; i++)
	if (der_heim_oid_cmp(oid, &attrs->val[i].attrId) == 0)
	    return &attrs->val[i];
    return NULL;
}

static int
ShroudedKeyBag_parser(hx509_context context,
		      struct hx509_collector *c, 
		      const void *data, size_t length,
		      const PKCS12_Attributes *attrs)
{
    const PKCS12_Attribute *attr;
    PKCS8EncryptedPrivateKeyInfo pk;
    PKCS8PrivateKeyInfo ki;
    heim_octet_string content;
    int ret;
    
    memset(&pk, 0, sizeof(pk));
    
    attr = find_attribute(attrs, oid_id_pkcs_9_at_localKeyId());
    if (attr == NULL)
	return 0;

    ret = decode_PKCS8EncryptedPrivateKeyInfo(data, length, &pk, NULL);
    if (ret)
	return ret;

    ret = _hx509_pbe_decrypt(context,
			     _hx509_collector_get_lock(c),
			     &pk.encryptionAlgorithm,
			     &pk.encryptedData,
			     &content);
    free_PKCS8EncryptedPrivateKeyInfo(&pk);
    if (ret)
	return ret;

    ret = decode_PKCS8PrivateKeyInfo(content.data, content.length,
				     &ki, NULL);
    der_free_octet_string(&content);
    if (ret)
	return ret;
    
    _hx509_collector_private_key_add(c,
				     &ki.privateKeyAlgorithm,
				     NULL,
				     &ki.privateKey,
				     &attr->attrValues);

    free_PKCS8PrivateKeyInfo(&ki);

    return 0;
}

static int
certBag_parser(hx509_context context,
	       struct hx509_collector *c, 
	       const void *data, size_t length,
	       const PKCS12_Attributes *attrs)
{
    heim_octet_string os;
    Certificate t;
    hx509_cert cert;
    PKCS12_CertBag cb;
    int ret;

    ret = decode_PKCS12_CertBag(data, length, &cb, NULL);
    if (ret)
	return ret;

    ret = decode_PKCS12_OctetString(cb.certValue.data, 
				    cb.certValue.length,
				    &os,
				    NULL);
    free_PKCS12_CertBag(&cb);
    if (ret)
	return ret;

    ret = decode_Certificate(os.data, os.length, &t, NULL);
    der_free_octet_string(&os);
    if (ret)
	return ret;

    ret = hx509_cert_init(context, &t, &cert);
    free_Certificate(&t);
    if (ret)
	return ret;

    ret = _hx509_collector_certs_add(context, c, cert);
    if (ret) {
	hx509_cert_free(cert);
	return ret;
    }

    {
	const PKCS12_Attribute *attr;
	const heim_oid * (*oids[])(void) = {
	    oid_id_pkcs_9_at_localKeyId, oid_id_pkcs_9_at_friendlyName
	};
	int i;

	for (i = 0; i < sizeof(oids)/sizeof(oids[0]); i++) {
	    const heim_oid *oid = (*(oids[i]))();
	    attr = find_attribute(attrs, oid);
	    if (attr)
		_hx509_set_cert_attribute(context, cert, oid, &attr->attrValues);
	}	
    }
    return 0;
}

static int
parse_safe_content(hx509_context context,
		   struct hx509_collector *c, 
		   const unsigned char *p, size_t len)
{
    PKCS12_SafeContents sc;
    int ret, i;

    memset(&sc, 0, sizeof(sc));

    ret = decode_PKCS12_SafeContents(p, len, &sc, NULL);
    if (ret)
	return ret;

    for (i = 0; i < sc.len ; i++)
	parse_pkcs12_type(context,
			  c,
			  &sc.val[i].bagId,
			  sc.val[i].bagValue.data,
			  sc.val[i].bagValue.length,
			  sc.val[i].bagAttributes);

    free_PKCS12_SafeContents(&sc);
    return 0;
}

static int
safeContent_parser(hx509_context context,
		   struct hx509_collector *c, 
		   const void *data, size_t length,
		   const PKCS12_Attributes *attrs)
{
    heim_octet_string os;
    int ret;

    ret = decode_PKCS12_OctetString(data, length, &os, NULL);
    if (ret)
	return ret;
    ret = parse_safe_content(context, c, os.data, os.length);
    der_free_octet_string(&os);
    return ret;
};

static int
encryptedData_parser(hx509_context context,
		     struct hx509_collector *c,
		     const void *data, size_t length,
		     const PKCS12_Attributes *attrs)
{
    heim_octet_string content;
    heim_oid contentType;
    int ret;
		
    memset(&contentType, 0, sizeof(contentType));

    ret = hx509_cms_decrypt_encrypted(context,
				      _hx509_collector_get_lock(c),
				      data, length,
				      &contentType,
				      &content);
    if (ret)
	return ret;

    if (der_heim_oid_cmp(&contentType, oid_id_pkcs7_data()) == 0)
	ret = parse_safe_content(context, c, content.data, content.length);

    der_free_octet_string(&content);
    der_free_oid(&contentType);
    return ret;
}

static int
envelopedData_parser(hx509_context context,
		     struct hx509_collector *c,
		     const void *data, size_t length,
		     const PKCS12_Attributes *attrs)
{
    heim_octet_string content;
    heim_oid contentType;
    hx509_lock lock;
    int ret;
		
    memset(&contentType, 0, sizeof(contentType));

    lock = _hx509_collector_get_lock(c);

    ret = hx509_cms_unenvelope(context,
			       _hx509_lock_unlock_certs(lock),
			       0,
			       data, length,
			       NULL,
			       &contentType,
			       &content);
    if (ret) {
	hx509_set_error_string(context, HX509_ERROR_APPEND, ret, 
			       "PKCS12 failed to unenvelope");
	return ret;
    }

    if (der_heim_oid_cmp(&contentType, oid_id_pkcs7_data()) == 0)
	ret = parse_safe_content(context, c, content.data, content.length);

    der_free_octet_string(&content);
    der_free_oid(&contentType);

    return ret;
}


struct type bagtypes[] = {
    { oid_id_pkcs12_pkcs8ShroudedKeyBag, ShroudedKeyBag_parser },
    { oid_id_pkcs12_certBag, certBag_parser },
    { oid_id_pkcs7_data, safeContent_parser },
    { oid_id_pkcs7_encryptedData, encryptedData_parser },
    { oid_id_pkcs7_envelopedData, envelopedData_parser }
};

static void
parse_pkcs12_type(hx509_context context,
		  struct hx509_collector *c,
		  const heim_oid *oid, 
		  const void *data, size_t length,
		  const PKCS12_Attributes *attrs)
{
    int i;

    for (i = 0; i < sizeof(bagtypes)/sizeof(bagtypes[0]); i++)
	if (der_heim_oid_cmp((*bagtypes[i].oid)(), oid) == 0)
	    (*bagtypes[i].func)(context, c, data, length, attrs);
}

static int
p12_init(hx509_context context,
	 hx509_certs certs, void **data, int flags, 
	 const char *residue, hx509_lock lock)
{
    struct ks_pkcs12 *p12;
    size_t len;
    void *buf;
    PKCS12_PFX pfx;
    PKCS12_AuthenticatedSafe as;
    int ret, i;
    struct hx509_collector *c;

    *data = NULL;

    if (lock == NULL)
	lock = _hx509_empty_lock;

    c = _hx509_collector_alloc(context, lock);
    if (c == NULL)
	return ENOMEM;

    p12 = calloc(1, sizeof(*p12));
    if (p12 == NULL) {
	ret = ENOMEM;
	goto out;
    }

    ret = _hx509_map_file(residue, &buf, &len, NULL);
    if (ret)
	goto out;

    ret = decode_PKCS12_PFX(buf, len, &pfx, NULL);
    _hx509_unmap_file(buf, len);
    if (ret)
	goto out;

    if (der_heim_oid_cmp(&pfx.authSafe.contentType, oid_id_pkcs7_data()) != 0) {
	free_PKCS12_PFX(&pfx);
	ret = EINVAL;
	goto out;
    }

    if (pfx.authSafe.content == NULL) {
	free_PKCS12_PFX(&pfx);
	ret = EINVAL;
	goto out;
    }

    {
	heim_octet_string asdata;

	ret = decode_PKCS12_OctetString(pfx.authSafe.content->data,
					pfx.authSafe.content->length,
					&asdata,
					NULL);
	free_PKCS12_PFX(&pfx);
	if (ret)
	    goto out;
	ret = decode_PKCS12_AuthenticatedSafe(asdata.data, 
					      asdata.length,
					      &as,
					      NULL);
	der_free_octet_string(&asdata);
	if (ret)
	    goto out;
    }

    for (i = 0; i < as.len; i++)
	parse_pkcs12_type(context,
			  c,
			  &as.val[i].contentType,
			  as.val[i].content->data,
			  as.val[i].content->length,
			  NULL);

    free_PKCS12_AuthenticatedSafe(&as);

    ret = _hx509_collector_collect(context, c, &p12->certs);
    if (ret == 0)
	*data = p12;

out:
    _hx509_collector_free(c);

    if (ret) {
	if (p12->certs)
	    hx509_certs_free(&p12->certs);
	free(p12);
    }

    return ret;
}

static int
p12_free(hx509_certs certs, void *data)
{
    struct ks_pkcs12 *p12 = data;
    hx509_certs_free(&p12->certs);
    free(p12);
    return 0;
}

static int 
p12_iter_start(hx509_context context,
	       hx509_certs certs,
	       void *data,
	       void **cursor)
{
    struct ks_pkcs12 *p12 = data;
    return hx509_certs_start_seq(context, p12->certs, cursor);
}

static int
p12_iter(hx509_context context,
	 hx509_certs certs,
	 void *data,
	 void *cursor,
	 hx509_cert *cert)
{
    struct ks_pkcs12 *p12 = data;
    return hx509_certs_next_cert(context, p12->certs, cursor, cert);
}

static int
p12_iter_end(hx509_context context,
	     hx509_certs certs,
	     void *data,
	     void *cursor)
{
    struct ks_pkcs12 *p12 = data;
    return hx509_certs_end_seq(context, p12->certs, cursor);
}

static struct hx509_keyset_ops keyset_pkcs12 = {
    "PKCS12",
    0,
    p12_init,
    p12_free,
    NULL,
    NULL,
    p12_iter_start,
    p12_iter,
    p12_iter_end
};

void
_hx509_ks_pkcs12_register(hx509_context context)
{
    _hx509_ks_register(context, &keyset_pkcs12);
}
