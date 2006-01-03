/*
 * Copyright (c) 2004 - 2005 Kungliga Tekniska Högskolan
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

struct private_key {
    AlgorithmIdentifier alg;
    heim_octet_string data;
    heim_octet_string localKeyId;
};

struct collector {
    hx509_lock lock;
    hx509_certs unenvelop_certs;
    hx509_certs certs;
    struct {
	struct private_key **data;
	size_t len;
    } val;
};

typedef int (*collector_func)(struct collector *, const void *, size_t,
			      const PKCS12_Attributes *);

struct type {
    const heim_oid * (*oid)(void);
    collector_func func;
};

static int
parse_pkcs12_type(struct collector *, const heim_oid *, 
		  const void *, size_t, const PKCS12_Attributes *);


static const PKCS12_Attribute *
find_attribute(const PKCS12_Attributes *attrs, const heim_oid *oid)
{
    int i;
    if (attrs == NULL)
	return NULL;
    for (i = 0; i < attrs->len; i++)
	if (heim_oid_cmp(oid, &attrs->val[i].attrId) == 0)
	    return &attrs->val[i];
    return NULL;
}

static int
ShroudedKeyBag_parser(struct collector *c, const void *data, size_t length,
		      const PKCS12_Attributes *attrs)
{
    struct private_key *key;
    const PKCS12_Attribute *attr;
    PKCS8EncryptedPrivateKeyInfo pk;
    PKCS8PrivateKeyInfo ki;
    heim_octet_string content;
    int ret;
    
    printf("pkcs8ShroudedKeyBag\n");
    memset(&pk, 0, sizeof(pk));
    
    attr = find_attribute(attrs, oid_id_pkcs_9_at_localKeyId());
    if (attr == NULL) {
	printf("no localKeyId, ignoreing private key\n");
	return 0;
    }

    ret = decode_PKCS8EncryptedPrivateKeyInfo(data, length, &pk, NULL);
    if (ret) {
	printf("PKCS8EncryptedPrivateKeyInfo returned %d\n", ret);
	return ret;
    }

    ret = _hx509_pbe_decrypt(c->lock,
			     &pk.encryptionAlgorithm,
			     &pk.encryptedData,
			     &content);
    free_PKCS8EncryptedPrivateKeyInfo(&pk);
    if (ret) {
	printf("decrypt encryped failed %d\n", ret);
	return ret;
    }
    ret = decode_PKCS8PrivateKeyInfo(content.data, content.length,
				     &ki, NULL);
    free_octet_string(&content);
    if (ret) {
	printf("PKCS8PrivateKeyInfo returned %d\n", ret);
	return ret;
    }
    
    key = malloc(sizeof(*key));
    if (key == NULL) {
	free_PKCS8PrivateKeyInfo(&ki);
	return ENOMEM;
    }

    copy_AlgorithmIdentifier(&ki.privateKeyAlgorithm, &key->alg);
    copy_octet_string(&ki.privateKey, &key->data);
    copy_octet_string(&attr->attrValues, &key->localKeyId);
    free_PKCS8PrivateKeyInfo(&ki);

    {
	void *d;
	d = realloc(c->val.data, (c->val.len + 1) * sizeof(c->val.data[0]));
	if (d == NULL) {
	    _hx509_abort("allocation failure"); /* XXX */
	}
	c->val.data = d;
	c->val.data[c->val.len] = key;
	c->val.len++;
    }
    return 0;
}

static int
certBag_parser(struct collector *c, const void *data, size_t length,
	       const PKCS12_Attributes *attrs)
{
    heim_octet_string os;
    Certificate t;
    hx509_cert cert;
    PKCS12_CertBag cb;
    int ret;

    printf("certBag\n");

    ret = decode_PKCS12_CertBag(data, length, &cb, NULL);
    if (ret)
	return ret;

    {
	char *str;
	hx509_oid_sprint(&cb.certType, &str);
	printf("oid: %s\n", str);
    }

    ret = decode_PKCS12_OctetString(cb.certValue.data, 
				    cb.certValue.length,
				    &os,
				    NULL);
    free_PKCS12_CertBag(&cb);
    if (ret) {
	printf("failed with %d\n", ret);
	return 1;
    }

    ret = decode_Certificate(os.data, os.length, &t, NULL);
    free_octet_string(&os);
    if (ret) {
	printf("failed with %d\n", ret);
	return 1;
    }
    printf("cert parsed ok\n");

    ret = hx509_cert_init(&t, &cert);
    free_Certificate(&t);
    if (ret) {
	return ret;
    }

    ret = hx509_certs_add(c->certs, cert);
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
		_hx509_set_cert_attribute(cert, oid, &attr->attrValues);
	}	
    }
    {
	const char *s = hx509_cert_get_friendly_name(cert);
	if (s)
	    printf("cert name: %s\n", s);
    }

    return 0;
}

static int
parse_safe_content(struct collector *c, const unsigned char *p, size_t len)
{
    PKCS12_SafeContents sc;
    int ret, i;

    memset(&sc, 0, sizeof(sc));

    ret = decode_PKCS12_SafeContents(p, len, &sc, NULL);
    if (ret)
	return ret;

    for (i = 0; i < sc.len ; i++)
	parse_pkcs12_type(c,
			  &sc.val[i].bagId,
			  sc.val[i].bagValue.data,
			  sc.val[i].bagValue.length,
			  sc.val[i].bagAttributes);

    free_PKCS12_SafeContents(&sc);
    return 0;
}

static int
safeContent_parser(struct collector *c, const void *data, size_t length,
	       const PKCS12_Attributes *attrs)
{
    heim_octet_string os;
    int ret;

    printf("safeContent\n");

    ret = decode_PKCS12_OctetString(data, length, &os, NULL);
    if (ret)
	return 1;
    ret = parse_safe_content(c, os.data, os.length);
    free_octet_string(&os);
    return ret;
};

static int
encryptedData_parser(struct collector *c, const void *data, size_t length,
	       const PKCS12_Attributes *attrs)
{
    heim_octet_string content;
    heim_oid contentType;
    int ret;
		
    memset(&contentType, 0, sizeof(contentType));

    ret = hx509_cms_decrypt_encrypted(c->lock,
				      data, length,
				      &contentType,
				      &content);
    if (ret)
	printf("decrypt encryped failed %d\n", ret);
    else {
	if (content.length == 0) {
	    printf("no content in encryped data\n");
	} else if (heim_oid_cmp(&contentType, oid_id_pkcs7_data()) == 0) {
	    ret = parse_safe_content(c, content.data, content.length);
	    if (ret)
		printf("parse_safe_content failed with %d\n", ret);
	}
    }

    return 0;
}

static int
envelopedData_parser(struct collector *c, const void *data, size_t length,
		     const PKCS12_Attributes *attrs)
{
    heim_octet_string content;
    heim_oid contentType;
    int ret;
		
    memset(&contentType, 0, sizeof(contentType));

    ret = hx509_cms_unenvelope(c->unenvelop_certs,
			       data, length,
			       &contentType,
			       &content);
    if (ret)
	printf("unenveloped failed %d\n", ret);
    else {
	if (content.length == 0) {
	    printf("no content enveloped data\n");
	} else if (heim_oid_cmp(&contentType, oid_id_pkcs7_data()) == 0) {
	    ret = parse_safe_content(c, content.data, content.length);
	    if (ret)
		printf("parse_safe_content failed with %d\n", ret);
	}
    }

    return 0;
}


struct type bagtypes[] = {
    { oid_id_pkcs12_pkcs8ShroudedKeyBag, ShroudedKeyBag_parser },
    { oid_id_pkcs12_certBag, certBag_parser },
    { oid_id_pkcs7_data, safeContent_parser },
    { oid_id_pkcs7_encryptedData, encryptedData_parser },
    { oid_id_pkcs7_envelopedData, envelopedData_parser }
};

static int
parse_pkcs12_type(struct collector *c, const heim_oid *oid, 
		  const void *data, size_t length,
		  const PKCS12_Attributes *attrs)
{
    int i;

    for (i = 0; i < sizeof(bagtypes)/sizeof(bagtypes[0]); i++) {
	if (heim_oid_cmp((*bagtypes[i].oid)(), oid) == 0) {
	    (*bagtypes[i].func)(c, data, length, attrs);
	    return 0;
	}
    }
    return 1;
}

static int
p12_init(hx509_certs certs, void **data, int flags, 
	 const char *residue, hx509_lock lock)
{
    size_t len;
    void *buf;
    PKCS12_PFX pfx;
    PKCS12_AuthenticatedSafe as;
    int ret, i;
    struct collector c;

    *data = NULL;

    if (lock == NULL)
	lock = _hx509_empty_lock;

    ret = _hx509_map_file(residue, &buf, &len);
    if (ret)
	return ret;

    ret = decode_PKCS12_PFX(buf, len, &pfx, NULL);
    _hx509_unmap_file(buf, len);
    if (ret)
	return ret;

    if (heim_oid_cmp(&pfx.authSafe.contentType, oid_id_pkcs7_data()) != 0) {
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
	free_octet_string(&asdata);
	if (ret)
	    goto out;
    }

    c.lock = lock;
    hx509_certs_init("MEMORY:dummy", 0, NULL, &c.unenvelop_certs);
    c.val.data = NULL;
    c.val.len = 0;
    hx509_certs_init("MEMORY:pkcs12-store", 0, NULL, &c.certs);

    for (i = 0; i < as.len; i++) {
	parse_pkcs12_type(&c,
			  &as.val[i].contentType,
			  as.val[i].content->data,
			  as.val[i].content->length,
			  NULL);
    }

    free_PKCS12_AuthenticatedSafe(&as);

    printf("found %lu private keys\n", (unsigned long)c.val.len);

    for (i = 0; i < c.val.len; i++) {
	hx509_cert cert;
	hx509_query q;

	_hx509_query_clear(&q);
	q.match |= HX509_QUERY_MATCH_LOCAL_KEY_ID;

	q.local_key_id = &c.val.data[i]->localKeyId;

	ret = _hx509_certs_find(c.certs, &q, &cert);
	if (ret == 0) {
	    hx509_private_key key;

	    ret = _hx509_parse_private_key(&c.val.data[i]->alg.algorithm,
					   c.val.data[i]->data.data,
					   c.val.data[i]->data.length,
					   &key);
	    if (ret == 0)
		_hx509_cert_assign_key(cert, key);
	    else
		printf("failed to parse key: %d\n", ret);

	    hx509_cert_free(cert);
	}
	free_octet_string(&c.val.data[i]->localKeyId);
	free_octet_string(&c.val.data[i]->data);
	free_AlgorithmIdentifier(&c.val.data[i]->alg);
	free(c.val.data[i]);
    }
    free(c.val.data);

    {
	struct ks_pkcs12 *p12;
	p12 = malloc(sizeof(*p12));
	if (p12 == NULL) {
	    _hx509_abort("allocation failure"); /* XXX */
	}
	memset(p12, 0, sizeof(*p12));
	p12->certs = c.certs;
	*data = p12;
    }
    ret = 0;
 out:
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
p12_iter_start(hx509_certs certs, void *data, void **cursor)
{
    struct ks_pkcs12 *p12 = data;
    return hx509_certs_start_seq(p12->certs, cursor);
}

static int
p12_iter(hx509_certs certs, void *data, void *cursor, hx509_cert *cert)
{
    struct ks_pkcs12 *p12 = data;
    return hx509_certs_next_cert(p12->certs, cursor, cert);
}

static int
p12_iter_end(hx509_certs certs,
	      void *data,
	      void *cursor)
{
    struct ks_pkcs12 *p12 = data;
    return hx509_certs_end_seq(p12->certs, cursor);
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
_hx509_ks_pkcs12_register(void)
{
    _hx509_ks_register(&keyset_pkcs12);
}
