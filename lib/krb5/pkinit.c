/*
 * Copyright (c) 2003 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"

RCSID("$Id$");

#ifdef PKINIT

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

#include <dirent.h>

#include "heim_asn1.h"
#include "rfc2459_asn1.h"
#include "cms_asn1.h"
#include "pkinit_asn1.h"

#define KRB5_AP_ERR_NO_CERT_OR_KEY EINVAL
#define KRB5_AP_ERR_NO_VALID_CA EINVAL
#define KRB5_AP_ERR_CERT EINVAL
#define KRB5_AP_ERR_PRIVATE_KEY EINVAL
#define KRB5_AP_ERR_OPENSSL EINVAL


#define OPENSSL_ASN1_MALLOC_ENCODE(T, B, BL, S, R)			\
{									\
  unsigned char *p;							\
  (BL) = i2d_##T((S), NULL);						\
  if ((BL) <= 0) {							\
     (R) = EINVAL;							\
  } else {								\
    (B) = malloc((BL));							\
    if ((B) == NULL) {							\
       (R) = ENOMEM;							\
    } else {								\
        p = (B);							\
        (R) = 0;							\
        (BL) = i2d_##T((S), &p);					\
        if ((BL) <= 0) {						\
           free((B));                                          		\
           (R) = EINVAL;						\
        }								\
    }									\
  }									\
}

struct krb5_pk_init_ctx_data {
    STACK_OF(X509) *cert;
    EVP_PKEY *private_key;
    STACK_OF(X509) *trusted_certs;
    DH *dh;
};

#define oid_enc(n) { sizeof(n)/sizeof(n[0]), n }

static unsigned rsaEncryption_num[] = 
    { 1, 2, 840, 113549, 1, 1, 1 };
static heim_oid heim_rsaEncryption_oid = 
	oid_enc(rsaEncryption_num);
static unsigned md5WithRSAEncryption_num[] = 
    { 1, 2, 840, 113549, 1, 1, 4 };
static heim_oid heim_md5WithRSAEncryption_oid =
	oid_enc(md5WithRSAEncryption_num);
static unsigned sha1WithRSAEncryption_num[] = 
    { 1, 2, 840, 113549, 1, 1, 5 };
static heim_oid heim_sha1WithRSAEncryption_oid =
	oid_enc(sha1WithRSAEncryption_num);
static unsigned des_ede3_cbc_num[] = 
    { 1, 2, 840, 113549, 3, 7 };
static heim_oid heim_des_ede3_cbc_oid =
	oid_enc(des_ede3_cbc_num);
static unsigned sha1_num[] = 
    { 1, 3 ,14, 3, 2, 26 };
static heim_oid heim_sha1_oid = 
	oid_enc(sha1_num);
static unsigned pkcs7_data_num[] = 
    { 1, 2, 840, 113549, 1, 7, 1 };
static heim_oid pkcs7_data_oid =
	oid_enc(pkcs7_data_num);
static unsigned pkcs7_signed_num[] = 
    { 1, 2, 840, 113549, 1, 7, 2 };
static heim_oid pkcs7_signed_oid =
	oid_enc(pkcs7_signed_num);
static unsigned pkcs7_enveloped_num[] = 
    { 1, 2, 840, 113549, 1, 7, 3 };
static heim_oid pkcs7_enveloped_oid =
	oid_enc(pkcs7_enveloped_num);
static unsigned pkauthdata_num[] = 
    { 1, 2, 6, 1, 5, 2, 3, 1 };
static heim_oid heim_pkauthdata_oid =
	oid_enc(pkauthdata_num);
static unsigned pkdhkeydata_num[] = 
    { 1, 3, 6, 1, 5, 2, 3, 2 };
static heim_oid heim_pkdhkeydata_oid =
	oid_enc(pkdhkeydata_num);
static unsigned pkrkeydata_num[] = 
    { 1, 3, 6, 1, 5, 2, 3, 3 };
static heim_oid heim_pkrkeydata_oid =
	oid_enc(pkrkeydata_num);

static void
write_buf(const char *fn, void *data, size_t len)
{
    int fd;
    fd = open(fn, O_RDWR|O_TRUNC|O_CREAT, 0644);
    if (fd > 0) {
	write(fd, data, len);
	close(fd);
    }
}

static krb5_error_code
pk_create_sign(krb5_context context,
               STACK_OF(X509) *cert_chain,
               EVP_PKEY *private_key,
               SignedData *sd)
{
    X509 *user_cert = NULL ;
    SignerInfo *signer_info;
    EVP_MD_CTX md;
    unsigned char *buf = NULL;
    int len, i, ret;
    
    X509_NAME *issuer_name;

    if (cert_chain == NULL || private_key == NULL)
	return EINVAL /* KRB5_AP_ERR_NO_CERT_OR_KEY */;

    if (sk_X509_num(cert_chain) == 0)
	return EINVAL /* KRB5_AP_ERR_NO_CERT_OR_KEY */;

    ALLOC_SEQ(&sd->signerInfos, 1);
    if (sd->signerInfos.val == NULL)
	return ENOMEM;

    signer_info = &sd->signerInfos.val[0];

    user_cert = sk_X509_value(cert_chain, 0);

    signer_info->version = 1;

    issuer_name = X509_get_issuer_name(user_cert);

    OPENSSL_ASN1_MALLOC_ENCODE(X509_NAME, 
			       buf,
			       len,
			       issuer_name,
			       ret);
    if (ret)
	return ENOMEM;
    signer_info->sid.element = choice_SignerIdentifier_issuerAndSerialNumber;
    signer_info->sid.u.issuerAndSerialNumber.issuer.data = buf;
    signer_info->sid.u.issuerAndSerialNumber.issuer.length = len;

    signer_info->sid.u.issuerAndSerialNumber.serialNumber = 
	ASN1_INTEGER_get(X509_get_serialNumber(user_cert));

#ifdef PACKET_CABLE
    copy_oid(&heim_sha1_oid, 
	     &signer_info->digestAlgorithm.algorithm);
#else
    copy_oid(&heim_sha1WithRSAEncryption_oid, 
	     &signer_info->digestAlgorithm.algorithm);
#endif
    signer_info->digestAlgorithm.parameters = NULL;

    signer_info->signedAttrs = NULL;
    signer_info->unsignedAttrs = NULL;

    copy_oid(&heim_rsaEncryption_oid, 
	     &signer_info->signatureAlgorithm.algorithm);
    signer_info->signatureAlgorithm.parameters = NULL;

    buf = malloc(EVP_PKEY_size(private_key));
    if (buf == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    EVP_SignInit(&md, EVP_sha1());
    EVP_SignUpdate(&md,
		   sd->encapContentInfo.eContent->data,
		   sd->encapContentInfo.eContent->length);
    ret = EVP_SignFinal(&md, buf, &len, private_key);
    if (ret == 0) {
	free(buf);
	krb5_set_error_string(context, "Can't sign private key: %s",
			      ERR_error_string(ERR_get_error(), NULL));
	return EINVAL;
    }

    signer_info->signature.data = buf;
    signer_info->signature.length = len;

    ALLOC_SEQ(&sd->digestAlgorithms, 1);
    if (sd->digestAlgorithms.val == NULL)
	return ENOMEM;

    copy_oid(&heim_rsaEncryption_oid, &sd->digestAlgorithms.val[0].algorithm);
    sd->digestAlgorithms.val[0].parameters = NULL;

    ALLOC(sd->certificates, 1);
    if (sd->certificates == NULL) {
	krb5_clear_error_string(context);
	return ENOMEM;
    }
#if 1
    sd->certificates->data = NULL;
    sd->certificates->length = 0;

    for (i = 0; i < sk_X509_num(cert_chain); i++) {
	void *data;

	OPENSSL_ASN1_MALLOC_ENCODE(X509, 
				   buf,
				   len,
				   sk_X509_value(cert_chain, i),
				   ret);
	data = realloc(sd->certificates->data, 
		       sd->certificates->length + len);
	if (data == NULL) {
	    krb5_clear_error_string(context);
	    return ENOMEM;
	}
	memcpy(((char *)data) + sd->certificates->length, buf, len);
	sd->certificates->length += len;
	sd->certificates->data = data;
    }
#else
    ALLOC_SEQ(sd->certificates, sk_X509_num(cert_chain));
    if (sd->certificates == NULL)
	return ENOMEM;

    for (i = 0; i < sk_X509_num(cert_chain); i++) {
	OPENSSL_ASN1_MALLOC_ENCODE(X509, 
				   buf,
				   len,
				   sk_X509_value(cert_chain, i),
				   ret);
	if (ret) {
	    krb5_clear_error_string(context);
	    return ENOMEM;
	}
	
	sd->certificates->val[i].data = buf;
	sd->certificates->val[i].length = len;
    }
#endif
    return 0;
}


static krb5_error_code
build_auth_pack(krb5_context context,
                unsigned nonce,
		DH *dh,
		const KDC_REQ_BODY *body,
		AuthPack *a)
{
    size_t buf_size, len;
    krb5_cksumtype cksum;
    krb5_error_code ret;
    void *buf;
    krb5_timestamp sec;
    int32_t usec;

#if 1 /* def PACKET_CABLE */
    cksum = CKSUMTYPE_RSA_MD5;
#else
    cksum = CKSUMTYPE_SHA1;
#endif


    krb5_us_timeofday(context, &sec, &usec);
    a->pkAuthenticator.ctime = sec;
    a->pkAuthenticator.nonce = nonce;

    ASN1_MALLOC_ENCODE(KDC_REQ_BODY, buf, buf_size, body, &len, ret);
    if (ret)
	return ret;
    if (buf_size != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");

    ret = krb5_create_checksum(context,
			       NULL,
			       0,
			       cksum,
			       buf,
			       len,
			       &a->pkAuthenticator.paChecksum);
    free(buf);

    if (ret == 0 && dh) {
	/* XXX */
    }

    return ret;
}

static krb5_error_code
build_auth_pack_win2k(krb5_context context,
                      unsigned nonce,
                      const KDC_REQ_BODY *body,
                      AuthPack_Win2k *a)
{
    krb5_error_code ret;
    krb5_timestamp sec;
    int32_t usec;

    /* fill in PKAuthenticator */
    ret = copy_PrincipalName(body->sname, &a->pkAuthenticator.kdcName);
    if (ret)
	return ret;
    ret = copy_Realm(&body->realm, &a->pkAuthenticator.kdcRealm);
    if (ret)
	return ret;

    krb5_us_timeofday(context, &sec, &usec);
    a->pkAuthenticator.ctime = sec;
    a->pkAuthenticator.cusec = usec;
    a->pkAuthenticator.nonce = nonce;

    return 0;
}


static krb5_error_code
pk_mk_ContentInfo(krb5_context context,
		  const krb5_data *buf, 
		  const heim_oid *oid,
                  ContentInfo *content_info)
{
    copy_oid(oid, &content_info->contentType);
    ALLOC(content_info->content, 1);
    if (content_info->content == NULL)
	return ENOMEM;

    content_info->content->data = buf->data;
    content_info->content->length = buf->length;
    return 0;
}

krb5_error_code 
_krb5_pk_mk_padata(krb5_context context,
		   void *c,
		   const KDC_REQ_BODY *req_body,
		   unsigned nonce,
		   METHOD_DATA *md)
{
    krb5_pk_init_ctx ctx = c;
    krb5_error_code ret;
    const heim_oid *oid;
    PA_PK_AS_REQ req;
    size_t size;
    SignedData sd;
    krb5_data buf;
    PROV_SRV_LOCATION provisioning_server = NULL;

#ifdef PACKET_CABLE
    provisioning_server = "provserver.ipfonix.com";
#endif

    krb5_data_zero(&buf);
    memset(&sd, 0, sizeof(sd));
    memset(&req, 0, sizeof(req));
  
    if (context->pkinit_win2k_compatible) {
	AuthPack_Win2k ap;

	memset(&ap, 0, sizeof(ap));

	ret = build_auth_pack_win2k(context, nonce, req_body, &ap);
	if (ret) {
	    free_AuthPack_Win2k(&ap);
	    goto out;
	}

	ASN1_MALLOC_ENCODE(AuthPack_Win2k, buf.data, buf.length,
			   &ap, &size, ret);
	free_AuthPack_Win2k(&ap);
	if (ret) {
	    krb5_set_error_string(context, "AuthPack_Win2k: %d", ret);
	    goto out;
	}
	if (buf.length != size)
	    krb5_abortx(context, "internal ASN1 encoder error");
    } else {
	AuthPack ap;
	
	memset(&ap, 0, sizeof(ap));

	ret = build_auth_pack(context, nonce, NULL, req_body, &ap);
	if (ret) {
	    free_AuthPack(&ap);
	    goto out;
	}

	ASN1_MALLOC_ENCODE(AuthPack, buf.data, buf.length, &ap, &size, ret);
	free_AuthPack(&ap);
	if (ret) {
	    krb5_set_error_string(context, "AuthPack: %d", ret);
	    goto out;
	}
	if (buf.length != size)
	    krb5_abortx(context, "internal ASN1 encoder error");
    }

    sd.version = 3;

    /* for win2k we have to use a different object identifier */
    if (context->pkinit_win2k_compatible) {
	oid = &pkcs7_data_oid;
    } else {
	oid = &heim_pkauthdata_oid;
    }

    sd.digestAlgorithms.len = 0;
    sd.digestAlgorithms.val = NULL;
    copy_oid(oid, &sd.encapContentInfo.eContentType);
    ALLOC(sd.encapContentInfo.eContent, 1);
    if (sd.encapContentInfo.eContent == NULL)
	goto out;

    sd.encapContentInfo.eContent->data = buf.data;
    sd.encapContentInfo.eContent->length = buf.length;

    ret = pk_create_sign(context, ctx->cert, ctx->private_key, &sd);
    if (ret)
	goto out;

    ASN1_MALLOC_ENCODE(SignedData, buf.data, buf.length, &sd, &size, ret);
    if (ret) {
	krb5_set_error_string(context, "SignedData failed %d", ret);
	goto out;
    }
    if (buf.length != size)
	krb5_abortx(context, "internal ASN1 encoder error");
  
    ret = pk_mk_ContentInfo(context, &buf, &pkcs7_signed_oid, 
			    &req.signedAuthPack);
    if (ret) {
	free(buf.data);
	goto out;
    }

    req.trustedCertifiers = NULL; /* XXX */
    req.kdcCert = NULL;
    req.encryptionCert = NULL;
  
    /* use the win2k compatible der encoding if needed */
    if (context->pkinit_win2k_compatible) {
	PA_PK_AS_REQ_Win2k winreq;
#if 1
	memset(&winreq, 0, sizeof(winreq));
#else
	convert_req_to_req_win(&req, &winreq);
#endif
	ASN1_MALLOC_ENCODE(PA_PK_AS_REQ_Win2k, buf.data, buf.length,
			   &winreq, &size, ret);
	free_PA_PK_AS_REQ_Win2k(&winreq);
    } else
	ASN1_MALLOC_ENCODE(PA_PK_AS_REQ, buf.data, buf.length,
			   &req, &size, ret);

    if (ret) {
	krb5_set_error_string(context, "PA-PK-AS-REQ %d", ret);
	goto out;
    }
    if (buf.length != size)
	krb5_abortx(context, "Internal ASN1 encoder error");

    { 
	int type;

	if (context->pkinit_win2k_compatible)
	    type = KRB5_PADATA_PK_AS_REQ+1;
	else
	    type = KRB5_PADATA_PK_AS_REQ;

	ret = krb5_padata_add(context, md, type, buf.data, buf.length);
	if (ret)
	    free(buf.data);
    }

    if (ret == 0 && provisioning_server) {
	/* PacketCable requires the PROV-SRV-LOCATION authenticator */

	ASN1_MALLOC_ENCODE(PROV_SRV_LOCATION, buf.data, buf.length,
			   &provisioning_server, &size, ret);
	if (ret)
	    goto out;
	if (buf.length != size)
	    krb5_abortx(context, "Internal ASN1 encoder error");

	/* PacketCable uses -1 (application specific) as the auth data type */
	ret = krb5_padata_add(context, md, -1, buf.data, buf.length);
	if (ret)
	    free(buf.data);
    }

 out:
    free_SignedData(&sd);
    free_PA_PK_AS_REQ(&req);

    return ret;
}

static krb5_boolean
pk_peer_compare(krb5_context context,
		const SignerIdentifier *peer1, 
		X509 *peer2)
{
    switch (peer1->element) {
    case choice_SignerIdentifier_issuerAndSerialNumber: {
	X509_NAME *name;
	unsigned char *p;
	size_t len;

	if (peer1->u.issuerAndSerialNumber.serialNumber != 
	    ASN1_INTEGER_get(X509_get_serialNumber(peer2)))
	    return FALSE;

	p = peer1->u.issuerAndSerialNumber.issuer.data;
	len = peer1->u.issuerAndSerialNumber.issuer.length;
	name = d2i_X509_NAME(NULL, &p, len);
	if (name == NULL)
	    return FALSE;
	
	if (X509_NAME_cmp(name, X509_get_issuer_name(peer2)) != 0) {
	    X509_NAME_free(name);
	    return FALSE;
	}
	X509_NAME_free(name);
	break;
    }
    case choice_SignerIdentifier_subjectKeyIdentifier:
	return FALSE;
    default:
	return FALSE;
    }
    return TRUE;
}

static krb5_error_code
pk_decrypt_key(krb5_context context,
	       heim_octet_string *encrypted_key,
	       EVP_PKEY *priv_key,
	       krb5_keyblock *key)
{
    int ret;
    unsigned char *buf;

    buf = malloc(EVP_PKEY_size(priv_key));
    if (buf == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }
    ret = EVP_PKEY_decrypt(buf,
			   encrypted_key->data,
			   encrypted_key->length,
			   priv_key);
    if (ret <= 0) {
	free(buf);
	krb5_set_error_string(context, "Can't decrypt key: %s",
			      ERR_error_string(ERR_get_error(), NULL));
	return KRB5_AP_ERR_OPENSSL;
    }

    /* use d2i() ?? */
    //ret = decode_EncryptionKey(buf, EVP_PKEY_size(priv_key), key, &len);
    key->keyvalue.length = ret;
    key->keyvalue.data = malloc(ret);
    if (key->keyvalue.data == NULL) {
	free(buf);
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }
    memcpy(key->keyvalue.data, buf, ret);
    key->keytype = 0;
    ret = 0;
  
    free(buf);
    return ret;
}


static krb5_error_code 
pk_verify_chain_standard(krb5_context context,
                         STACK_OF(X509) *trusted_certs,
                         STACK_OF(X509_CRL) *crls,
			 const SignerIdentifier *client,
			 STACK_OF(X509) *chain,
			 X509 **client_cert)
{
    X509_STORE *cert_store = NULL;
    X509_STORE_CTX *store_ctx = NULL;
    X509 *cert = NULL;
    int i;
    int ret;

    ret = KDC_ERROR_CLIENT_NAME_MISMATCH; /* XXX */
    for (i = 0; i < sk_X509_num(chain); i++) {
	cert = sk_X509_value(chain, i);
	if (pk_peer_compare(context, client, cert) == TRUE) {
	    ret = 0;
	    break;
	}
    }
    if (ret)
	return ret;

    cert_store = X509_STORE_new();
    if (cert_store == NULL) {
	ret = KRB5_AP_ERR_OPENSSL;
	krb5_set_error_string(context, "Can't create X509 store: %s",
			      ERR_error_string(ERR_get_error(), NULL));
    }

    store_ctx = X509_STORE_CTX_new();
    if (store_ctx == NULL) {
	ret = KRB5_AP_ERR_OPENSSL;
	krb5_set_error_string(context, "Can't create X509 store ctx: %s",
			      ERR_error_string(ERR_get_error(), NULL));
	goto end;
    }
   
    X509_STORE_CTX_init(store_ctx, cert_store, cert, chain);
    X509_STORE_CTX_trusted_stack(store_ctx, trusted_certs);
    X509_verify_cert(store_ctx);
    /* the last checked certificate is in store_ctx->current_cert */
    switch(store_ctx->error) {
    case X509_V_OK:
	ret = 0;
	break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	ret = KDC_ERROR_CANT_VERIFY_CERTIFICATE;
	break;
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_CERT_HAS_EXPIRED:
	ret = KDC_ERROR_INVALID_CERTIFICATE;
	break;
    default:
	ret = KDC_ERROR_INVALID_CERTIFICATE; /* XXX */
	break;
    }
    if (ret)
	goto end;

    /* Since X509_verify_cert() doesn't do CRL checking at all, we have to
       perform own verification against CRLs */
#if 0
    ret = pk_verify_crl(context, store_ctx, crls);
    if (ret)
	goto end;
#endif

    if (client_cert && cert)
	*client_cert = X509_dup(cert);

 end:
    if (store_ctx)
	X509_STORE_CTX_free(store_ctx);
    return ret;
}

static int
cert_to_X509(krb5_context context, CertificateSetReal *set,
	     STACK_OF(X509_CRL) **certs)
{
    krb5_error_code ret;
    int i;

    *certs = sk_X509_new_null();

    ret = 0;
    for (i = 0; i < set->len; i++) {
	unsigned char *p = set->val[i].data;
	int len = set->val[i].length;
	X509 *cert;

	cert = d2i_X509(NULL, &p, len);
	if (cert == NULL) {
	    ret = EINVAL; /* XXX */
	    break;
	}
	sk_push(*certs, (char *)cert);
    }
    if (ret) {
	krb5_set_error_string(context, "Failed to parse certificate chain");
	sk_X509_free(*certs);
	*certs = NULL;
    }
    return ret;
}

static krb5_error_code
any_to_CertificateSet(krb5_context context, heim_any *cert, 
		      CertificateSetReal *set)
{
    size_t size, len, length;
    heim_any *val;
    int ret;
    char *p;
    
    write_buf("/tmp/CertSet", cert->data, cert->length);

    set->len = 0;
    set->val = NULL;

    len = 0;
    p = cert->data;
    length = cert->length;
    while (len < cert->length) {
	val = realloc(set->val, (set->len + 1) * sizeof(set->val[0]));
	if (val == NULL) {
	    ret = ENOMEM;
	    goto out;
	}
	set->val = val;
	ret = decode_heim_any(p, length, &set->val[set->len], &size);
	if (ret)
	    goto out;
	set->len++;

	p += size;
	len += size;
	length -= size;
    }
    return 0;
 out:
    krb5_clear_error_string(context);
    free_CertificateSetReal(set);
    set->val = NULL;
    return ret;
}


static krb5_error_code
pk_verify_sign(krb5_context context,
      	       const SignedData *sd,
	       STACK_OF(X509) *trusted_certs,
	       STACK_OF(X509_CRL) *crls,
    	       X509 **signer)
{
    STACK_OF(X509) *certificates;
    SignerInfo *signer_info;
    const EVP_MD *evp_type;
    EVP_PKEY *public_key;
    krb5_error_code ret;
    CertificateSetReal set;
    EVP_MD_CTX md;
    X509 *cert;
    
    *signer = NULL;

    /* XXX Check CMS version */

    if (sd->signerInfos.len < 1) {
	krb5_set_error_string(context, "Signature information missing from "
			      "pkinit response");
	return KDC_ERROR_INVALID_SIG;
    }

    signer_info = &sd->signerInfos.val[0];
  
    ret = any_to_CertificateSet(context, sd->certificates, &set);
    if (ret)
	return ret;

    ret = cert_to_X509(context, &set, &certificates);
    free_CertificateSetReal(&set);
    if (ret)
	return ret;

    ret = pk_verify_chain_standard(context, trusted_certs, crls,
				   &signer_info->sid, certificates, &cert);
    sk_X509_free(certificates);
    if (ret)
	return ret;
  
    if (signer_info->signature.length == 0) {
	X509_free(cert);
	krb5_set_error_string(context, "Signature missing from "
			      "pkinit response");
	return KDC_ERROR_INVALID_SIG; 
    }

    public_key = X509_get_pubkey(cert);

    /* verify signature */
    if (oid_cmp(&signer_info->digestAlgorithm.algorithm,
		&heim_sha1WithRSAEncryption_oid) == 0)
	evp_type = EVP_sha1();
    else if (oid_cmp(&signer_info->digestAlgorithm.algorithm,
		     &heim_md5WithRSAEncryption_oid) == 0) 
	evp_type = EVP_md5();
    else if (oid_cmp(&signer_info->digestAlgorithm.algorithm, 
		     &heim_sha1_oid) == 0)
	evp_type = EVP_sha1();
    else {
	X509_free(cert);
	krb5_set_error_string(context, "The requested digest algorithm is "
			      "not supported");
	return KDC_ERROR_INVALID_SIG;
    }

    EVP_VerifyInit(&md, evp_type);
    EVP_VerifyUpdate(&md,
		     sd->encapContentInfo.eContent->data,
		     sd->encapContentInfo.eContent->length);
    ret = EVP_VerifyFinal(&md,
			  signer_info->signature.data,
			  signer_info->signature.length,
			  public_key);
    if (ret != 1) {
	X509_free(cert);
	krb5_set_error_string(context, "pkinit signature didn't verify");
	return KDC_ERROR_INVALID_SIG;
    }

    if (signer)
	*signer = cert;
    else
	X509_free(cert);

    return 0;
}

static krb5_error_code
get_reply_key(krb5_context context,
	      SignedData *sd,
	      unsigned nonce,
	      krb5_keyblock **key)
{
    ReplyKeyPack key_pack;
    krb5_error_code ret;
    size_t size;

    if (oid_cmp(&sd->encapContentInfo.eContentType, &heim_pkrkeydata_oid) != 0)
	return KRB5KRB_AP_ERR_MSG_TYPE;

    if (sd->encapContentInfo.eContent == NULL)
	return KRB5KRB_AP_ERR_MSG_TYPE;

    ret = decode_ReplyKeyPack(sd->encapContentInfo.eContent->data,
			      sd->encapContentInfo.eContent->length,
			      &key_pack,
			      &size);
    if (ret) {
	free_ReplyKeyPack(&key_pack);
	return ret;
    }
     
    if (key_pack.nonce != nonce) {
	free_ReplyKeyPack(&key_pack);
	return KRB5KRB_AP_ERR_MODIFIED;
    }

    *key = malloc (sizeof (**key));
    if (*key == NULL) {
	free_ReplyKeyPack(&key_pack);
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    ret = copy_EncryptionKey(&key_pack.replyKey, *key);
    free_ReplyKeyPack(&key_pack);
    if (ret)
	free(*key);

    return ret;
}

static krb5_error_code
pk_verify_host(krb5_context context, X509 *host)
{
    /* XXX */
    return 0;
}

static krb5_error_code
pk_rd_pa_reply_enckey(krb5_context context,
                      ContentInfo *rep,
		      krb5_pk_init_ctx ctx,
		      krb5_enctype etype,
	       	      unsigned nonce,
	       	      PA_DATA *pa,
	       	      krb5_keyblock **key) 
{
    krb5_error_code ret;
    SignedData sd;
    EnvelopedData ed;
    krb5_keyblock tmp_key;
    krb5_crypto crypto;
    krb5_data plain;
    KeyTransRecipientInfo *ri;
    int length;
    size_t size;
    X509 *host, *user_cert;
    char *p;
    krb5_boolean bret;

    memset(&tmp_key, 0, sizeof(tmp_key));
    memset(&ed, 0, sizeof(ed));
    memset(&sd, 0, sizeof(sd));
    krb5_data_zero(&plain);

    user_cert = sk_X509_value(ctx->cert, 0);

    if (oid_cmp(&pkcs7_enveloped_oid, &rep->contentType)) {
	krb5_set_error_string(context, "Invalid content type");
	return EINVAL;
    }

    if (rep->content == NULL) {
	krb5_set_error_string(context, "No content in pkinit reply");
	return EINVAL;
    }

    ret = decode_EnvelopedData(rep->content->data,
			       rep->content->length,
			       &ed,
			       &size);
    if (ret) {
	free_EnvelopedData(&ed);
	return ret;
    }

    if (ed.recipientInfos.len != 1) {
	free_EnvelopedData(&ed);
	krb5_set_error_string(context, "Number of recipient infos "
			      "not one (%d)",
			      ed.recipientInfos.len);
	return EINVAL; /* XXX */
    }

    ri = &ed.recipientInfos.val[0];

    /* XXX make SignerIdentifier and RecipientIdentifier the same */
    bret = pk_peer_compare(context, (SignerIdentifier *)&ri->rid, user_cert);
    if (bret == FALSE) {
	ret = KRB5KRB_AP_ERR_BADMATCH; /* XXX */
	goto out;
    }

    if (oid_cmp(&heim_rsaEncryption_oid,
		&ri->keyEncryptionAlgorithm.algorithm)) {
	krb5_set_error_string(context, "Invalid content type");
	return EINVAL;
    }
    
    ret = pk_decrypt_key(context, &ri->encryptedKey,
			 ctx->private_key, &tmp_key);
    if (ret)
	goto out;

  
    /* verify content type */
    if (context->pkinit_win2k_compatible) {
	if (oid_cmp(&ed.encryptedContentInfo.contentType, &pkcs7_data_oid)) {
	    ret = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto out;
	}
    } else {
	if (oid_cmp(&ed.encryptedContentInfo.contentType, &pkcs7_signed_oid)) {
	    ret = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto out;
	}
    }


    if (oid_cmp(&ed.encryptedContentInfo.contentEncryptionAlgorithm.algorithm,
		&heim_des_ede3_cbc_oid) == 0) {
	/* use des-ede3-cbc */
	heim_octet_string encryptedContent;
	heim_octet_string *any;

	if (ed.encryptedContentInfo.encryptedContent == NULL) {
	    krb5_set_error_string(context, "OPTIONAL encryptedContent "
				  "field not filled in in KDC reply");
	    ret = KRB5_BADMSGTYPE;
	    goto out;
	}

	any = ed.encryptedContentInfo.encryptedContent;
	ret = der_get_octet_string(any->data, any->length,
				   &encryptedContent, NULL);
	if (ret) {
	    krb5_set_error_string(context, "encryptedContent content invalid");
	    goto out;
	}

	tmp_key.keytype = ETYPE_DES3_CBC_NONE;
	ret = krb5_crypto_init(context, &tmp_key,ETYPE_DES3_CBC_NONE, &crypto);
	if (ret) {
	    free_octet_string(&encryptedContent);
	    goto out;
	}
	ret = krb5_decrypt(context, crypto,
			   0,
			   encryptedContent.data,
			   encryptedContent.length,
			   &plain);
	krb5_crypto_destroy(context, crypto);
	free_octet_string(&encryptedContent);
	if (ret)
	    goto out;
	
    } else {
	krb5_set_error_string(context, "no pkinit support for oid");
	ret = KRB5KRB_AP_ERR_BADKEYVER; 
	goto out;
    }

    p = plain.data;
    length = plain.length;

    /* win2k uses ContentInfo */
    if (context->pkinit_win2k_compatible) {
	ContentInfo ci;
	size_t size;

	ret = decode_ContentInfo(p, length, &ci, &size);
	if (ret) {
	    krb5_set_error_string(context,
				  "decoding failed ContentInfo: %d", ret);
	    goto out;
	}

	if (oid_cmp(&ci.contentType, &pkcs7_signed_oid) == 0) {
	    ret = EINVAL; /* XXX */
	    krb5_set_error_string(context, "Invalid content type");
	    goto out;
	}
	p = ci.content->data;
	length = ci.content->length;
    } 

    ret = decode_SignedData(p, length, &sd, &size);
    if (ret) {
	krb5_set_error_string(context, "decoding failed SignedData: %d",
			      ret);
	goto out;
    }

    ret = pk_verify_sign(context, &sd, ctx->trusted_certs, NULL, &host);
    if (ret) {
	krb5_set_error_string(context, "failed verify signature of reply: %d",
			      ret);
	goto out;
    }

    /* make sure that it is the kdc's certificate */
    ret = pk_verify_host(context, host);
    if (ret) {
	krb5_set_error_string(context, "failed verify host: %d", ret);
	goto out;
    }

    ret = get_reply_key(context, &sd, nonce, key);
    if (ret) {
	krb5_set_error_string(context, "failed getting reply key: %d", ret);
	goto out;
    }

    /* XXX compare given etype with key->etype */

 out:
    krb5_free_keyblock_contents(context, &tmp_key);
    krb5_data_free(&plain);
    free_SignedData(&sd);

    return ret;
}

static krb5_error_code
pk_rd_pa_reply_dh(krb5_context context,
                  ContentInfo *rep,
		  krb5_pk_init_ctx ctx,
		  krb5_enctype etype,
                  unsigned nonce,
                  PA_DATA *pa,
                  krb5_keyblock **key)
{
    krb5_error_code ret;
    SignedData sd;
    KDCDHKeyInfo kdc_dh_info;
    X509 *host;
    DES_cblock *k;
    int dh_gen_keylen;
    BIGNUM *kdc_dh_pubkey = NULL;
    size_t size;

    unsigned char *p;
    unsigned char *dh_gen_key = NULL;
    ASN1_INTEGER *dh_pub_key = NULL;

    memset(&kdc_dh_info, 0, sizeof(kdc_dh_info));
    memset(&sd, 0, sizeof(sd));

    if (oid_cmp(&pkcs7_signed_oid, &rep->contentType)) {
	krb5_set_error_string(context, "Invalid content type");
	return EINVAL;
    }

    if (rep->content == NULL) {
	krb5_set_error_string(context, "No content in pkinit reply");
	return EINVAL;
    }

    ret = decode_SignedData(rep->content->data,
			    rep->content->length,
			    &sd,
			    &size);
    if (ret) {
	krb5_set_error_string(context, "decoding failed SignedData: %d",
			      ret);
	goto out;
    }

    ret = pk_verify_sign(context, &sd, ctx->trusted_certs, NULL, &host);
    if (ret)
	goto out;

    /* make sure that it is the kdc's certificate */
    ret = pk_verify_host(context, host);
    if (ret)
	goto out;

    if (oid_cmp(&sd.encapContentInfo.eContentType, &heim_pkdhkeydata_oid)) {
	ret = KRB5KRB_AP_ERR_MSG_TYPE; /* XXX */
	goto out;
    }

    if (sd.encapContentInfo.eContent == NULL) {
	ret = KRB5KRB_AP_ERR_MSG_TYPE; /* XXX */
	goto out;
    }


    ret = decode_KDCDHKeyInfo(sd.encapContentInfo.eContent->data,
			      sd.encapContentInfo.eContent->length,
			      &kdc_dh_info,
			      &size);

    if (ret)
	goto out;

    if (kdc_dh_info.nonce != nonce) {
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto out;
    }

#if 1
    kdc_dh_pubkey = BN_new();
    if (kdc_dh_pubkey == NULL) {
	ret = ENOMEM;
	goto out;
    }
    BN_bin2bn(kdc_dh_info.subjectPublicKey.data,
	      kdc_dh_info.subjectPublicKey.length,
	      kdc_dh_pubkey);
    p = NULL;
    dh_pub_key = NULL;
#else
    p = kdc_dh_info.subjectPublicKey.data;
    if (p == NULL) {
	krb5_set_error_string(context,
			      "Invalid DH public key parameter "
			      "in KdcDHKeyInfo");
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }

    d2i_ASN1_INTEGER(&dh_pub_key, &p, kdc_dh_info.subjectPublicKey.length);
    if (dh_pub_key == NULL) {
	krb5_set_error_string(context, "Cannot decode public key "
			      "parameter from KdcDHKey");
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }

    kdc_dh_pubkey = ASN1_INTEGER_to_BN(dh_pub_key, kdc_dh_pubkey);
    if (kdc_dh_pubkey == NULL) {
	krb5_set_error_string(context, "Cannot convert KDC's DH public key");
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }
#endif

    dh_gen_key = malloc(DH_size(ctx->dh));
    if (dh_gen_key == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	ret = ENOMEM;
	goto out;
    }

    dh_gen_keylen = DH_compute_key(dh_gen_key, kdc_dh_pubkey, ctx->dh);
    if (dh_gen_keylen == -1) {
	krb5_set_error_string(context, 
			      "Cannot compute Diffie-Hellman key (%s)",
			      ERR_error_string(ERR_get_error(), NULL));
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }

    *key = malloc (sizeof (**key));
    if (*key == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	ret = ENOMEM;
	goto out;
    }

    /* XXX all this stuff only to get the key length ? */
    switch(etype) {
    case ETYPE_DES3_CBC_SHA1:
	ret = krb5_generate_random_keyblock(context, etype, *key);
	if (ret) {
	    free(*key);
	    *key = NULL;
	    goto out;
	}
	
	memcpy((*key)->keyvalue.data, dh_gen_key, (*key)->keyvalue.length);
	k = (*key)->keyvalue.data;
	DES_set_odd_parity(&k[0]);
	DES_set_odd_parity(&k[1]);
	DES_set_odd_parity(&k[2]);
	
	(*key)->keytype = etype;
	break;
    default:
	krb5_set_error_string(context, "unsupported enctype %d", etype);
	ret = EINVAL;
	break;
    }

 out:
    if (kdc_dh_pubkey)
	BN_free(kdc_dh_pubkey);
    if (dh_gen_key) {
	memset(dh_gen_key, 0, DH_size(ctx->dh));
	free(dh_gen_key);
    }
    free_KDCDHKeyInfo(&kdc_dh_info);
    free_SignedData(&sd);

    return ret;
}

krb5_error_code
_krb5_pk_rd_pa_reply(krb5_context context,
		     void *c,
		     krb5_enctype etype,
		     unsigned nonce,
		     PA_DATA *pa,
		     krb5_keyblock **key)
{
    krb5_pk_init_ctx ctx = c;
    krb5_error_code ret;
    PA_PK_AS_REP rep;
    size_t size;

    memset(&rep, 0, sizeof(rep));

    ret = decode_PA_PK_AS_REP(pa->padata_value.data,
			      pa->padata_value.length,
			      &rep,
			      &size);
    if (ret != 0) {
	PA_PK_AS_REP_Win2k w2krep;

	free_PA_PK_AS_REP(&rep);

	ret = decode_PA_PK_AS_REP_Win2k(pa->padata_value.data,
					pa->padata_value.length,
					&w2krep,
					&size);
	if (ret) {
	    krb5_set_error_string(context, "Failed decoding windows"
				  "pkinit reply %d", ret);
	    return ret;
	}
#if 0
	convert_rep(&w2krep, &rep);
	printf("decoing of win reply succeded\n");
#endif
	krb5_set_error_string(context, "w2k pkinit support missing");
	free_PA_PK_AS_REP_Win2k(&w2krep);
	return EINVAL;
    }

    switch(rep.element) {
    case choice_PA_PK_AS_REP_dhSignedData:
	ret = pk_rd_pa_reply_dh(context, &rep.u.dhSignedData, ctx,
				etype, nonce, pa, key);
	break;
    case choice_PA_PK_AS_REP_encKeyPack:
	ret = pk_rd_pa_reply_enckey(context, &rep.u.encKeyPack, ctx,
				    etype, nonce, pa, key);
	break;
    default:
	krb5_set_error_string(context, "pkinit reply invalid content type");
	ret = EINVAL;
	break;
    }
  
    free_PA_PK_AS_REP(&rep);
    return ret;
}

static int
ssl_pass_cb(char *buf, int size, int rwflag, void *u)
{
    krb5_error_code ret;
    krb5_prompt prompt;
    krb5_data password_data;
   
    password_data.data   = buf;
    password_data.length = size;
    prompt.prompt = "Enter your private key passphrase: ";
    prompt.hidden = 1;
    prompt.reply  = &password_data;
    prompt.type   = KRB5_PROMPT_TYPE_PASSWORD;
   
    ret = krb5_prompter_posix(NULL, NULL, NULL, NULL, 1, &prompt);
    if (ret) {
	memset (buf, 0, size);
	return 0;
    }
    return strlen(buf);
}

#endif /* PKINIT */

krb5_error_code
krb5_get_init_creds_opt_set_pkinit(krb5_context context,
				   krb5_get_init_creds_opt *opt,
				   const char *cert_file,
				   const char *key_file,
				   const char *ca_dir,
				   char *password)
{
#ifdef PKINIT
    STACK_OF(X509) *certificate = NULL, *trusted_certs = NULL;
    EVP_PKEY *private_key = NULL;
    X509 *cert = NULL;
    krb5_error_code ret;
    char *dirname;
    struct dirent *file;
    DIR *dir;
    FILE *f;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (opt->private == NULL) {
	krb5_set_error_string(context, "pkinit on non extendable opt");
	return EINVAL;
    }
    if (cert_file == NULL) {
	krb5_set_error_string(context, "certificate file file missing");
	return KRB5_AP_ERR_NO_CERT_OR_KEY;
    }
    if (key_file == NULL) {
	krb5_set_error_string(context, "key file missing");
	return KRB5_AP_ERR_NO_CERT_OR_KEY;
    }
    if (ca_dir == NULL) {
	krb5_set_error_string(context, "No root ca directory given\n");
	return KRB5_AP_ERR_NO_VALID_CA;
    }

    f = fopen(cert_file, "r");
    if (f == NULL) {
	ret = errno;
	krb5_set_error_string(context, "open failed %s: %s", 
			      cert_file, strerror(ret));
	return ret;
    }
    certificate = sk_X509_new_null();
    while (1) {
	/* see http://www.openssl.org/docs/crypto/pem.html section BUGS */
	cert = PEM_read_X509(f, NULL, NULL, NULL);
	if (cert == NULL) {
	    if (ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE) {
		/* End of file reached. no error */
		ERR_clear_error();
		break;
	    }
	    krb5_set_error_string(context, "Can't read certificate");
	    ret = KRB5_AP_ERR_CERT;
	    goto out;
	}
	sk_X509_insert(certificate, cert, sk_X509_num(certificate));
    }
    fclose(f);
    f = NULL;
    if (sk_X509_num(certificate) == 0) {
	krb5_set_error_string(context, "No certificate found");
	ret = KRB5_AP_ERR_CERT;
	goto out;
    }
    /* load private key */
    f = fopen(key_file, "r");
    if (f == NULL) {
	ret = errno;
	krb5_set_error_string(context, "open %s: %s", key_file, strerror(ret));
	goto out;
    }
    private_key = PEM_read_PrivateKey(f, NULL, 
				      (password == NULL||password[0] == '\0') ?
				      ssl_pass_cb : NULL, password);
    if (private_key == NULL) {
	krb5_set_error_string(context, "Can't read private key");
	ret = KRB5_AP_ERR_PRIVATE_KEY;
	goto out;
    }
    fclose(f);
    f = NULL;
    ret = X509_check_private_key(sk_X509_value(certificate, 0), private_key);
    if (ret != 1) {
	ret = KRB5_AP_ERR_PRIVATE_KEY;
	krb5_set_error_string(context,
			      "The private key doesn't match the public key "
			      "certificate");
	goto out;
    }

    /* read ca certificates */
    dir = opendir(ca_dir);
    if (dir == NULL) {
	ret = errno;
	krb5_set_error_string(context, "open directory %s: %s",
			      ca_dir, strerror(ret));
	goto out;
    }

    asprintf(&dirname, "%s%s", ca_dir, 
	     ca_dir[strlen(ca_dir) - 1] == '/' ? "" : "/");

    trusted_certs = sk_X509_new_null();
    while ((file = readdir(dir))) {
	/* suppose the certificate filenames constist of hashed
	 * subject name followed by suffix ".0" */
	char *filename;

	if (strlen(file->d_name) == 10 && strcmp(&file->d_name[8],".0") == 0) {
	    asprintf(&filename, "%s%s", dirname, file->d_name);
	    f = fopen(filename, "r");
	    if (f == NULL) {
		ret = errno;
		krb5_set_error_string(context, "open %s: %s",
				      filename, strerror(ret));
		free(filename);
		closedir(dir);
		goto out;
	    }
	    cert = PEM_read_X509(f, NULL, NULL, NULL);
	    if (cert != NULL) {
		/* order of the certs is not important */
		sk_X509_push(trusted_certs, cert);
	    }
	    free(filename);
	    fclose(f);
	    f = NULL;
	}
    }
    closedir(dir);

    if (sk_X509_num(trusted_certs) == 0) {
	krb5_set_error_string(context, "No CA certificate(s) found");
	ret = KRB5_AP_ERR_NO_VALID_CA;
	goto out;
    }

    opt->private->pk_init_ctx = malloc(sizeof(*opt->private->pk_init_ctx));
    if (opt->private->pk_init_ctx == NULL) {
	krb5_set_error_string(context, "malloc");
	ret = ENOMEM;
	goto out;
    }

    opt->private->pk_init_ctx->cert = certificate;
    opt->private->pk_init_ctx->private_key = private_key;
    opt->private->pk_init_ctx->trusted_certs = trusted_certs;
    opt->private->pk_init_ctx->dh = NULL;

    return 0;

 out:
    if (certificate)
	sk_X509_pop_free(certificate, X509_free);
    if (trusted_certs)
	sk_X509_pop_free(trusted_certs, X509_free);
    if (private_key)
	EVP_PKEY_free(private_key);
    if (f)
	fclose(f);

    return ret;
#else
    krb5_set_error_string(context, "no support for PKINIT compiled in");
    return EINVAL;
#endif
}
