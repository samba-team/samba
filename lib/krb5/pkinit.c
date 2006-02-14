/*
 * Copyright (c) 2003 - 2005 Kungliga Tekniska Högskolan
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

struct krb5_dh_moduli {
    char *name;
    unsigned long bits;
    heim_integer p;
    heim_integer g;
    heim_integer q;
};

#ifdef PKINIT

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/ui.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include "heim_asn1.h"
#include "rfc2459_asn1.h"
#include "cms_asn1.h"
#include "pkinit_asn1.h"

enum {
    COMPAT_WIN2K = 1,
    COMPAT_IETF = 2
};

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
           (R) = ASN1_OVERRUN;						\
        }								\
    }									\
  }									\
}

/* ENGING_load_private_key requires a UI_METHOD and data  
 * if to be usable from PAM 
 */

struct krb5_ui_data {
    krb5_context context;
    krb5_prompter_fct prompter;
    void * prompter_data;
};

struct krb5_pk_identity {
    EVP_PKEY *private_key;
    STACK_OF(X509) *cert;
    STACK_OF(X509) *trusted_certs;
    STACK_OF(X509_CRL) *crls;
    ENGINE *engine;
};

struct krb5_pk_cert {
    X509 *cert;
};

struct krb5_pk_init_ctx_data {
    struct krb5_pk_identity *id;
    DH *dh;
    krb5_data *clientDHNonce;
    struct krb5_dh_moduli **m;
    int require_binding;
};

void KRB5_LIB_FUNCTION
_krb5_pk_cert_free(struct krb5_pk_cert *cert)
{
    if (cert->cert)
	X509_free(cert->cert);
    free(cert);
}

static krb5_error_code
BN_to_integer(krb5_context context, BIGNUM *bn, heim_integer *integer)
{
    integer->length = BN_num_bytes(bn);
    integer->data = malloc(integer->length);
    if (integer->data == NULL) {
	krb5_clear_error_string(context);
	return ENOMEM;
    }
    BN_bn2bin(bn, integer->data);
    integer->negative = bn->neg;
    return 0;
}

static BIGNUM *
integer_to_BN(krb5_context context, const char *field, const heim_integer *f)
{
    BIGNUM *bn;

    bn = BN_bin2bn((const unsigned char *)f->data, f->length, NULL);
    if (bn == NULL) {
	krb5_set_error_string(context, "PKINIT: parsing BN failed %s", field);
	return NULL;
    }
    bn->neg = f->negative;
    return bn;
}

/*
 * UI ex_data has the callback_data as passed to Engine. This is far
 * from being complete, we will only process one prompt
 */

static int
krb5_ui_method_read_string(UI *ui, UI_STRING *uis)
{
    char *buffer;
    size_t length;
    krb5_error_code ret;
    krb5_prompt prompt;
    krb5_data password_data;
    struct krb5_ui_data *ui_data;
  
    ui_data = (struct krb5_ui_data *)UI_get_app_data(ui);

    switch (UI_get_string_type(uis)) {
    case UIT_INFO:
    case UIT_ERROR:
	/* looks like the RedHat pam_prompter might handle 
	 * INFO and ERROR, Will see what happens */
    case UIT_VERIFY:
    case UIT_PROMPT:
	length = UI_get_result_maxsize(uis);
	buffer = malloc(length);
	if (buffer == NULL) {
	    krb5_set_error_string(ui_data->context, "malloc: out of memory");
	    return 0;
	}
	password_data.data = buffer;
	password_data.length = length;

	prompt.prompt = UI_get0_output_string(uis);
	prompt.hidden = !(UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO);
	prompt.reply  = &password_data;
	prompt.type   = KRB5_PROMPT_TYPE_PASSWORD;
  
	ret = (*ui_data->prompter)(ui_data->context, 
				   ui_data->prompter_data, 
				   NULL, NULL, 1, &prompt);
	if (ret == 0) {
	    buffer[length - 1] = '\0';
	    UI_set_result(ui, uis, password_data.data);

	    /*
	     * RedHat pam_krb5 pam_prompter does a strdup but others
	     * may copy into buffer. XXX should we just leak the
	     * memory instead ?
	     */

	    if (buffer != password_data.data)
		free(password_data.data);
	    memset (buffer, 0, length);
	    free(buffer);
	    return 1;
	}
	memset (buffer, 0, length);
	free(buffer);
	break;
    case UIT_NONE:
    case UIT_BOOLEAN:
	/* XXX for now do not handle */
	break;

    }
    return 0;
}


static krb5_error_code
set_digest_alg(DigestAlgorithmIdentifier *id,
	       const heim_oid *oid,
	       void *param, size_t length)
{
    krb5_error_code ret;
    if (param) {
	id->parameters = malloc(sizeof(*id->parameters));
	if (id->parameters == NULL)
	    return ENOMEM;
	id->parameters->data = malloc(length);
	if (id->parameters->data == NULL) {
	    free(id->parameters);
	    id->parameters = NULL;
	    return ENOMEM;
	}
	memcpy(id->parameters->data, param, length);
	id->parameters->length = length;
    } else
	id->parameters = NULL;
    ret = copy_oid(oid, &id->algorithm);
    if (ret) {
	if (id->parameters) {
	    free(id->parameters->data);
	    free(id->parameters);
	    id->parameters = NULL;
	}
	return ret;
    }
    return 0;
}

krb5_error_code KRB5_LIB_FUNCTION
_krb5_pk_create_sign(krb5_context context,
		     const heim_oid *eContentType,
		     krb5_data *eContent,
		     struct krb5_pk_identity *id,
		     krb5_data *sd_data)
{
    SignerInfo *signer_info;
    X509 *user_cert;
    heim_integer *serial;
    krb5_error_code ret;
    krb5_data buf;
    SignedData sd;
    EVP_MD_CTX md;
    int i;
    unsigned len;
    size_t size;
    
    X509_NAME *issuer_name;

    memset(&sd, 0, sizeof(sd));

    if (id == NULL)
	return HEIM_PKINIT_NO_CERTIFICATE;
    if (id->cert == NULL)
	return HEIM_PKINIT_NO_CERTIFICATE;
    if (id->private_key == NULL)
	return HEIM_PKINIT_NO_PRIVATE_KEY;

    if (sk_X509_num(id->cert) == 0)
	return HEIM_PKINIT_NO_CERTIFICATE;

    sd.version = 3;

    sd.digestAlgorithms.len = 0;
    sd.digestAlgorithms.val = NULL;
    copy_oid(eContentType, &sd.encapContentInfo.eContentType);
    ALLOC(sd.encapContentInfo.eContent, 1);
    if (sd.encapContentInfo.eContent == NULL) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }

    ret = krb5_data_copy(&buf, eContent->data, eContent->length);
    if (ret) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }

    sd.encapContentInfo.eContent->data = buf.data;
    sd.encapContentInfo.eContent->length = buf.length;

    ALLOC_SEQ(&sd.signerInfos, 1);
    if (sd.signerInfos.val == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	ret = ENOMEM;
	goto out;
    }

    signer_info = &sd.signerInfos.val[0];

    user_cert = sk_X509_value(id->cert, 0);
    if (user_cert == NULL) {
	krb5_set_error_string(context, "pkinit: no user certificate");
	ret = HEIM_PKINIT_NO_CERTIFICATE;
	goto out;
    }

    signer_info->version = 1;

    issuer_name = X509_get_issuer_name(user_cert);

    OPENSSL_ASN1_MALLOC_ENCODE(X509_NAME, 
			       buf.data,
			       buf.length,
			       issuer_name,
			       ret);
    if (ret) {
	krb5_set_error_string(context, "pkinit: failed encoding name");
	goto out;
    }
    ret = decode_Name(buf.data, buf.length,
		      &signer_info->sid.u.issuerAndSerialNumber.issuer,
		      NULL);
    free(buf.data);
    if (ret) {
	krb5_set_error_string(context, "pkinit: failed to parse Name");
	goto out;
    }
    signer_info->sid.element = choice_CMSIdentifier_issuerAndSerialNumber;

    serial = &signer_info->sid.u.issuerAndSerialNumber.serialNumber;
    {
	ASN1_INTEGER *isn = X509_get_serialNumber(user_cert);
	BIGNUM *bn = ASN1_INTEGER_to_BN(isn, NULL);
	if (bn == NULL) {
	    ret = ENOMEM;
	    krb5_set_error_string(context, "pkinit: failed allocating "
				  "serial number");
	    goto out;
	}
	ret = BN_to_integer(context, bn, serial);
	BN_free(bn);
	if (ret) {
	    krb5_set_error_string(context, "pkinit: failed encoding "
				  "serial number");
	    goto out;
	}
    }

    ret = set_digest_alg(&signer_info->digestAlgorithm,
			 oid_id_secsig_sha_1(), "\x05\x00", 2);
    if (ret) {
	krb5_set_error_string(context, "malloc: out of memory");
	goto out;
    }

    signer_info->signedAttrs = NULL;
    signer_info->unsignedAttrs = NULL;

    copy_oid(oid_id_pkcs1_rsaEncryption(),
	     &signer_info->signatureAlgorithm.algorithm);
    signer_info->signatureAlgorithm.parameters = NULL;

    buf.data = malloc(EVP_PKEY_size(id->private_key));
    if (buf.data == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	ret = ENOMEM;
	goto out;
    }

    EVP_SignInit(&md, EVP_sha1());
    EVP_SignUpdate(&md,
		   sd.encapContentInfo.eContent->data,
		   sd.encapContentInfo.eContent->length);
    ret = EVP_SignFinal(&md, buf.data, &len, id->private_key);
    if (ret != 1) {
	free(buf.data);
	krb5_set_error_string(context, "PKINIT: failed to sign with "
			      "private key: %s",
			      ERR_error_string(ERR_get_error(), NULL));
	ret = EINVAL;
	goto out;
    }

    signer_info->signature.data = buf.data;
    signer_info->signature.length = len;

    ALLOC_SEQ(&sd.digestAlgorithms, 1);
    if (sd.digestAlgorithms.val == NULL) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }

    ret = set_digest_alg(&sd.digestAlgorithms.val[0],
			 oid_id_secsig_sha_1(), "\x05\x00", 2);
    if (ret) {
	krb5_set_error_string(context, "malloc: out of memory");
	goto out;
    }

    ALLOC(sd.certificates, 1);
    if (sd.certificates == NULL) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }

    i = sk_X509_num(id->cert);
    sd.certificates->val = malloc(sizeof(sd.certificates->val[0]) * i);
    if (sd.certificates->val == NULL) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }
    sd.certificates->len = i;

    for (i = 0; i < sk_X509_num(id->cert); i++) {
	OPENSSL_ASN1_MALLOC_ENCODE(X509, 
				   sd.certificates->val[i].data,
				   sd.certificates->val[i].length,
				   sk_X509_value(id->cert, i),
				   ret);
	if (ret) {
	    krb5_clear_error_string(context);
	    goto out;
	}
    }

    ASN1_MALLOC_ENCODE(SignedData, sd_data->data, sd_data->length, 
		       &sd, &size, ret);
    if (ret) {
	krb5_set_error_string(context, "SignedData failed %d", ret);
	goto out;
    }
    if (sd_data->length != size)
	krb5_abortx(context, "internal ASN1 encoder error");

 out:
    free_SignedData(&sd);

    return ret;
}

static krb5_error_code
build_auth_pack(krb5_context context,
		unsigned nonce,
		krb5_pk_init_ctx ctx,
		DH *dh,
		const KDC_REQ_BODY *body,
		AuthPack *a)
{
    size_t buf_size, len;
    krb5_error_code ret;
    void *buf;
    krb5_timestamp sec;
    int32_t usec;
    Checksum checksum;

    krb5_clear_error_string(context);

    memset(&checksum, 0, sizeof(checksum));

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
			       CKSUMTYPE_SHA1,
			       buf,
			       len,
			       &checksum);
    free(buf);
    if (ret) 
	return ret;

    ALLOC(a->pkAuthenticator.paChecksum, 1);
    if (a->pkAuthenticator.paChecksum == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    ret = krb5_data_copy(a->pkAuthenticator.paChecksum,
			 checksum.checksum.data, checksum.checksum.length);
    free_Checksum(&checksum);
    if (ret)
	return ret;

    if (dh) {
	DomainParameters dp;
	heim_integer dh_pub_key;
	krb5_data dhbuf;
	size_t size;

	if (1 /* support_cached_dh */) {
	    ALLOC(a->clientDHNonce, 1);
	    if (a->clientDHNonce == NULL) {
		krb5_clear_error_string(context);
		return ENOMEM;
	    }
	    ret = krb5_data_alloc(a->clientDHNonce, 40);
	    if (a->clientDHNonce == NULL) {
		krb5_clear_error_string(context);
		return ENOMEM;
	    }
	    memset(a->clientDHNonce->data, 0, a->clientDHNonce->length);
	    ret = krb5_copy_data(context, a->clientDHNonce, 
				 &ctx->clientDHNonce);
	    if (ret)
		return ret;
	}

	ALLOC(a->clientPublicValue, 1);
	if (a->clientPublicValue == NULL)
	    return ENOMEM;
	ret = copy_oid(oid_id_dhpublicnumber(),
		       &a->clientPublicValue->algorithm.algorithm);
	if (ret)
	    return ret;
	
	memset(&dp, 0, sizeof(dp));

	ret = BN_to_integer(context, dh->p, &dp.p);
	if (ret) {
	    free_DomainParameters(&dp);
	    return ret;
	}
	ret = BN_to_integer(context, dh->g, &dp.g);
	if (ret) {
	    free_DomainParameters(&dp);
	    return ret;
	}
	ret = BN_to_integer(context, dh->q, &dp.q);
	if (ret) {
	    free_DomainParameters(&dp);
	    return ret;
	}
	dp.j = NULL;
	dp.validationParms = NULL;

	a->clientPublicValue->algorithm.parameters = 
	    malloc(sizeof(*a->clientPublicValue->algorithm.parameters));
	if (a->clientPublicValue->algorithm.parameters == NULL) {
	    free_DomainParameters(&dp);
	    return ret;
	}

	ASN1_MALLOC_ENCODE(DomainParameters,
			   a->clientPublicValue->algorithm.parameters->data,
			   a->clientPublicValue->algorithm.parameters->length,
			   &dp, &size, ret);
	free_DomainParameters(&dp);
	if (ret)
	    return ret;
	if (size != a->clientPublicValue->algorithm.parameters->length)
	    krb5_abortx(context, "Internal ASN1 encoder error");

	ret = BN_to_integer(context, dh->pub_key, &dh_pub_key);
	if (ret)
	    return ret;

	ASN1_MALLOC_ENCODE(DHPublicKey, dhbuf.data, dhbuf.length,
			   &dh_pub_key, &size, ret);
	free_heim_integer(&dh_pub_key);
	if (ret)
	    return ret;
	if (size != dhbuf.length)
	    krb5_abortx(context, "asn1 internal error");

	a->clientPublicValue->subjectPublicKey.length = dhbuf.length * 8;
	a->clientPublicValue->subjectPublicKey.data = dhbuf.data;
    }

    return ret;
}

krb5_error_code KRB5_LIB_FUNCTION
_krb5_pk_mk_ContentInfo(krb5_context context,
			const krb5_data *buf, 
			const heim_oid *oid,
			struct ContentInfo *content_info)
{
    krb5_error_code ret;

    ret = copy_oid(oid, &content_info->contentType);
    if (ret)
	return ret;
    ALLOC(content_info->content, 1);
    if (content_info->content == NULL)
	return ENOMEM;
    content_info->content->data = malloc(buf->length);
    if (content_info->content->data == NULL)
	return ENOMEM;
    memcpy(content_info->content->data, buf->data, buf->length);
    content_info->content->length = buf->length;
    return 0;
}

static krb5_error_code
pk_mk_padata(krb5_context context,
	     int compat,
	     krb5_pk_init_ctx ctx,
	     const KDC_REQ_BODY *req_body,
	     unsigned nonce,
	     METHOD_DATA *md)
{
    struct ContentInfo content_info;
    krb5_error_code ret;
    const heim_oid *oid;
    size_t size;
    krb5_data buf, sd_buf;
    int pa_type;

    krb5_data_zero(&buf);
    krb5_data_zero(&sd_buf);
    memset(&content_info, 0, sizeof(content_info));

    if (compat == COMPAT_WIN2K) {
	AuthPack_Win2k ap;
	krb5_timestamp sec;
	int32_t usec;

	memset(&ap, 0, sizeof(ap));

	/* fill in PKAuthenticator */
	ret = copy_PrincipalName(req_body->sname, &ap.pkAuthenticator.kdcName);
	if (ret) {
	    free_AuthPack_Win2k(&ap);
	    krb5_clear_error_string(context);
	    goto out;
	}
	ret = copy_Realm(&req_body->realm, &ap.pkAuthenticator.kdcRealm);
	if (ret) {
	    free_AuthPack_Win2k(&ap);
	    krb5_clear_error_string(context);
	    goto out;
	}

	krb5_us_timeofday(context, &sec, &usec);
	ap.pkAuthenticator.ctime = sec;
	ap.pkAuthenticator.cusec = usec;
	ap.pkAuthenticator.nonce = nonce;

	ASN1_MALLOC_ENCODE(AuthPack_Win2k, buf.data, buf.length,
			   &ap, &size, ret);
	free_AuthPack_Win2k(&ap);
	if (ret) {
	    krb5_set_error_string(context, "AuthPack_Win2k: %d", ret);
	    goto out;
	}
	if (buf.length != size)
	    krb5_abortx(context, "internal ASN1 encoder error");

	oid = oid_id_pkcs7_data();
    } else if (compat == COMPAT_IETF) {
	AuthPack ap;
	
	memset(&ap, 0, sizeof(ap));

	ret = build_auth_pack(context, nonce, ctx, ctx->dh, req_body, &ap);
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

	oid = oid_id_pkauthdata();
    } else
	krb5_abortx(context, "internal pkinit error");

    ret = _krb5_pk_create_sign(context,
			       oid,
			       &buf,
			       ctx->id, 
			       &sd_buf);
    krb5_data_free(&buf);
    if (ret)
	goto out;

    ret = _krb5_pk_mk_ContentInfo(context, &sd_buf, oid_id_pkcs7_signedData(), 
				  &content_info);
    krb5_data_free(&sd_buf);
    if (ret)
	goto out;

    ASN1_MALLOC_ENCODE(ContentInfo, buf.data, buf.length,
		       &content_info, &size, ret);
    if (ret)
	goto out;
    if (buf.length != size)
	krb5_abortx(context, "Internal ASN1 encoder error");

    if (compat == COMPAT_WIN2K) {
	PA_PK_AS_REQ_Win2k winreq;

	pa_type = KRB5_PADATA_PK_AS_REQ_WIN;

	memset(&winreq, 0, sizeof(winreq));

	winreq.signed_auth_pack = buf;

	ASN1_MALLOC_ENCODE(PA_PK_AS_REQ_Win2k, buf.data, buf.length,
			   &winreq, &size, ret);
	free_PA_PK_AS_REQ_Win2k(&winreq);

    } else if (compat == COMPAT_IETF) {
	PA_PK_AS_REQ req;

	pa_type = KRB5_PADATA_PK_AS_REQ;

	memset(&req, 0, sizeof(req));
	req.signedAuthPack = buf;	

	/* XXX tell the kdc what CAs the client is willing to accept */
	req.trustedCertifiers = NULL;
	req.kdcPkId = NULL;

	ASN1_MALLOC_ENCODE(PA_PK_AS_REQ, buf.data, buf.length,
			   &req, &size, ret);

	free_PA_PK_AS_REQ(&req);

    } else
	krb5_abortx(context, "internal pkinit error");
    if (ret) {
	krb5_set_error_string(context, "PA-PK-AS-REQ %d", ret);
	goto out;
    }
    if (buf.length != size)
	krb5_abortx(context, "Internal ASN1 encoder error");

    ret = krb5_padata_add(context, md, pa_type, buf.data, buf.length);
    if (ret)
	free(buf.data);

    if (ret == 0 && compat == COMPAT_WIN2K)
	krb5_padata_add(context, md, KRB5_PADATA_PK_AS_09_BINDING, NULL, 0);

out:
    free_ContentInfo(&content_info);

    return ret;
}


krb5_error_code KRB5_LIB_FUNCTION 
_krb5_pk_mk_padata(krb5_context context,
		   void *c,
		   const KDC_REQ_BODY *req_body,
		   unsigned nonce,
		   METHOD_DATA *md)
{
    krb5_pk_init_ctx ctx = c;
    int win2k_compat, type;

    win2k_compat = krb5_config_get_bool_default(context, NULL,
						FALSE,
						"realms",
						req_body->realm,
						"win2k_pkinit",
						NULL);
    if (context->pkinit_flags & KRB5_PKINIT_WIN2K)
	win2k_compat = 1;

    if (win2k_compat) {
	ctx->require_binding = 
	    krb5_config_get_bool_default(context, NULL,
					 FALSE,
					 "realms",
					 req_body->realm,
					 "win2k_pkinit_require_binding",
					 NULL);
	type = COMPAT_WIN2K;
    } else
	type = COMPAT_IETF;

    return pk_mk_padata(context, type, ctx, req_body, nonce, md);
}

static krb5_boolean
pk_peer_compare(krb5_context context,
		const SignerIdentifier *peer1, 
		X509 *peer2)
{
    switch (peer1->element) {
    case choice_CMSIdentifier_issuerAndSerialNumber: {
	ASN1_INTEGER *i;
	const heim_integer *serial;
	X509_NAME *name;
	unsigned char *p;
	size_t len;

	i = X509_get_serialNumber(peer2);
	serial = &peer1->u.issuerAndSerialNumber.serialNumber;

	if (i->length != serial->length ||
	    memcmp(i->data, serial->data, i->length) != 0)
	    return FALSE;

	p = peer1->u.issuerAndSerialNumber.issuer._save.data;
	len = peer1->u.issuerAndSerialNumber.issuer._save.length;
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
    case choice_CMSIdentifier_subjectKeyIdentifier:
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
	return ENOMEM;
    }

    key->keytype = 0;
    key->keyvalue.length = ret;
    key->keyvalue.data = malloc(ret);
    if (key->keyvalue.data == NULL) {
	free(buf);
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }
    memcpy(key->keyvalue.data, buf, ret);
    free(buf);
    return 0;
}


static krb5_error_code 
pk_verify_chain_standard(krb5_context context,
			 struct krb5_pk_identity *id,
			 const SignerIdentifier *client,
			 STACK_OF(X509) *chain,
			 X509 **client_cert)
{
    X509_STORE *cert_store = NULL;
    X509_STORE_CTX *store_ctx = NULL;
    X509 *cert = NULL;
    int i;
    int ret;

    ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
    for (i = 0; i < sk_X509_num(chain); i++) {
	cert = sk_X509_value(chain, i);
	if (pk_peer_compare(context, client, cert) == TRUE) {
	    ret = 0;
	    break;
	}
    }
    if (ret) {
	krb5_set_error_string(context, "PKINIT: verify chain failed "
			      "to find client in chain");
	return ret;
    }

    cert_store = X509_STORE_new();
    if (cert_store == NULL) {
	ret = ENOMEM;
	krb5_set_error_string(context, "PKINIT: can't create X509 store: %s",
			      ERR_error_string(ERR_get_error(), NULL));
    }

    store_ctx = X509_STORE_CTX_new();
    if (store_ctx == NULL) {
	ret = ENOMEM;
	krb5_set_error_string(context,
			      "PKINIT: can't create X509 store ctx: %s",
			      ERR_error_string(ERR_get_error(), NULL));
	goto end;
    }
   
    X509_STORE_CTX_init(store_ctx, cert_store, cert, chain);
    X509_STORE_CTX_trusted_stack(store_ctx, id->trusted_certs);
    X509_verify_cert(store_ctx);
    /* the last checked certificate is in store_ctx->current_cert */
    krb5_clear_error_string(context);
    switch(store_ctx->error) {
    case X509_V_OK:
	ret = 0;
	break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	ret = KRB5_KDC_ERR_CANT_VERIFY_CERTIFICATE;
	krb5_set_error_string(context, "PKINIT: failed to verify "
			      "certificate: %s ",
			      X509_verify_cert_error_string(store_ctx->error));
	break;
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_CERT_HAS_EXPIRED:
	ret = KRB5_KDC_ERR_INVALID_CERTIFICATE;
	krb5_set_error_string(context, "PKINIT: invalid certificate: %s ",
			      X509_verify_cert_error_string(store_ctx->error));
	break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    case X509_V_ERR_INVALID_CA:
	ret = KRB5_KDC_ERR_INVALID_CERTIFICATE;
	krb5_set_error_string(context, "PKINIT: unknown CA or can't "
			      "verify certificate: %s",
			      X509_verify_cert_error_string(store_ctx->error));
	break;
    default:
	ret = KRB5_KDC_ERR_INVALID_CERTIFICATE; /* XXX */
	krb5_set_error_string(context, "PKINIT: failed to verify "
			      "certificate: %s (%ld) ",
			      X509_verify_cert_error_string(store_ctx->error),
			      (long)store_ctx->error);
	break;
    }
    if (ret)
	goto end;

    /* 
     * Since X509_verify_cert() doesn't do CRL checking at all, we have to
     * perform own verification against CRLs
     */
    /*
     * XXX add crl checking
     */

    if (client_cert && cert)
	*client_cert = X509_dup(cert);

 end:
    if (cert_store)
	X509_STORE_free(cert_store);
    if (store_ctx)
	X509_STORE_CTX_free(store_ctx);
    return ret;
}

static int
cert_to_X509(krb5_context context, CertificateSet *set,
	     STACK_OF(X509_CRL) **certs)
{
    krb5_error_code ret;
    int i;

    *certs = sk_X509_new_null();

    if (set == NULL)
	return 0;

    ret = 0;
    for (i = 0; i < set->len; i++) {
	unsigned char *p;
	X509 *cert;

	p = set->val[i].data;
	cert = d2i_X509(NULL, &p, set->val[i].length);
	if (cert == NULL) {
	    ret = ASN1_BAD_FORMAT;
	    break;
	}
	sk_X509_insert(*certs, cert, i);
    }
    if (ret) {
	krb5_set_error_string(context,
			      "PKINIT: Failed to decode certificate chain");
	sk_X509_free(*certs);
	*certs = NULL;
    }
    return ret;
}

krb5_error_code KRB5_LIB_FUNCTION
_krb5_pk_verify_sign(krb5_context context,
		     const void *data,
		     size_t length,
		     struct krb5_pk_identity *id,
		     heim_oid *contentType,
		     krb5_data *content,
		     struct krb5_pk_cert **signer)
{
    STACK_OF(X509) *certificates;
    SignerInfo *signer_info;
    const EVP_MD *evp_type;
    EVP_PKEY *public_key;
    krb5_error_code ret;
    EVP_MD_CTX md;
    X509 *cert = NULL;
    SignedData sd;
    size_t size;
    
    *signer = NULL;
    krb5_data_zero(content);
    contentType->length = 0;
    contentType->components = NULL;

    memset(&sd, 0, sizeof(sd));

    ret = decode_SignedData(data, length, &sd, &size);
    if (ret) {
	krb5_set_error_string(context, 
			      "PKINIT: decoding failed SignedData: %d",
			      ret);
	goto out;
    }

    if (sd.encapContentInfo.eContent == NULL) {
	krb5_set_error_string(context, 
			      "PKINIT: signature missing encapContent");
	ret = KRB5KRB_AP_ERR_MSG_TYPE;
	goto out;
    }

    /* XXX Check CMS version */

    if (sd.signerInfos.len < 1) {
	krb5_set_error_string(context,
			      "PKINIT: signature information missing from "
			      "pkinit response");
	ret = KRB5_KDC_ERR_INVALID_SIG;
	goto out;
    }

    signer_info = &sd.signerInfos.val[0];
  
    {
	CertificateSet set;
	set.val = sd.certificates->val;
	set.len = sd.certificates->len;

	ret = cert_to_X509(context, &set, &certificates);
    }
    if (ret) {
	krb5_set_error_string(context,
			      "PKINIT: failed to decode Certificates");
	goto out;
    }

    ret = pk_verify_chain_standard(context, id,
				   &signer_info->sid,
				   certificates,
				   &cert);
    sk_X509_free(certificates);
    if (ret)
	goto out;
  
    if (signer_info->signature.length == 0) {
	free_SignedData(&sd);
	X509_free(cert);
	krb5_set_error_string(context, "PKINIT: signature missing from"
			      "pkinit response");
	return KRB5_KDC_ERR_INVALID_SIG; 
    }

    public_key = X509_get_pubkey(cert);

    /* verify signature */
    if (heim_oid_cmp(&signer_info->digestAlgorithm.algorithm,
		oid_id_pkcs1_sha1WithRSAEncryption()) == 0)
	evp_type = EVP_sha1();
    else if (heim_oid_cmp(&signer_info->digestAlgorithm.algorithm,
			  oid_id_pkcs1_md5WithRSAEncryption()) == 0) 
	evp_type = EVP_md5();
    else if (heim_oid_cmp(&signer_info->digestAlgorithm.algorithm, 
			  oid_id_secsig_sha_1()) == 0)
	evp_type = EVP_sha1();
    else {
	X509_free(cert);
	krb5_set_error_string(context, "PKINIT: The requested digest "
			      "algorithm is not supported");
	ret = KRB5_KDC_ERR_INVALID_SIG;
	goto out;
    }

    EVP_VerifyInit(&md, evp_type);
    EVP_VerifyUpdate(&md,
		     sd.encapContentInfo.eContent->data,
		     sd.encapContentInfo.eContent->length);
    ret = EVP_VerifyFinal(&md,
			  signer_info->signature.data,
			  signer_info->signature.length,
			  public_key);
    if (ret != 1) {
	X509_free(cert);
	krb5_set_error_string(context, "PKINIT: signature didn't verify: %s",
			      ERR_error_string(ERR_get_error(), NULL));
	ret = KRB5_KDC_ERR_INVALID_SIG;
	goto out;
    }

    ret = copy_oid(&sd.encapContentInfo.eContentType, contentType);
    if (ret) {
	krb5_clear_error_string(context);
	goto out;
    }

    content->data = malloc(sd.encapContentInfo.eContent->length);
    if (content->data == NULL) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }
    content->length = sd.encapContentInfo.eContent->length;
    memcpy(content->data,sd.encapContentInfo.eContent->data,content->length);

    *signer = malloc(sizeof(**signer));
    if (*signer == NULL) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }
    (*signer)->cert = cert;

 out:
    free_SignedData(&sd);
    if (ret) {
	free_oid(contentType);
	krb5_data_free(content);
    }
    return ret;
}

static krb5_error_code
get_reply_key_win(krb5_context context,
		  const krb5_data *content,
		  unsigned nonce,
		  krb5_keyblock **key)
{
    ReplyKeyPack_Win2k key_pack;
    krb5_error_code ret;
    size_t size;

    ret = decode_ReplyKeyPack_Win2k(content->data,
				    content->length,
				    &key_pack,
				    &size);
    if (ret) {
	krb5_set_error_string(context, "PKINIT decoding reply key failed");
	free_ReplyKeyPack_Win2k(&key_pack);
	return ret;
    }
     
    if (key_pack.nonce != nonce) {
	krb5_set_error_string(context, "PKINIT enckey nonce is wrong");
	free_ReplyKeyPack_Win2k(&key_pack);
	return KRB5KRB_AP_ERR_MODIFIED;
    }

    *key = malloc (sizeof (**key));
    if (*key == NULL) {
	krb5_set_error_string(context, "PKINIT failed allocating reply key");
	free_ReplyKeyPack_Win2k(&key_pack);
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    ret = copy_EncryptionKey(&key_pack.replyKey, *key);
    free_ReplyKeyPack_Win2k(&key_pack);
    if (ret) {
	krb5_set_error_string(context, "PKINIT failed copying reply key");
	free(*key);
    }

    return ret;
}

static krb5_error_code
get_reply_key(krb5_context context,
	      const krb5_data *content,
	      const krb5_data *req_buffer,
	      krb5_keyblock **key)
{
    ReplyKeyPack key_pack;
    krb5_error_code ret;
    size_t size;

    ret = decode_ReplyKeyPack(content->data,
			      content->length,
			      &key_pack,
			      &size);
    if (ret) {
	krb5_set_error_string(context, "PKINIT decoding reply key failed");
	free_ReplyKeyPack(&key_pack);
	return ret;
    }
    
    {
	krb5_crypto crypto;

	/* 
	 * XXX Verify kp.replyKey is a allowed enctype in the
	 * configuration file
	 */

	ret = krb5_crypto_init(context, &key_pack.replyKey, 0, &crypto);
	if (ret) {
	    free_ReplyKeyPack(&key_pack);
	    return ret;
	}

	ret = krb5_verify_checksum(context, crypto, 6,
				   req_buffer->data, req_buffer->length,
				   &key_pack.asChecksum);
	krb5_crypto_destroy(context, crypto);
	if (ret) {
	    free_ReplyKeyPack(&key_pack);
	    return ret;
	}
    }

    *key = malloc (sizeof (**key));
    if (*key == NULL) {
	krb5_set_error_string(context, "PKINIT failed allocating reply key");
	free_ReplyKeyPack(&key_pack);
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    ret = copy_EncryptionKey(&key_pack.replyKey, *key);
    free_ReplyKeyPack(&key_pack);
    if (ret) {
	krb5_set_error_string(context, "PKINIT failed copying reply key");
	free(*key);
    }

    return ret;
}


static krb5_error_code
pk_verify_host(krb5_context context, struct krb5_pk_cert *host)
{
    /* XXX */
    return 0;
}

static krb5_error_code
pk_rd_pa_reply_enckey(krb5_context context,
		      int type,
                      ContentInfo *rep,
		      krb5_pk_init_ctx ctx,
		      krb5_enctype etype,
		      const krb5_krbhst_info *hi,
	       	      unsigned nonce,
		      const krb5_data *req_buffer,
	       	      PA_DATA *pa,
	       	      krb5_keyblock **key) 
{
    krb5_error_code ret;
    EnvelopedData ed;
    krb5_keyblock tmp_key;
    krb5_crypto crypto;
    krb5_data plain;
    KeyTransRecipientInfo *ri;
    int length;
    size_t size;
    X509 *user_cert;
    void *p;
    krb5_boolean bret;
    krb5_data content;
    heim_oid contentType = { 0, NULL };
    struct krb5_pk_cert *host = NULL;
    heim_octet_string encryptedContent;
    heim_octet_string *any;
    krb5_data ivec;
    krb5_data params;


    memset(&tmp_key, 0, sizeof(tmp_key));
    memset(&ed, 0, sizeof(ed));
    krb5_data_zero(&plain);
    krb5_data_zero(&content);
    krb5_data_zero(&encryptedContent);
    krb5_data_zero(&ivec);

    user_cert = sk_X509_value(ctx->id->cert, 0);

    if (heim_oid_cmp(oid_id_pkcs7_envelopedData(), &rep->contentType)) {
	krb5_set_error_string(context, "PKINIT: Invalid content type");
	return EINVAL;
    }

    if (rep->content == NULL) {
	krb5_set_error_string(context, "PKINIT: No content in reply");
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
	krb5_set_error_string(context, "pkinit: Number of recipient infos "
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

    if (heim_oid_cmp(oid_id_pkcs1_rsaEncryption(),
		     &ri->keyEncryptionAlgorithm.algorithm)) {
	krb5_set_error_string(context, "PKINIT: invalid content type");
	return EINVAL;
    }
    
    ret = pk_decrypt_key(context, &ri->encryptedKey,
			 ctx->id->private_key, &tmp_key);
    if (ret)
	goto out;

  
    /* 
     * Try to verify content type. We can't do this for W2K case
     * because W2K/W2K3 sends id-pkcs7-data, but Windows Vista sends
     * id-pkcs7-signedData to all versions, even W2K clients.
     */

    if (type != COMPAT_WIN2K) {
	if (heim_oid_cmp(&ed.encryptedContentInfo.contentType, oid_id_pkcs7_signedData())) {
	    ret = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto out;
	}
    }

    if (ed.encryptedContentInfo.encryptedContent == NULL) {
	krb5_set_error_string(context, "PKINIT: OPTIONAL encryptedContent "
			      "field not filled in in KDC reply");
	ret = KRB5_BADMSGTYPE;
	goto out;
    }

    any = ed.encryptedContentInfo.encryptedContent;
    ret = der_get_octet_string(any->data, any->length,
			       &encryptedContent, NULL);
    if (ret) {
	krb5_set_error_string(context,
			      "PKINIT: encryptedContent content invalid");
	goto out;
    }

    if (ed.encryptedContentInfo.contentEncryptionAlgorithm.parameters == NULL){
	krb5_set_error_string(context,
			      "PKINIT: encryptedContent parameter missing");
	ret = KRB5_BADMSGTYPE;
	goto out;
    }

    params.data = ed.encryptedContentInfo.contentEncryptionAlgorithm.parameters->data;
    params.length = ed.encryptedContentInfo.contentEncryptionAlgorithm.parameters->length;

    ret = _krb5_oid_to_enctype(context,
			       &ed.encryptedContentInfo.contentEncryptionAlgorithm.algorithm,
			       &tmp_key.keytype);
    if (ret)
	goto out;

    ret = krb5_crypto_init(context, &tmp_key, 0, &crypto);
    if (ret)
	goto out;

    ret = krb5_crypto_get_params(context, crypto, &params, &ivec);
    if (ret)
	goto out;

    ret = krb5_decrypt_ivec(context, crypto,
			    0,
			    encryptedContent.data,
			    encryptedContent.length,
			    &plain,
			    ivec.data);

    p = plain.data;
    length = plain.length;

    /* win2k uses ContentInfo */
    if (type == COMPAT_WIN2K) {
	ContentInfo ci;

	ret = decode_ContentInfo(p, length, &ci, &size);
	if (ret) {
	    krb5_set_error_string(context,
				  "PKINIT: failed decoding ContentInfo: %d",
				  ret);
	    goto out;
	}

	if (heim_oid_cmp(&ci.contentType, oid_id_pkcs7_signedData())) {
	    ret = EINVAL; /* XXX */
	    krb5_set_error_string(context, "PKINIT: Invalid content type");
	    goto out;
	}
	p = ci.content->data;
	length = ci.content->length;
    }

    ret = _krb5_pk_verify_sign(context, 
			       p,
			       length,
			       ctx->id,
			       &contentType,
			       &content,
			       &host);
    if (ret)
	goto out;

    /* make sure that it is the kdc's certificate */
    ret = pk_verify_host(context, host);
    if (ret) {
	krb5_set_error_string(context, "PKINIT: failed verify host: %d", ret);
	goto out;
    }

#if 0
    if (type == COMPAT_WIN2K) {
	if (heim_oid_cmp(&contentType, oid_id_pkcs7_data()) != 0) {
	    krb5_set_error_string(context, "PKINIT: reply key, wrong oid");
	    ret = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto out;
	}
    } else {
	if (heim_oid_cmp(&contentType, oid_id_pkrkeydata()) != 0) {
	    krb5_set_error_string(context, "PKINIT: reply key, wrong oid");
	    ret = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto out;
	}
    }
#endif

    switch(type) {
    case COMPAT_WIN2K:
	ret = get_reply_key(context, &content, req_buffer, key);
	if (ret != 0 && ctx->require_binding == 0)
	    ret = get_reply_key_win(context, &content, nonce, key);
	break;
    case COMPAT_IETF:
	ret = get_reply_key(context, &content, req_buffer, key);
	break;
    }
    if (ret)
	goto out;

    /* XXX compare given etype with key->etype */

 out:
    if (host)
	_krb5_pk_cert_free(host);
    free_oid(&contentType);
    free_octet_string(&encryptedContent);
    krb5_data_free(&content);
    krb5_free_keyblock_contents(context, &tmp_key);
    krb5_data_free(&plain);
    krb5_data_free(&ivec);

    return ret;
}

static krb5_error_code
pk_rd_pa_reply_dh(krb5_context context,
                  ContentInfo *rep,
		  krb5_pk_init_ctx ctx,
		  krb5_enctype etype,
		  const krb5_krbhst_info *hi,
		  const DHNonce *c_n,
		  const DHNonce *k_n,
                  unsigned nonce,
                  PA_DATA *pa,
                  krb5_keyblock **key)
{
    unsigned char *p, *dh_gen_key = NULL;
    ASN1_INTEGER *dh_pub_key = NULL;
    struct krb5_pk_cert *host = NULL;
    BIGNUM *kdc_dh_pubkey = NULL;
    KDCDHKeyInfo kdc_dh_info;
    heim_oid contentType = { 0, NULL };
    krb5_data content;
    krb5_error_code ret;
    int dh_gen_keylen;
    size_t size;

    krb5_data_zero(&content);
    memset(&kdc_dh_info, 0, sizeof(kdc_dh_info));

    if (heim_oid_cmp(oid_id_pkcs7_signedData(), &rep->contentType)) {
	krb5_set_error_string(context, "PKINIT: Invalid content type");
	return EINVAL;
    }

    if (rep->content == NULL) {
	krb5_set_error_string(context, "PKINIT: No content in reply");
	return EINVAL;
    }

    ret = _krb5_pk_verify_sign(context, 
			       rep->content->data,
			       rep->content->length,
			       ctx->id,
			       &contentType,
			       &content,
			       &host);
    if (ret)
	goto out;

    /* make sure that it is the kdc's certificate */
    ret = pk_verify_host(context, host);
    if (ret)
	goto out;

    if (heim_oid_cmp(&contentType, oid_id_pkdhkeydata())) {
	krb5_set_error_string(context, "pkinit - dh reply contains wrong oid");
	ret = KRB5KRB_AP_ERR_MSG_TYPE;
	goto out;
    }

    ret = decode_KDCDHKeyInfo(content.data,
			      content.length,
			      &kdc_dh_info,
			      &size);

    if (ret)
	goto out;

    if (kdc_dh_info.nonce != nonce) {
	krb5_set_error_string(context, "PKINIT: DH nonce is wrong");
	ret = KRB5KRB_AP_ERR_MODIFIED;
	goto out;
    }

    if (kdc_dh_info.dhKeyExpiration) {
	if (k_n == NULL) {
	    krb5_set_error_string(context, "pkinit; got key expiration "
				  "without server nonce");
	    ret = KRB5KRB_ERR_GENERIC;
	    goto out;
	}
	if (c_n == NULL) {
	    krb5_set_error_string(context, "pkinit; got DH reuse but no "
				  "client nonce");
	    ret = KRB5KRB_ERR_GENERIC;
	    goto out;
	}
    } else {
	if (k_n) {
	    krb5_set_error_string(context, "pkinit; got server nonce "
				  "without key expiration");
	    ret = KRB5KRB_ERR_GENERIC;
	    goto out;
	}
	c_n = NULL;
    }


    p = kdc_dh_info.subjectPublicKey.data;
    size = (kdc_dh_info.subjectPublicKey.length + 7) / 8;
    dh_pub_key = d2i_ASN1_INTEGER(NULL, &p, size);
    if (dh_pub_key == NULL) {
	krb5_set_error_string(context,
			      "PKINIT: Can't parse KDC's DH public key");
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }

    kdc_dh_pubkey = ASN1_INTEGER_to_BN(dh_pub_key, NULL);
    if (kdc_dh_pubkey == NULL) {
	krb5_set_error_string(context,
			      "PKINIT: Can't convert KDC's DH public key");
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }

    dh_gen_keylen = DH_size(ctx->dh);
    size = BN_num_bytes(ctx->dh->p);
    if (size < dh_gen_keylen)
	size = dh_gen_keylen;

    dh_gen_key = malloc(size);
    if (dh_gen_key == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	ret = ENOMEM;
	goto out;
    }
    memset(dh_gen_key, 0, size - dh_gen_keylen);

    dh_gen_keylen = DH_compute_key(dh_gen_key + (size - dh_gen_keylen),
				   kdc_dh_pubkey, ctx->dh);
    if (dh_gen_keylen == -1) {
	krb5_set_error_string(context, 
			      "PKINIT: Can't compute Diffie-Hellman key (%s)",
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

    ret = _krb5_pk_octetstring2key(context,
				   etype,
				   dh_gen_key, dh_gen_keylen,
				   c_n, k_n,
				   *key);
    if (ret) {
	krb5_set_error_string(context,
			      "PKINIT: can't create key from DH key");
	free(*key);
	*key = NULL;
	goto out;
    }

 out:
    if (kdc_dh_pubkey)
	BN_free(kdc_dh_pubkey);
    if (dh_gen_key) {
	memset(dh_gen_key, 0, DH_size(ctx->dh));
	free(dh_gen_key);
    }
    if (dh_pub_key)
	ASN1_INTEGER_free(dh_pub_key);
    if (host)
	_krb5_pk_cert_free(host);
    if (content.data)
	krb5_data_free(&content);
    free_KDCDHKeyInfo(&kdc_dh_info);

    return ret;
}

krb5_error_code KRB5_LIB_FUNCTION
_krb5_pk_rd_pa_reply(krb5_context context,
		     void *c,
		     krb5_enctype etype,
		     const krb5_krbhst_info *hi,
		     unsigned nonce,
		     const krb5_data *req_buffer,
		     PA_DATA *pa,
		     krb5_keyblock **key)
{
    krb5_pk_init_ctx ctx = c;
    krb5_error_code ret;
    ContentInfo ci;
    size_t size;

    /* Check for PK-INIT -27 */
    if (pa->padata_type == KRB5_PADATA_PK_AS_REP) {
	PA_PK_AS_REP rep;

	memset(&rep, 0, sizeof(rep));

	ret = decode_PA_PK_AS_REP(pa->padata_value.data,
				  pa->padata_value.length,
				  &rep,
				  &size);
	if (ret)
	    return ret;

	switch (rep.element) {
	case choice_PA_PK_AS_REP_dhInfo:
	    ret = decode_ContentInfo(rep.u.dhInfo.dhSignedData.data,
				     rep.u.dhInfo.dhSignedData.length,
				     &ci,
				     &size);
	    if (ret) {
		krb5_set_error_string(context,
				      "PKINIT: -25 decoding failed DH "
				      "ContentInfo: %d", ret);

		free_PA_PK_AS_REP(&rep);
		break;
	    }
	    ret = pk_rd_pa_reply_dh(context, &ci, ctx, etype, hi,
				    ctx->clientDHNonce,
				    rep.u.dhInfo.serverDHNonce,
				    nonce, pa, key);
	    free_ContentInfo(&ci);
	    free_PA_PK_AS_REP(&rep);

	    break;
	case choice_PA_PK_AS_REP_encKeyPack:
	    ret = decode_ContentInfo(rep.u.encKeyPack.data,
				     rep.u.encKeyPack.length,
				     &ci,
				     &size);
	    free_PA_PK_AS_REP(&rep);
	    if (ret) {
		krb5_set_error_string(context,
				      "PKINIT: -25 decoding failed "
				      "ContentInfo: %d", ret);
		break;
	    }
	    ret = pk_rd_pa_reply_enckey(context, COMPAT_IETF, &ci, ctx,
					etype, hi, nonce, req_buffer, pa, key);
	    free_ContentInfo(&ci);
	    return ret;
	default:
	    free_PA_PK_AS_REP(&rep);
	    krb5_set_error_string(context, "PKINIT: -27 reply "
				  "invalid content type");
	    ret = EINVAL;
	    break;
	}
	if (ret == 0)
	    return ret;
    }

    /* Check for Windows encoding of the AS-REP pa data */ 
    {
	PA_PK_AS_REP_Win2k w2krep;

	memset(&w2krep, 0, sizeof(w2krep));
	
	ret = decode_PA_PK_AS_REP_Win2k(pa->padata_value.data,
					pa->padata_value.length,
					&w2krep,
					&size);
	if (ret) {
	    krb5_set_error_string(context, "PKINIT: Failed decoding windows "
				  "pkinit reply %d", ret);
	    return ret;
	}

	krb5_clear_error_string(context);
	
	switch (w2krep.element) {
	case choice_PA_PK_AS_REP_Win2k_encKeyPack:
	    ret = decode_ContentInfo(w2krep.u.encKeyPack.data,
				     w2krep.u.encKeyPack.length,
				     &ci,
				     &size);
	    free_PA_PK_AS_REP_Win2k(&w2krep);
	    if (ret) {
		krb5_set_error_string(context,
				      "PKINIT: decoding failed "
				      "ContentInfo: %d",
				      ret);
		return ret;
	    }
	    ret = pk_rd_pa_reply_enckey(context, COMPAT_WIN2K, &ci, ctx,
					etype, hi, nonce, NULL, pa, key);
	    free_ContentInfo(&ci);
	    break;
	default:
	    free_PA_PK_AS_REP_Win2k(&w2krep);
	    krb5_set_error_string(context, "PKINIT: win2k reply invalid "
				  "content type");
	    ret = EINVAL;
	    break;
	}
    
    }

    return ret;
}

static int
ssl_pass_cb(char *buf, int size, int rwflag, void *u)
{
    krb5_error_code ret;
    krb5_prompt prompt;
    krb5_data password_data;
    krb5_prompter_fct prompter = u;
   
    password_data.data   = buf;
    password_data.length = size;
    prompt.prompt = "Enter your private key passphrase: ";
    prompt.hidden = 1;
    prompt.reply  = &password_data;
    prompt.type   = KRB5_PROMPT_TYPE_PASSWORD;
   
    ret = (*prompter)(NULL, NULL, NULL, NULL, 1, &prompt);
    if (ret) {
	memset (buf, 0, size);
	return 0;
    }
    return strlen(buf);
}

static krb5_error_code
load_openssl_cert(krb5_context context,
		  const char *file,
		  STACK_OF(X509) **c)
{
    STACK_OF(X509) *certificate;
    krb5_error_code ret;
    FILE *f;

    f = fopen(file, "r");
    if (f == NULL) {
	ret = errno;
	krb5_set_error_string(context, "PKINIT: open failed %s: %s", 
			      file, strerror(ret));
	return ret;
    }

    certificate = sk_X509_new_null();
    while (1) {
	/* see http://www.openssl.org/docs/crypto/pem.html section BUGS */
	X509 *cert;
	cert = PEM_read_X509(f, NULL, NULL, NULL);
	if (cert == NULL) {
	    if (ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE) {
		/* End of file reached. no error */
		ERR_clear_error();
		break;
	    }
	    krb5_set_error_string(context, "PKINIT: Can't read certificate");
	    fclose(f);
	    return HEIM_PKINIT_CERTIFICATE_INVALID;
	}
	sk_X509_insert(certificate, cert, sk_X509_num(certificate));
    }
    fclose(f);
    if (sk_X509_num(certificate) == 0) {
	krb5_set_error_string(context, "PKINIT: No certificate found");
	return HEIM_PKINIT_NO_CERTIFICATE;
    }
    *c = certificate;
    return 0;
}

static krb5_error_code
load_openssl_file(krb5_context context,
		  char *password,
		  krb5_prompter_fct prompter,
		  void *prompter_data,
		  const char *user_id,
		  struct krb5_pk_identity *id)
{
    krb5_error_code ret;
    STACK_OF(X509) *certificate = NULL;
    char *cert_file = NULL, *key_file;
    EVP_PKEY *private_key = NULL;
    FILE *f;

    cert_file = strdup(user_id);
    if (cert_file == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }
    key_file = strchr(cert_file, ',');
    if (key_file == NULL) {
	krb5_set_error_string(context, "PKINIT: key file missing");
	ret = HEIM_PKINIT_NO_PRIVATE_KEY;
	goto out;
    }
    *key_file++ = '\0';

    ret = load_openssl_cert(context, cert_file, &certificate);
    if (ret)
	goto out;

    /* load private key */
    f = fopen(key_file, "r");
    if (f == NULL) {
	ret = errno;
	krb5_set_error_string(context, "PKINIT: open %s: %s",
			      key_file, strerror(ret));
	goto out;
    }
    if (password == NULL || password[0] == '\0') {
	if (prompter == NULL)
	    prompter = krb5_prompter_posix;
	private_key = PEM_read_PrivateKey(f, NULL, ssl_pass_cb, prompter);
    } else
	private_key = PEM_read_PrivateKey(f, NULL, NULL, password);
    fclose(f);
    if (private_key == NULL) {
	krb5_set_error_string(context, "PKINIT: Can't read private key");
	ret = HEIM_PKINIT_PRIVATE_KEY_INVALID;
	goto out;
    }
    ret = X509_check_private_key(sk_X509_value(certificate, 0), private_key);
    if (ret != 1) {
	ret = HEIM_PKINIT_PRIVATE_KEY_INVALID;
	krb5_set_error_string(context,
			      "PKINIT: The private key doesn't match "
			      "the public key certificate");
	goto out;
    }

    id->private_key = private_key;
    id->cert = certificate;

    return 0;
 out:
    if (cert_file)
	free(cert_file);
    if (certificate)
	sk_X509_pop_free(certificate, X509_free);
    if (private_key)
	EVP_PKEY_free(private_key);

    return ret;
}

static int
add_pair(krb5_context context, char *str, char ***cmds, int *num)
{
    char **c;
    char *p;
    int i;

    p = strchr(str, ':');
    if (p) {
	*p = '\0';
	p++;
    }

    /* filter out dup keys */
    for (i = 0; i < *num; i++)
	if (strcmp((*cmds)[i * 2], str) == 0)
	    return 0;

    c = realloc(*cmds, sizeof(*c) * ((*num + 1) * 2));
    if (c == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    c[(*num * 2)] = str;
    c[(*num * 2) + 1] = p;
    *num += 1;
    *cmds = c;
    return 0;
}

static krb5_error_code
eval_pairs(krb5_context context, ENGINE *e, const char *name,
	   const char *type, char **cmds, int num)
{
    int i;

    for (i = 0; i < num; i++) {
	char *a1 = cmds[i * 2], *a2 = cmds[(i * 2) + 1];
	if(!ENGINE_ctrl_cmd_string(e, a1, a2, 0)) {
	    krb5_set_error_string(context,
				  "PKINIT: Failed %scommand (%s - %s:%s): %s", 
				  type, name, a1, a2 ? a2 : "(NULL)",
				  ERR_error_string(ERR_get_error(), NULL));
	    return HEIM_PKINIT_NO_PRIVATE_KEY;
	}
    }
    return 0;
}

struct engine_context {
    char **pre_cmds;
    char **post_cmds;
    int num_pre;
    int num_post;
    char *engine_name;
    char *cert_file;
    char *key_id;
};

static krb5_error_code
parse_openssl_engine_conf(krb5_context context, 
			  struct engine_context *ctx,
			  char *line)
{
    krb5_error_code ret;
    char *last, *p, *q;

    for (p = strtok_r(line, ",", &last);
	 p != NULL;
	 p = strtok_r(NULL, ",", &last)) {

	q = strchr(p, '=');
	if (q == NULL) {
	    krb5_set_error_string(context, 
				  "PKINIT: openssl engine configuration "
				  "key %s missing = and thus value", p);
	    return HEIM_PKINIT_NO_PRIVATE_KEY;
	}
	*q = '\0';
	q++;
	if (strcasecmp("PRE", p) == 0) {
	    ret = add_pair(context, q, &ctx->pre_cmds, &ctx->num_pre);
	    if (ret)
		return ret;
	} else if (strcasecmp("POST", p) == 0) {
	    ret = add_pair(context, q, &ctx->post_cmds, &ctx->num_post);
	    if (ret)
		return ret;
	} else if (strcasecmp("KEY", p) == 0) {
	    ctx->key_id = q;
	} else if (strcasecmp("CERT", p) == 0) {
	    ctx->cert_file = q;
	} else if (strcasecmp("ENGINE", p) == 0) {
	    ctx->engine_name = q;
	} else {
	    krb5_set_error_string(context, 
				  "PKINIT: openssl engine configuration "
				  "key %s is unknown", p);
	    return HEIM_PKINIT_NO_PRIVATE_KEY;
	}
    }
    return 0;
}


static krb5_error_code
load_openssl_engine(krb5_context context,
		    char *password,
		    krb5_prompter_fct prompter,
		    void *prompter_data,
		    const char *string,
		    struct krb5_pk_identity *id)
{
    struct engine_context ctx;
    krb5_error_code ret;
    const char *f;
    char *file_conf = NULL, *user_conf = NULL;
    ENGINE *e = NULL;

    memset(&ctx, 0, sizeof(ctx));

    ENGINE_load_builtin_engines();

    user_conf = strdup(string);
    if (user_conf == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    ret = parse_openssl_engine_conf(context, &ctx, user_conf);
    if (ret)
	goto out;

    f = krb5_config_get_string_default(context, NULL, NULL,
				       "libdefaults", 
				       "pkinit-openssl-engine", 
				       NULL);
    if (f) {
	file_conf = strdup(f);
	if (file_conf) {
	    ret = parse_openssl_engine_conf(context, &ctx, file_conf);
	    if (ret)
		goto out;
	}
    }

    if (ctx.cert_file == NULL) {
	krb5_set_error_string(context, 
			      "PKINIT: openssl engine missing certificate");
	ret = HEIM_PKINIT_NO_CERTIFICATE;
	goto out;
    }
    if (ctx.key_id == NULL) {
	krb5_set_error_string(context,
			      "PKINIT: openssl engine missing key id");
	ret = HEIM_PKINIT_NO_PRIVATE_KEY;
	goto out;
    }
    if (ctx.engine_name == NULL) {
	krb5_set_error_string(context,
			      "PKINIT: openssl engine missing engine name");
	ret = HEIM_PKINIT_NO_PRIVATE_KEY;
	goto out;
    }

    e = ENGINE_by_id(ctx.engine_name);
    if (e == NULL) {
	krb5_set_error_string(context, 
			      "PKINIT: failed getting openssl engine %s: %s", 
			      ctx.engine_name,
			      ERR_error_string(ERR_get_error(), NULL));
	ret = HEIM_PKINIT_NO_PRIVATE_KEY;
	goto out;
    }

    ret = eval_pairs(context, e, ctx.engine_name, "pre", 
		     ctx.pre_cmds, ctx.num_pre);
    if (ret)
	goto out;

    if(!ENGINE_init(e)) {
	ret = HEIM_PKINIT_NO_PRIVATE_KEY;
	krb5_set_error_string(context,
			      "PKINIT: openssl engine init %s failed: %s", 
			      ctx.engine_name,
			      ERR_error_string(ERR_get_error(), NULL));
	ENGINE_free(e);
	goto out;
    }

    ret = eval_pairs(context, e, ctx.engine_name, "post", 
		     ctx.post_cmds, ctx.num_post);
    if (ret)
	goto out;

    /*
     * If the engine supports a LOAD_CERT_CTRL function, lets try
     * it. OpenSC support this function. Eventially this should be
     * a ENGINE_load_cert function if it failes, treat it like a
     * non fatal error.
     */
    {
	struct {
	    const char * cert_id;
	    X509 * cert;
	} parms;

	parms.cert_id = ctx.cert_file;
	parms.cert = NULL;
	ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &parms, NULL, 1); 
	if (parms.cert) {
	    id->cert = sk_X509_new_null();
	    sk_X509_insert(id->cert, parms.cert, 0);	
	}  
    }

    if (id->cert == NULL) {
	ret = load_openssl_cert(context, ctx.cert_file, &id->cert);
	if (ret)
	    goto out;
    }

    {
	UI_METHOD * krb5_ui_method = NULL;
	struct krb5_ui_data ui_data;

	krb5_ui_method = UI_create_method("Krb5 ui method");
	if (krb5_ui_method == NULL) {
	    krb5_set_error_string(context,
				  "PKINIT: failed to setup prompter "
				  "function: %s",
				  ERR_error_string(ERR_get_error(), NULL));
	    ret = HEIM_PKINIT_NO_PRIVATE_KEY;
	    goto out;
	}
	UI_method_set_reader(krb5_ui_method, krb5_ui_method_read_string);

	ui_data.context = context;
	ui_data.prompter = prompter;
	if (prompter == NULL)
	    ui_data.prompter = krb5_prompter_posix;
	ui_data.prompter_data = prompter_data;

    	id->private_key = ENGINE_load_private_key(e,
						  ctx.key_id, 
						  krb5_ui_method,
						  (void*) &ui_data);
	UI_destroy_method(krb5_ui_method);
    }
	
    if (id->private_key == NULL) {
	krb5_set_error_string(context,
			      "PKINIT: failed to load private key: %s",
			      ERR_error_string(ERR_get_error(), NULL));
	ret = HEIM_PKINIT_NO_PRIVATE_KEY;
	goto out;
    }

    ret = X509_check_private_key(sk_X509_value(id->cert, 0), id->private_key);
    if (ret != 1) {
	ret = HEIM_PKINIT_PRIVATE_KEY_INVALID;
	krb5_set_error_string(context,
			      "PKINIT: The private key doesn't match "
			      "the public key certificate");
	goto out;
    }

    if (user_conf)
	free(user_conf);
    if (file_conf)
	free(file_conf);

    id->engine = e;

    return 0;

 out:
    if (user_conf)
	free(user_conf);
    if (file_conf)
	free(file_conf);
    if (e) {
	ENGINE_finish(e); /* make sure all shared libs are unloaded */
	ENGINE_free(e);
    }
	
    return ret;
}

krb5_error_code KRB5_LIB_FUNCTION
_krb5_pk_load_openssl_id(krb5_context context,
			 struct krb5_pk_identity **ret_id,
			 const char *user_id,
			 const char *x509_anchors,
			 krb5_prompter_fct prompter,
			 void *prompter_data,
			 char *password)
{
    STACK_OF(X509) *trusted_certs = NULL;
    struct krb5_pk_identity *id = NULL;
    krb5_error_code ret;
    struct dirent *file;
    char *dirname = NULL;
    DIR *dir;
    FILE *f;
    krb5_error_code (*load_pair)(krb5_context, 
				 char *, 
				 krb5_prompter_fct,
				 void *,
				 const char *,
				 struct krb5_pk_identity *) = NULL;


    *ret_id = NULL;

    if (x509_anchors == NULL) {
	krb5_set_error_string(context, "PKINIT: No root ca directory given");
	return HEIM_PKINIT_NO_VALID_CA;
    }

    if (user_id == NULL) {
	krb5_set_error_string(context,
			      "PKINIT: No user X509 source given given");
	return HEIM_PKINIT_NO_PRIVATE_KEY;
    }

    /* 
     *
     */

    if (strncasecmp(user_id, "FILE:", 5) == 0) {
	load_pair = load_openssl_file;
	user_id += 5;
    } else if (strncasecmp(user_id, "ENGINE:", 7) == 0) {
	load_pair = load_openssl_engine;
	user_id += 7;
    } else {
	krb5_set_error_string(context, "PKINIT: user identity not FILE");
	return HEIM_PKINIT_NO_CERTIFICATE;
    }
    if (strncasecmp(x509_anchors, "OPENSSL-ANCHOR-DIR:", 19) != 0) {
	krb5_set_error_string(context, "PKINIT: anchor OPENSSL-ANCHOR-DIR");
	return HEIM_PKINIT_NO_VALID_CA;
    }
    x509_anchors += 19;

    id = malloc(sizeof(*id));
    if (id == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	ret = ENOMEM;
	goto out;
    }	
    memset(id, 0, sizeof(*id));

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    
    ret = (*load_pair)(context, password, prompter, prompter_data, user_id, id);
    if (ret)
	goto out;

    /* load anchors */

    dirname = strdup(x509_anchors);
    if (dirname == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	ret = ENOMEM;
	goto out;
    }

    {
	size_t len;
	len = strlen(dirname);
	if (dirname[len - 1] == '/')
	    dirname[len - 1] = '\0';
    }

    /* read ca certificates */
    dir = opendir(dirname);
    if (dir == NULL) {
	ret = errno;
	krb5_set_error_string(context, "PKINIT: open directory %s: %s",
			      dirname, strerror(ret));
	goto out;
    }

    trusted_certs = sk_X509_new_null();
    while ((file = readdir(dir)) != NULL) {
	X509 *cert;
	char *filename;

	/*
	 * Assume the certificate filenames constist of hashed subject
	 * name followed by suffix ".0"
	 */

	if (strlen(file->d_name) == 10 && strcmp(&file->d_name[8],".0") == 0) {
	    asprintf(&filename, "%s/%s", dirname, file->d_name);
	    if (filename == NULL) {
		ret = ENOMEM;
		krb5_set_error_string(context, "malloc: out or memory");
		goto out;
	    }
	    f = fopen(filename, "r");
	    if (f == NULL) {
		ret = errno;
		krb5_set_error_string(context, "PKINIT: open %s: %s",
				      filename, strerror(ret));
		free(filename);
		closedir(dir);
		goto out;
	    }
	    cert = PEM_read_X509(f, NULL, NULL, NULL);
	    fclose(f);
	    if (cert != NULL) {
		/* order of the certs is not important */
		sk_X509_push(trusted_certs, cert);
	    }
	    free(filename);
	}
    }
    closedir(dir);

    if (sk_X509_num(trusted_certs) == 0) {
	krb5_set_error_string(context,
			      "PKINIT: No CA certificate(s) found in %s",
			      dirname);
	ret = HEIM_PKINIT_NO_VALID_CA;
	goto out;
    }

    id->trusted_certs = trusted_certs;

    *ret_id = id;

    return 0;

 out:
    if (dirname)
	free(dirname);
    if (trusted_certs)
	sk_X509_pop_free(trusted_certs, X509_free);
    if (id) {
	if (id->cert)
	    sk_X509_pop_free(id->cert, X509_free);
	if (id->private_key)
	    EVP_PKEY_free(id->private_key);
	free(id);
    }

    return ret;
}

static krb5_error_code
select_dh_group(krb5_context context, DH *dh, unsigned long bits, 
		struct krb5_dh_moduli **moduli)
{
    const struct krb5_dh_moduli *m;

    m = moduli[1]; /* XXX */
    if (m == NULL)
	m = moduli[0]; /* XXX */

    dh->p = integer_to_BN(context, "p", &m->p);
    if (dh->p == NULL)
	return ENOMEM;
    dh->g = integer_to_BN(context, "g", &m->g);
    if (dh->g == NULL)
	return ENOMEM;
    dh->q = integer_to_BN(context, "q", &m->q);
    if (dh->q == NULL)
	return ENOMEM;

    return 0;
}

#endif /* PKINIT */

static int
parse_integer(krb5_context context, char **p, const char *file, int lineno, 
	      const char *name, heim_integer *integer)
{
    int ret;
    char *p1;
    p1 = strsep(p, " \t");
    if (p1 == NULL) {
	krb5_set_error_string(context, "moduli file %s missing %s on line %d",
			      file, name, lineno);
	return EINVAL;
    }
    ret = der_parse_hex_heim_integer(p1, integer);
    if (ret) {
	krb5_set_error_string(context, "moduli file %s failed parsing %s "
			      "on line %d",
			      file, name, lineno);
	return ret;
    }

    return 0;
}

krb5_error_code
_krb5_parse_moduli_line(krb5_context context, 
			const char *file,
			int lineno,
			char *p,
			struct krb5_dh_moduli **m)
{
    struct krb5_dh_moduli *m1;
    char *p1;
    int ret;

    *m = NULL;

    m1 = calloc(1, sizeof(*m1));
    if (m1 == NULL) {
	krb5_set_error_string(context, "malloc - out of memory");
	return ENOMEM;
    }

    while (isspace((unsigned char)*p))
	p++;
    if (*p  == '#')
	return 0;
    ret = EINVAL;

    p1 = strsep(&p, " \t");
    if (p1 == NULL) {
	krb5_set_error_string(context, "moduli file %s missing name "
			      "on line %d", file, lineno);
	goto out;
    }
    m1->name = strdup(p1);
    if (p1 == NULL) {
	krb5_set_error_string(context, "malloc - out of memeory");
	ret = ENOMEM;
	goto out;
    }

    p1 = strsep(&p, " \t");
    if (p1 == NULL) {
	krb5_set_error_string(context, "moduli file %s missing bits on line %d",
			      file, lineno);
	goto out;
    }

    m1->bits = atoi(p1);
    if (m1->bits == 0) {
	krb5_set_error_string(context, "moduli file %s have un-parsable "
			      "bits on line %d", file, lineno);
	goto out;
    }
	
    ret = parse_integer(context, &p, file, lineno, "p", &m1->p);
    if (ret)
	goto out;
    ret = parse_integer(context, &p, file, lineno, "g", &m1->g);
    if (ret)
	goto out;
    ret = parse_integer(context, &p, file, lineno, "q", &m1->q);
    if (ret)
	goto out;

    *m = m1;

    return 0;
out:
    free(m1->name);
    free_heim_integer(&m1->p);
    free_heim_integer(&m1->g);
    free_heim_integer(&m1->q);
    free(m1);
    return ret;
}

void
_krb5_free_moduli(struct krb5_dh_moduli **moduli)
{
    int i;
    for (i = 0; moduli[i] != NULL; i++) {
	free(moduli[i]->name);
	free_heim_integer(&moduli[i]->p);
	free_heim_integer(&moduli[i]->g);
	free_heim_integer(&moduli[i]->q);
	free(moduli[i]);
    }
    free(moduli);
}

static const char *default_moduli =
    /* name */
    "RFC2412-MODP-group2 "
    /* bits */
    "1024 "
    /* p */
    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
    "FFFFFFFF" "FFFFFFFF "
    /* g */
    "02 "
    /* q */
    "7FFFFFFF" "FFFFFFFF" "E487ED51" "10B4611A" "62633145" "C06E0E68"
    "94812704" "4533E63A" "0105DF53" "1D89CD91" "28A5043C" "C71A026E"
    "F7CA8CD9" "E69D218D" "98158536" "F92F8A1B" "A7F09AB6" "B6A8E122"
    "F242DABB" "312F3F63" "7A262174" "D31BF6B5" "85FFAE5B" "7A035BF6"
    "F71C35FD" "AD44CFD2" "D74F9208" "BE258FF3" "24943328" "F67329C0"
    "FFFFFFFF" "FFFFFFFF";


krb5_error_code
_krb5_parse_moduli(krb5_context context, const char *file,
		   struct krb5_dh_moduli ***moduli)
{
    /* name bits P G Q */
    krb5_error_code ret;
    struct krb5_dh_moduli **m = NULL, **m2;
    char buf[4096];
    FILE *f;
    int lineno = 0, n = 0;

    *moduli = NULL;

    m = calloc(1, sizeof(m[0]) * 2);
    if (m == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    strlcpy(buf, default_moduli, sizeof(buf));
    ret = _krb5_parse_moduli_line(context, "builtin", 1, buf,  &m[0]);
    if (ret) {
	_krb5_free_moduli(m);
	return ret;
    }
    n = 1;

    if (file == NULL)
	file = MODULI_FILE;

    f = fopen(file, "r");
    if (f == NULL) {
	*moduli = m;
	return 0;
    }

    while(fgets(buf, sizeof(buf), f) != NULL) {
	struct krb5_dh_moduli *element;

	buf[strcspn(buf, "\n")] = '\0';
	lineno++;

	m2 = realloc(m, (n + 2) * sizeof(m[0]));
	if (m2 == NULL) {
	    krb5_set_error_string(context, "malloc: out of memory");
	    _krb5_free_moduli(m);
	    return ENOMEM;
	}
	m = m2;
	
	m[n] = NULL;

	ret = _krb5_parse_moduli_line(context, file, lineno, buf,  &element);
	if (ret) {
	    _krb5_free_moduli(m);
	    return ret;
	}
	if (element == NULL)
	    continue;

	m[n] = element;
	m[n + 1] = NULL;
	n++;
    }
    *moduli = m;
    return 0;
}

krb5_error_code
_krb5_dh_group_ok(krb5_context context, unsigned long bits,
		  heim_integer *p, heim_integer *g, heim_integer *q,
		  struct krb5_dh_moduli **moduli,
		  char **name)
{
    int i;

    if (name)
	*name = NULL;

    for (i = 0; moduli[i] != NULL; i++) {
	if (heim_integer_cmp(&moduli[i]->g, g) == 0 &&
	    heim_integer_cmp(&moduli[i]->p, p) == 0 &&
	    (q == NULL || heim_integer_cmp(&moduli[i]->q, q) == 0))
	{
	    if (bits && bits > moduli[i]->bits) {
		krb5_set_error_string(context, "PKINIT: DH group parameter %s "
				      "no accepted, not enough bits generated",
				      moduli[i]->name);
		return KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
	    }
	    if (name)
		*name = strdup(moduli[i]->name);
	    return 0;
	}
    }
    krb5_set_error_string(context, "PKINIT: DH group parameter no ok");
    return KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
}

void KRB5_LIB_FUNCTION
_krb5_get_init_creds_opt_free_pkinit(krb5_get_init_creds_opt *opt)
{
#ifdef PKINIT
    krb5_pk_init_ctx ctx;

    if (opt->opt_private == NULL || opt->opt_private->pk_init_ctx == NULL)
	return;
    ctx = opt->opt_private->pk_init_ctx;
    if (ctx->dh)
	DH_free(ctx->dh);
	ctx->dh = NULL;
    if (ctx->id) {
	if (ctx->id->cert)
	    sk_X509_pop_free(ctx->id->cert, X509_free);
	if (ctx->id->trusted_certs)
	    sk_X509_pop_free(ctx->id->trusted_certs, X509_free);
	if (ctx->id->private_key)
	    EVP_PKEY_free(ctx->id->private_key);
	if (ctx->id->engine) {
		ENGINE_finish(ctx->id->engine); /* unload shared libs etc */
	    ENGINE_free(ctx->id->engine);
		ctx->id->engine = NULL;
	}
	if (ctx->clientDHNonce) {
	    krb5_free_data(NULL, ctx->clientDHNonce);
	    ctx->clientDHNonce = NULL;
	}
	if (ctx->m)
	    _krb5_free_moduli(ctx->m);
	free(ctx->id);
	ctx->id = NULL;
    }
    opt->opt_private->pk_init_ctx = NULL;
#endif
}
    
krb5_error_code KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_pkinit(krb5_context context,
				   krb5_get_init_creds_opt *opt,
				   krb5_principal principal,
				   const char *user_id,
				   const char *x509_anchors,
				   int flags,
				   krb5_prompter_fct prompter,
				   void *prompter_data,
				   char *password)
{
#ifdef PKINIT
    krb5_error_code ret;

    if (opt->opt_private == NULL) {
	krb5_set_error_string(context, "PKINIT: on non extendable opt");
	return EINVAL;
    }

    opt->opt_private->pk_init_ctx = 
	calloc(1, sizeof(*opt->opt_private->pk_init_ctx));
    if (opt->opt_private->pk_init_ctx == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }
    opt->opt_private->pk_init_ctx->dh = NULL;
    opt->opt_private->pk_init_ctx->id = NULL;
    opt->opt_private->pk_init_ctx->clientDHNonce = NULL;
    opt->opt_private->pk_init_ctx->require_binding = 0;

    ret = _krb5_pk_load_openssl_id(context,
				   &opt->opt_private->pk_init_ctx->id,
				   user_id,
				   x509_anchors,
				   prompter,
				   prompter_data,
				   password);
    if (ret) {
	free(opt->opt_private->pk_init_ctx);
	opt->opt_private->pk_init_ctx = NULL;
	return ret;
    }

    if ((flags & 2) == 0) {
	const char *moduli_file;

	moduli_file = krb5_config_get_string(context, NULL,
					     "libdefaults",
					     "moduli",
					     NULL);

	ret = _krb5_parse_moduli(context, moduli_file, 
				 &opt->opt_private->pk_init_ctx->m);
	if (ret) {
	    _krb5_get_init_creds_opt_free_pkinit(opt);
	    return ret;
	}
	
	opt->opt_private->pk_init_ctx->dh = DH_new();
	if (opt->opt_private->pk_init_ctx->dh == NULL) {
	    krb5_set_error_string(context, "malloc: out of memory");
	    _krb5_get_init_creds_opt_free_pkinit(opt);
	    return ENOMEM;
	}

	ret = select_dh_group(context, opt->opt_private->pk_init_ctx->dh, 0, 
			      opt->opt_private->pk_init_ctx->m);
	if (ret) {
	    _krb5_get_init_creds_opt_free_pkinit(opt);
	    return ret;
	}

	if (DH_generate_key(opt->opt_private->pk_init_ctx->dh) != 1) {
	    krb5_set_error_string(context, "malloc: out of memory");
	    _krb5_get_init_creds_opt_free_pkinit(opt);
	    return ENOMEM;
	}
    }

    return 0;
#else
    krb5_set_error_string(context, "no support for PKINIT compiled in");
    return EINVAL;
#endif
}
