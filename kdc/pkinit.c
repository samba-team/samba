/*
 * Copyright (c) 2003 - 2004 Kungliga Tekniska Högskolan
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

#include "kdc_locl.h"

RCSID("$Id$");

#ifdef PKINIT

#include <heim_asn1.h>
#include <rfc2459_asn1.h>
#include <cms_asn1.h>
#include <pkinit_asn1.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/err.h>

int enable_pkinit = 0;

/* XXX copied from lib/krb5/pkinit.c */
struct krb5_pk_identity {
    EVP_PKEY *private_key;
    STACK_OF(X509) *cert;
    STACK_OF(X509) *trusted_certs;
    STACK_OF(X509_CRL) *crls;
};

/* XXX copied from lib/krb5/pkinit.c */
struct krb5_pk_cert {
    X509 *cert;
};

struct pk_client_params {
    BIGNUM *dh_public_key;
    struct krb5_pk_cert *certificate;
    unsigned nonce;
    DH *dh;
    EncryptionKey reply_key;
};

struct pk_principal_mapping {
    unsigned int len;
    struct pk_allowed_princ {
	krb5_principal principal;
	char *subject;
    } *val;
};

/* XXX copied from lib/krb5/pkinit.c */
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

/* XXX fix asn1_compile */
extern heim_oid heim_dhpublicnumber_oid;
extern heim_oid pkcs7_signed_oid;
extern heim_oid heim_pkauthdata_oid;
extern heim_oid heim_des_ede3_cbc_oid;
extern heim_oid heim_pkdhkeydata_oid;
extern heim_oid pkcs7_signed_oid;
extern heim_oid heim_pkrkeydata_oid;
extern heim_oid heim_rsaEncryption_oid;
extern heim_oid pkcs7_enveloped_oid;

static struct krb5_pk_identity *kdc_identity;
static struct pk_principal_mapping principal_mappings;

/*
 *
 */

static krb5_error_code
pk_check_pkauthenticator(krb5_context context,
      			 PKAuthenticator *a,
			 KDC_REQ *req)
{
    u_char *buf = NULL;
    size_t buf_size;
    krb5_error_code ret;
    size_t len;
    krb5_timestamp now;

    krb5_timeofday (context, &now);

    /* XXX cusec */
    if (a->ctime == 0 || abs(a->ctime - now) > context->max_skew) {
	krb5_clear_error_string(context);
	return KRB5KRB_AP_ERR_SKEW;
    }

    ASN1_MALLOC_ENCODE(KDC_REQ_BODY, buf, buf_size, &req->req_body, &len, ret);
    if (ret) {
	krb5_clear_error_string(context);
	return ret;
    }
    if (buf_size != len)
	krb5_abortx(context, "Internal error in ASN.1 encoder");

    ret = krb5_verify_checksum(context, NULL, 0, buf, len,
			       &a->paChecksum);
    if (ret)
	krb5_clear_error_string(context);

    free(buf);
    return ret;
}

static krb5_error_code
pk_encrypt_key(krb5_context context,
      	       krb5_keyblock *key,
               EVP_PKEY *public_key,
	       krb5_data *encrypted_key,
	       heim_oid **oid)
{
    krb5_error_code ret;

    encrypted_key->length = EVP_PKEY_size(public_key);

    if (encrypted_key->length < key->keyvalue.length + 11) { /* XXX */
	krb5_set_error_string(context, "pkinit: encrypted key too long");
	return KRB5KRB_ERR_GENERIC;
    }

    encrypted_key->data = malloc(encrypted_key->length);
    if (encrypted_key->data == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	return ENOMEM;
    }

    ret = EVP_PKEY_encrypt(encrypted_key->data, 
			   key->keyvalue.data,
			   key->keyvalue.length,
			   public_key);
    if (ret < 0) {
	free(encrypted_key->data);
	krb5_set_error_string(context, "Can't encrypt key: %s",
			      ERR_error_string(ERR_get_error(), NULL));
	return KRB5KRB_ERR_GENERIC;
    }
    if (encrypted_key->length != ret)
	krb5_abortx(context, "size of EVP_PKEY_size is not the "
		    "size of the output");

    *oid = &heim_rsaEncryption_oid;

    return 0;
}

void
pk_free_client_param(krb5_context context, pk_client_params *client_params)
{
    if (client_params->certificate)
	_krb5_pk_cert_free(client_params->certificate);
    if (client_params->dh)
	DH_free(client_params->dh);
    if (client_params->dh_public_key)
	BN_free(client_params->dh_public_key);
    krb5_free_keyblock_contents(context, &client_params->reply_key);
    memset(client_params, 0, sizeof(*client_params));
    free(client_params);
}

static krb5_error_code
check_dh_params(DH *dh)
{
    /* XXX check the DH parameters come from 1st or 2nd Oeakley Group */
    return 0;
}

static krb5_error_code
generate_dh_keyblock(krb5_context context, pk_client_params *client_params,
                     krb5_keyblock *reply_key)
{
    unsigned char *dh_gen_key = NULL;
    krb5_keyblock key;
    int dh_gen_keylen;
    krb5_error_code ret;
    /* XXX don't hardcode the keytype */
    krb5_enctype enctype = ETYPE_DES3_CBC_SHA1;

    memset(&key, 0, sizeof(key));

    dh_gen_key = malloc(DH_size(client_params->dh));
    if (dh_gen_key == NULL) {
	krb5_set_error_string(context, "malloc: out of memory");
	ret = ENOMEM;
	goto out;
    }

    if (!DH_generate_key(client_params->dh)) {
	krb5_set_error_string(context, "Can't generate Diffie-Hellman "
			      "keys (%s)",
			      ERR_error_string(ERR_get_error(), NULL));
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }
    if (client_params->dh_public_key == NULL) {
	krb5_set_error_string(context, "dh_public_key");
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }

    dh_gen_keylen = DH_compute_key(dh_gen_key, 
				   client_params->dh_public_key,
				   client_params->dh);
    if (dh_gen_keylen == -1) {
	krb5_set_error_string(context, "Can't compute Diffie-Hellman key (%s)",
			      ERR_error_string(ERR_get_error(), NULL));
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }

    switch (enctype) {
    case ETYPE_DES_CBC_CRC:
    case ETYPE_DES_CBC_MD4:
    case ETYPE_DES_CBC_MD5:
    case ETYPE_DES3_CBC_SHA1:
    case ETYPE_OLD_DES3_CBC_SHA1: {
	DES_cblock *k;

	ret = krb5_generate_random_keyblock(context, enctype, &key);
	if (ret)
	    goto out;
	memset(key.keyvalue.data, 0, key.keyvalue.length);
  
	if (dh_gen_keylen < key.keyvalue.length) {
	    krb5_set_error_string(context, "Too small key generated by "
				  "Diffie-Hellman mechanism");
	    ret = KRB5KRB_ERR_GENERIC;
	    goto out;
	}
	memcpy(key.keyvalue.data, dh_gen_key, key.keyvalue.length);
	k = key.keyvalue.data;
	DES_set_odd_parity(&k[0]);
	switch (enctype) {
	case ETYPE_DES3_CBC_SHA1: 
	case ETYPE_OLD_DES3_CBC_SHA1:
	    DES_set_odd_parity(&k[1]);
	    DES_set_odd_parity(&k[2]);
	    break;
	default:
	    break;
	}
	break;
    }
    default:
	krb5_set_error_string(context, "PKINIT DH, unsupported enctype: %d",
			      (int)enctype);
	ret = KDC_ERROR_KEY_TOO_WEAK;
	break;
    }

    ret = krb5_copy_keyblock_contents(context, &key, reply_key);

 out:
    if (dh_gen_key)
	free(dh_gen_key);
    if (key.keyvalue.data)
	krb5_free_keyblock_contents(context, &key);

    return ret;
}

static BIGNUM *
big_integer_to_BN(krb5_context context, const char *field, heim_big_integer *f)
{
    unsigned char *p = f->data;
    ASN1_INTEGER *i;
    BIGNUM *bn;

    i = d2i_ASN1_INTEGER(NULL, &p, f->length);
    if (i == NULL) {
	krb5_set_error_string(context, "PKINIT: failed to decode %s", field);
	return NULL;
    }
    bn = ASN1_INTEGER_to_BN(i, NULL);
    ASN1_INTEGER_free(i);
    if (bn == NULL) {
	krb5_set_error_string(context,
			      "PKINIT: failed to convert %s to bignum",
			      field);
	return NULL;
    }
    return bn;
}

static krb5_error_code
get_dh_param(krb5_context context, SubjectPublicKeyInfo *dh_key_info,
	     pk_client_params *client_params)
{
    DomainParameters dhparam;
    DH *dh = NULL;
    krb5_error_code ret;
    int dhret;

    memset(&dhparam, 0, sizeof(dhparam));

    if (oid_cmp(&dh_key_info->algorithm.algorithm, &heim_dhpublicnumber_oid)) {
	krb5_set_error_string(context,
			      "PKINIT invalid oid in clientPublicValue");
	return KRB5_BADMSGTYPE;
    }

#if 0
    if (dh_key_info->algorithm.parameters == NULL) {
	krb5_set_error_string(context, "PKINIT missing algorithm parameter "
			      "in clientPublicValue");
	return KRB5_BADMSGTYPE;
    }
#endif

    ret = decode_DomainParameters(dh_key_info->algorithm.parameters.data,
				  dh_key_info->algorithm.parameters.length,
				  &dhparam,
				  NULL);
    if (ret) {
	krb5_set_error_string(context, "Can't decode algorithm "
			      "parameters in clientPublicValue");
	goto out;
    }

    dh = DH_new();
    if (dh == NULL) {
	krb5_set_error_string(context, "Cannot create DH structure (%s)",
			      ERR_error_string(ERR_get_error(), NULL));
	ret = ENOMEM;
	goto out;
    }
    ret = KRB5_BADMSGTYPE;
    dh->p = big_integer_to_BN(context, "DH prime", &dhparam.p);
    if (dh->p == NULL)
	goto out;
    dh->g = big_integer_to_BN(context, "DH base", &dhparam.g);
    if (dh->g == NULL)
	goto out;
    dh->q = big_integer_to_BN(context, "DH p-1 factor", &dhparam.q);
    if (dh->g == NULL)
	goto out;

    {
	heim_big_integer glue;
	glue.data = dh_key_info->subjectPublicKey.data;
	glue.length = dh_key_info->subjectPublicKey.length;

	client_params->dh_public_key = big_integer_to_BN(context,
							 "subjectPublicKey",
							 &glue);
	if (client_params->dh_public_key == NULL) {
	    krb5_clear_error_string(context);
	    goto out;
	}
    }

    if (DH_check(dh, &dhret) != 1) {
	krb5_set_error_string(context, "PKINIT DH data not ok: %s",
			      ERR_error_string(ERR_get_error(), NULL));
	ret = KDC_ERROR_KEY_TOO_WEAK;
	goto out;
    }

    client_params->dh = dh;
    dh = NULL;
    ret = 0;
    
 out:
    if (dh)
	DH_free(dh);
    free_DomainParameters(&dhparam);
    return ret;
}

krb5_error_code
pk_rd_padata(krb5_context context,
             KDC_REQ *req,
             PA_DATA *pa,
	     pk_client_params **ret_params)
{
    pk_client_params *client_params;
    krb5_error_code ret;
    PA_PK_AS_REQ r;
    AuthPack ap;
    heim_oid eContentType = { 0, NULL };
    krb5_data eContent;
    int i;

    *ret_params = NULL;
    
    if (!enable_pkinit) {
	krb5_clear_error_string(context);
	return 0;
    }

    memset(&ap, 0, sizeof(ap));
    memset(&r, 0, sizeof(r));
    krb5_data_zero(&eContent);

    client_params = malloc(sizeof(*client_params));
    if (client_params == NULL) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }
    memset(client_params, 0, sizeof(*client_params));

    if (pa->padata_type !=  KRB5_PADATA_PK_AS_REQ) {
	krb5_clear_error_string(context);
	ret = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
	goto out;
    }

    ret = decode_PA_PK_AS_REQ(pa->padata_value.data,
			      pa->padata_value.length,
			      &r,
			      NULL);
    if (ret) {
	krb5_set_error_string(context, "Can't decode PK-AS-REQ: %d", ret);
	return ret;
    }

    if (oid_cmp(&r.signedAuthPack.contentType, &pkcs7_signed_oid)) {
	krb5_set_error_string(context, "PK-AS-REQ invalid content type oid");
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }
  
    if (r.signedAuthPack.content == NULL) {
	krb5_set_error_string(context, "PK-AS-REQ no signed auth pack");
	ret = KRB5KRB_ERR_GENERIC;
	goto out;
    }

    ret = _krb5_pk_verify_sign(context,
			       r.signedAuthPack.content->data,
			       r.signedAuthPack.content->length,
			       kdc_identity,
			       &eContentType,
			       &eContent,
			       &client_params->certificate);
    if (ret)
	goto out;

    /* Signature is correct, now verify the signed message */
    if (oid_cmp(&eContentType, &heim_pkauthdata_oid)) {
	krb5_set_error_string(context, "got wrong oid for pkauthdata");
	ret = KRB5_BADMSGTYPE;
	goto out;
    }

    ret = decode_AuthPack(eContent.data,
			  eContent.length,
			  &ap,
			  NULL);
    if (ret) {
	krb5_set_error_string(context, "can't decode AuthPack: %d", ret);
	goto out;
    }
  
    ret = pk_check_pkauthenticator(context, 
				   &ap.pkAuthenticator,
				   req);
    if (ret)
	goto out;

    client_params->nonce = ap.pkAuthenticator.nonce;

    if (ap.clientPublicValue) {
	ret = get_dh_param(context, ap.clientPublicValue, client_params);
	if (ret)
	    goto out;
    }

    /* 
     * If client has sent a list of CA's trusted by him, make sure our
     * CA is in the list.
     */

    if (r.trustedCertifiers != NULL) {
	X509_NAME *kdc_issuer;
	X509 *kdc_cert;

	kdc_cert = sk_X509_value(kdc_identity->cert, 0);
	kdc_issuer = X509_get_issuer_name(kdc_cert);
     
	/* XXX will work for heirarchical CA's ? */
	/* XXX also serial_number should be compared */

	ret = KDC_ERROR_KDC_NOT_TRUSTED;
	for (i = 0; i < r.trustedCertifiers->len; i++) {
	    TrustedCAs *ca = &r.trustedCertifiers->val[i];

	    switch (ca->element) {
	    case choice_TrustedCAs_caName: {
		X509_NAME *name;
		unsigned char *p;

		p = ca->u.caName.data;
		name = d2i_X509_NAME(NULL, &p, ca->u.caName.length);
		if (name == NULL) /* XXX should this be a failure instead ? */
		    break;
		if (X509_NAME_cmp(name, kdc_issuer) == 0)
		    ret = 0;
		X509_NAME_free(name);
		break;
	    }
	    case choice_TrustedCAs_principalName:
		/* KerberosName principalName; */
		break;
	    case choice_TrustedCAs_issuerAndSerial:
		/* IssuerAndSerialNumber issuerAndSerial */
		break;
	    }
	    if (ret == 0)
		break;
	}
	if (ret)
	    goto out;
    }

    /* 
     * Remaining fields (ie kdcCert and encryptionCert) in the request
     * are ignored for now.
     */

 out:
    krb5_data_free(&eContent);
    free_oid(&eContentType);
    if (ret)
	pk_free_client_param(context, client_params);
    else
	*ret_params = client_params;
    free_PA_PK_AS_REQ(&r);
    free_AuthPack(&ap);
    return ret;
}

/*
 *
 */

static krb5_error_code
pk_mk_pa_reply_enckey(krb5_context context,
      	              pk_client_params *client_params,
		      const KDC_REQ *req,
                      krb5_keyblock *reply_key,
		      ContentInfo *content_info)
{
    KeyTransRecipientInfo *ri;
    EnvelopedData ed;

    krb5_error_code ret;
    krb5_crypto crypto;

    krb5_data buf, sd_data, enc_sd_data;

    krb5_keyblock tmp_key;
    krb5_enctype enctype = ETYPE_DES3_CBC_NONE;
    heim_oid *enc_type_oid = NULL;
    X509_NAME *issuer_name;
    heim_big_integer *serial;

    size_t size;

    krb5_data_zero(&enc_sd_data);
    krb5_data_zero(&sd_data);

    memset(&tmp_key, 0, sizeof(tmp_key));
    memset(&ed, 0, sizeof(ed));

    switch (enctype) {
    case ETYPE_DES3_CBC_NONE:
	enc_type_oid = &heim_des_ede3_cbc_oid;
	break;
    default:
	krb5_set_error_string(context, "not support for enctype %d", enctype);
	return KRB5_PROG_KEYTYPE_NOSUPP;
    }

    {
	ReplyKeyPack kp;
	memset(&kp, 0, sizeof(kp));

	ret = copy_EncryptionKey(reply_key, &kp.replyKey);
	if (ret) {
	    krb5_clear_error_string(context);
	    return ret;
	}
	kp.nonce = client_params->nonce;
	
	ASN1_MALLOC_ENCODE(ReplyKeyPack, buf.data, buf.length, &kp, &size,ret);
	free_ReplyKeyPack(&kp);
    }
    if (ret) {
	krb5_set_error_string(context, "ASN.1 encoding of ReplyKeyPack "
			      "failed (%d)", ret);
	return ret;
    }
    if (buf.length != size)
	krb5_abortx(context, "Internal ASN.1 encoder error");

    /* 
     * CRL's are not transfered -- should be ?
     */

    ret = _krb5_pk_create_sign(context,
			       &heim_pkrkeydata_oid,
			       &buf,
			       kdc_identity,
			       &sd_data);
    krb5_data_free(&buf);
    if (ret) 
	goto out;

    ret = krb5_generate_random_keyblock(context, enctype, &tmp_key);
    if (ret)
	goto out;

    ret = krb5_crypto_init(context, &tmp_key, 0, &crypto);
    if (ret)
	goto out;

    ret = krb5_encrypt(context, crypto, 0, 
		       sd_data.data, sd_data.length,
		       &enc_sd_data);
    krb5_crypto_destroy(context, crypto);
    if (ret)
	goto out;

    ALLOC_SEQ(&ed.recipientInfos, 1);
    if (ed.recipientInfos.val == NULL) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }

    ri = &ed.recipientInfos.val[0];

    ri->version = 0;
    ri->rid.element = choice_RecipientIdentifier_issuerAndSerialNumber;
	
    issuer_name = X509_get_issuer_name(client_params->certificate->cert);
    OPENSSL_ASN1_MALLOC_ENCODE(X509_NAME, buf.data, buf.length,
			       issuer_name, ret);
    if (ret) {
	krb5_clear_error_string(context);
	goto out;
    }
    ri->rid.u.issuerAndSerialNumber.issuer.data = buf.data;
    ri->rid.u.issuerAndSerialNumber.issuer.length = buf.length;

    serial = &ri->rid.u.issuerAndSerialNumber.serialNumber;
    OPENSSL_ASN1_MALLOC_ENCODE(ASN1_INTEGER,
			       serial->data,
			       serial->length,
			       X509_get_serialNumber(client_params->certificate->cert),
			       ret);
    if (ret) {
	krb5_clear_error_string(context);
	goto out;
    }

    {
	heim_oid *pk_enc_key_oid;
	krb5_data enc_tmp_key;

	ret = pk_encrypt_key(context, &tmp_key,
			     X509_get_pubkey(client_params->certificate->cert),
			     &enc_tmp_key,
			     &pk_enc_key_oid);
	if (ret)
	    goto out;

	ri->encryptedKey.length = enc_tmp_key.length;
	ri->encryptedKey.data = enc_tmp_key.data;

	ret = copy_oid(pk_enc_key_oid, &ri->keyEncryptionAlgorithm.algorithm);
	if (ret)
	    goto out;
    }

    /*
     *
     */

    ed.version = 0;
    ed.originatorInfo = NULL;

    ret = copy_oid(&pkcs7_signed_oid, &ed.encryptedContentInfo.contentType);
    if (ret) {
	krb5_clear_error_string(context);
	goto out;
    }
    ret = copy_oid(enc_type_oid,
	&ed.encryptedContentInfo.contentEncryptionAlgorithm.algorithm);
    if (ret) {
	krb5_clear_error_string(context);
	goto out;
    }
    ed.encryptedContentInfo.contentEncryptionAlgorithm.parameters = NULL;

    ALLOC(ed.encryptedContentInfo.encryptedContent);
    if (ed.encryptedContentInfo.encryptedContent == NULL) {
	krb5_clear_error_string(context);
	ret = ENOMEM;
	goto out;
    }

    ed.encryptedContentInfo.encryptedContent->data = enc_sd_data.data;
    ed.encryptedContentInfo.encryptedContent->length = enc_sd_data.length;
    krb5_data_zero(&enc_sd_data);

    ed.unprotectedAttrs = NULL;

    ASN1_MALLOC_ENCODE(EnvelopedData, buf.data, buf.length, &ed, &size, ret);
    if (ret) {
	krb5_set_error_string(context, 
			      "ASN.1 encoding of EnvelopedData failed (%d)",
			      ret);
	goto out;
    }
  
    ret = _krb5_pk_mk_ContentInfo(context,
				  &buf,
				  &pkcs7_enveloped_oid,
				  content_info);
    krb5_data_free(&buf);

 out:
    krb5_free_keyblock_contents(context, &tmp_key);
    krb5_data_free(&enc_sd_data);
    krb5_data_zero(&sd_data);
    free_EnvelopedData(&ed);

    return ret;
}

/*
 *
 */

static krb5_error_code
pk_mk_pa_reply_dh(krb5_context context,
                  DH *kdc_dh,
      		  pk_client_params *client_params,
                  krb5_keyblock *reply_key,
		  ContentInfo *content_info)
{
    ASN1_INTEGER *dh_pub_key = NULL;
    KDCDHKeyInfo dh_info;
    krb5_error_code ret;
    SignedData sd;
    krb5_data buf, sd_buf;
    size_t size;

    memset(&dh_info, 0, sizeof(dh_info));
    memset(&sd, 0, sizeof(sd));
    krb5_data_zero(&buf);
    krb5_data_zero(&sd_buf);

    dh_pub_key = BN_to_ASN1_INTEGER(kdc_dh->pub_key, NULL);
    if (dh_pub_key == NULL) {
	krb5_set_error_string(context, "BN_to_ASN1_INTEGER() failed (%s)",
			      ERR_error_string(ERR_get_error(), NULL));
	ret = ENOMEM;
	goto out;
    }

    OPENSSL_ASN1_MALLOC_ENCODE(ASN1_INTEGER, buf.data, buf.length, dh_pub_key,
			       ret);
    ASN1_INTEGER_free(dh_pub_key);
    if (ret) {
	krb5_set_error_string(context, "Encoding of ASN1_INTEGER failed (%s)",
			      ERR_error_string(ERR_get_error(), NULL));
	goto out;
    }
   
    dh_info.subjectPublicKey.length = buf.length * 8;
    dh_info.subjectPublicKey.data = buf.data;
    
    dh_info.nonce = client_params->nonce;

    ASN1_MALLOC_ENCODE(KDCDHKeyInfo, buf.data, buf.length, &dh_info, &size, 
		       ret);
    if (ret) {
	krb5_set_error_string(context, "ASN.1 encoding of "
			      "KdcDHKeyInfo failed (%d)", ret);
	goto out;
    }
    if (buf.length != size)
	krb5_abortx(context, "Internal ASN.1 encoder error");

    /* 
     * Create the SignedData structure and sign the KdcDHKeyInfo
     * filled in above
     */

    ret = _krb5_pk_create_sign(context, 
			       &heim_pkdhkeydata_oid,
			       &buf,
			       kdc_identity, 
			       &sd_buf);
    krb5_data_free(&buf);
    if (ret)
	goto out;

    ret = _krb5_pk_mk_ContentInfo(context, &sd_buf, &pkcs7_signed_oid,
				  content_info);
    krb5_data_free(&sd_buf);

 out:
    free_KDCDHKeyInfo(&dh_info);

    return ret;
}

/*
 *
 */

krb5_error_code
pk_mk_pa_reply(krb5_context context,
      	       pk_client_params *client_params,
	       const KDC_REQ *req,
               krb5_keyblock **reply_key,
	       METHOD_DATA *md)
{
    krb5_error_code ret;
    PA_PK_AS_REP rep;
    void *buf;
    size_t len, size;
    krb5_enctype enctype;

    if (!enable_pkinit) {
	krb5_clear_error_string(context);
	return 0;
    }

    memset(&rep, 0, sizeof(rep));

    if (req->req_body.etype.len < 1) {
	ret = KRB5KRB_ERR_GENERIC;
	krb5_set_error_string(context,
			      "No valid enctype available from client");
	goto out;
    }

    enctype = req->req_body.etype.val[0];
    enctype = ETYPE_DES3_CBC_SHA1;

    if (client_params->dh == NULL) {
	rep.element = choice_PA_PK_AS_REP_encKeyPack;

	krb5_generate_random_keyblock(context, enctype, 
				      &client_params->reply_key);

	ret = pk_mk_pa_reply_enckey(context,
				    client_params,
				    req,
				    &client_params->reply_key,
				    &rep.u.encKeyPack);
    } else {
	rep.element = choice_PA_PK_AS_REP_dhSignedData;

	ret = check_dh_params(client_params->dh);
	if (ret)
	    return ret;

	ret = generate_dh_keyblock(context, client_params,
				   &client_params->reply_key);
	if (ret)
	    return ret;

	ret = pk_mk_pa_reply_dh(context, client_params->dh,
				client_params, 
				&client_params->reply_key,
				&rep.u.dhSignedData);
    }
    if (ret)
	goto out;

    ASN1_MALLOC_ENCODE(PA_PK_AS_REP, buf, len, &rep, &size, ret);
    if (ret) {
	krb5_set_error_string(context, "encode PA-PK-AS-REP failed %d", ret);
	goto out;
    }
    if (len != size)
	krb5_abortx(context, "Internal ASN.1 encoder error");

    ret = krb5_padata_add(context, md, KRB5_PADATA_PK_AS_REP, buf, len);
    if (ret) {
	krb5_set_error_string(context, "failed adding PA-PK-AS-REP %d", ret);
	free(buf);
    }
 out:
    if (ret == 0)
	*reply_key = &client_params->reply_key;
    free_PA_PK_AS_REP(&rep);
    return ret;
}

/* XXX match with issuer too ? */

krb5_error_code
pk_check_client(krb5_context context,
                krb5_principal client_princ,
                pk_client_params *client_params,
		char **subject_name)
{
    struct krb5_pk_cert *client_cert = client_params->certificate;
    X509_NAME *name;
    char *subject = NULL;
    int i;

    *subject_name = NULL;

    name = X509_get_subject_name(client_cert->cert);
    if (name == NULL) {
	krb5_set_error_string(context, "PKINIT can't get subject name");
	return ENOMEM;
    }
    subject = X509_NAME_oneline(name, NULL, 0);
    if (subject == NULL) {
	krb5_set_error_string(context, "PKINIT can't get subject name");
	return ENOMEM;
    }
    *subject_name = strdup(subject);
    if (*subject_name == NULL) {
	krb5_set_error_string(context, "out of memory");
	return ENOMEM;
    }
    OPENSSL_free(subject);

    for (i = 0; i < principal_mappings.len; i++) {
	krb5_boolean ret;

	ret = krb5_principal_compare(context,
				     client_princ,
				     principal_mappings.val[i].principal);
	if (ret == FALSE)
	    continue;
	if (strcmp(principal_mappings.val[i].subject, *subject_name) != 0)
	    continue;
	return 0;
    }
    free(*subject_name);
    *subject_name = NULL;
    krb5_set_error_string(context, "PKINIT no matching principals");
    return KDC_ERROR_CLIENT_NAME_MISMATCH;
}

static krb5_error_code
add_principal_mapping(const char *principal_name, const char * subject)
{
   struct pk_allowed_princ *tmp;
   krb5_principal principal;
   krb5_error_code ret;

   tmp = realloc(principal_mappings.val,
	         (principal_mappings.len + 1) * sizeof(*tmp));
   if (tmp == NULL)
       return ENOMEM;
   principal_mappings.val = tmp;

   ret = krb5_parse_name(context, principal_name, &principal);
   if (ret)
       return ret;

   principal_mappings.val[principal_mappings.len].principal = principal;

   principal_mappings.val[principal_mappings.len].subject = strdup(subject);
   if (principal_mappings.val[principal_mappings.len].subject == NULL) {
       krb5_free_principal(context, principal);
       return ENOMEM;
   }
   principal_mappings.len++;

   return 0;
}


krb5_error_code
pk_initialize(const char *cert_file,
	      const char *key_file,
	      const char *ca_dir)
{
    const krb5_config_binding *binding; 
    krb5_error_code ret;

    principal_mappings.len = 0;
    principal_mappings.val = NULL;

    ret = _krb5_pk_load_openssl_id(context,
				   &kdc_identity,
				   cert_file,
				   key_file,
				   ca_dir,
				   NULL);
    if (ret) {
	krb5_warn(context, ret, "PKINIT: failed to load");
	enable_pkinit = 0;
	return ret;
    }

    binding = krb5_config_get_list(context, 
			     NULL,
			     "kdc",
			     "pki-allowed-principals",
			     NULL);
    while (binding) {
	if (binding->type != krb5_config_string)
	    continue;
	ret = add_principal_mapping(binding->name, binding->u.string);
	if (ret)
	    krb5_err(context, 1, ret, "adding cert %s to principal %s failed",
		     binding->u.string, binding->name);
	binding = binding->next;
    }

    return ret;
}

#endif /* PKINIT */
