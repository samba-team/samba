/*
 * Copyright (c) 2003 - 2016 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include "hdb_asn1.h"
#include "kdc_locl.h"
#ifdef PKINIT

#include <heim_asn1.h>
#include <rfc2459_asn1.h>
#include <cms_asn1.h>
#include <pkinit_asn1.h>

#include <hx509.h>
#include "crypto-headers.h"

struct pk_client_params {
    enum krb5_pk_type type;
    enum keyex_enum keyex;
    union {
	struct {
	    BIGNUM *public_key;
	    DH *key;
	} dh;
	struct {
	    void *public_key;
	    void *key;
	} ecdh;
    } u;
    hx509_cert cert;
    krb5_timestamp endtime;
    krb5_timestamp max_life;
    unsigned nonce;
    EncryptionKey reply_key;
    char *dh_group_name;
    hx509_peer_info peer;
    hx509_certs client_anchors;
    hx509_verify_ctx verify_ctx;
    heim_octet_string *freshness_token;
};

struct pk_principal_mapping {
    unsigned int len;
    struct pk_allowed_princ {
	krb5_principal principal;
	char *subject;
    } *val;
};

static struct krb5_pk_identity *kdc_identity;
static struct pk_principal_mapping principal_mappings;
static struct krb5_dh_moduli **moduli;

static struct {
    krb5_data data;
    time_t expire;
    time_t next_update;
} ocsp;

/*
 *
 */

static krb5_error_code
pk_check_pkauthenticator_win2k(krb5_context context,
			       PKAuthenticator_Win2k *a,
			       const KDC_REQ *req)
{
    krb5_timestamp now;

    krb5_timeofday (context, &now);

    /* XXX cusec */
    if (a->ctime == 0 || labs(a->ctime - now) > context->max_skew) {
	krb5_clear_error_message(context);
	return KRB5KRB_AP_ERR_SKEW;
    }
    return 0;
}

static krb5_error_code
pk_check_pkauthenticator(krb5_context context,
			 const PKAuthenticator *a,
			 const KDC_REQ *req)
{
    krb5_error_code ret;
    krb5_timestamp now;
    Checksum checksum;

    krb5_timeofday (context, &now);

    /* XXX cusec */
    if (a->ctime == 0 || labs(a->ctime - now) > context->max_skew) {
	krb5_clear_error_message(context);
	return KRB5KRB_AP_ERR_SKEW;
    }

    ret = krb5_create_checksum(context,
			       NULL,
			       0,
			       CKSUMTYPE_SHA1,
			       req->req_body._save.data,
			       req->req_body._save.length,
			       &checksum);
    if (ret) {
	krb5_clear_error_message(context);
	return ret;
    }

    if (a->paChecksum == NULL) {
	krb5_clear_error_message(context);
	ret = KRB5_KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED;
	goto out;
    }

    if (der_heim_octet_string_cmp(a->paChecksum, &checksum.checksum) != 0) {
	krb5_clear_error_message(context);
	ret = KRB5KRB_ERR_GENERIC;
    }

out:
    free_Checksum(&checksum);

    return ret;
}

void
_kdc_pk_free_client_param(krb5_context context, pk_client_params *cp)
{
    if (cp == NULL)
        return;
    if (cp->cert)
	hx509_cert_free(cp->cert);
    if (cp->verify_ctx)
	hx509_verify_destroy_ctx(cp->verify_ctx);
    if (cp->keyex == USE_DH) {
	if (cp->u.dh.key)
	    DH_free(cp->u.dh.key);
	if (cp->u.dh.public_key)
	    BN_free(cp->u.dh.public_key);
    }
    if (cp->keyex == USE_ECDH)
        _kdc_pk_free_client_ec_param(context, cp->u.ecdh.key,
                                     cp->u.ecdh.public_key);
    krb5_free_keyblock_contents(context, &cp->reply_key);
    if (cp->dh_group_name)
	free(cp->dh_group_name);
    if (cp->peer)
	hx509_peer_info_free(cp->peer);
    if (cp->client_anchors)
	hx509_certs_free(&cp->client_anchors);
    if (cp->freshness_token)
	der_free_octet_string(cp->freshness_token);
    free(cp->freshness_token);
    memset(cp, 0, sizeof(*cp));
    free(cp);
}

static krb5_error_code
generate_dh_keyblock(krb5_context context,
		     pk_client_params *client_params,
                     krb5_enctype enctype)
{
    unsigned char *dh_gen_key = NULL;
    krb5_keyblock key;
    krb5_error_code ret;
    size_t dh_gen_keylen, size;

    memset(&key, 0, sizeof(key));

    if (client_params->keyex == USE_DH) {

	if (client_params->u.dh.public_key == NULL) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(context, ret, "missing DH public_key");
	    goto out;
	}

	if (!DH_generate_key(client_params->u.dh.key)) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(context, ret,
				   "Can't generate Diffie-Hellman keys");
	    goto out;
	}

	size = DH_size(client_params->u.dh.key);

	dh_gen_key = malloc(size);
	if (dh_gen_key == NULL) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "malloc: out of memory");
	    goto out;
	}

	dh_gen_keylen = DH_compute_key(dh_gen_key,client_params->u.dh.public_key, client_params->u.dh.key);
	if (dh_gen_keylen == (size_t)-1) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(context, ret,
				   "Can't compute Diffie-Hellman key");
	    goto out;
	}
	if (dh_gen_keylen < size) {
	    size -= dh_gen_keylen;
	    memmove(dh_gen_key + size, dh_gen_key, dh_gen_keylen);
	    memset(dh_gen_key, 0, size);
	    dh_gen_keylen += size;
	}
    } else if (client_params->keyex == USE_ECDH) {
	if (client_params->u.ecdh.public_key == NULL) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(context, ret, "missing ECDH public_key");
	    goto out;
	}
        ret = _kdc_generate_ecdh_keyblock(context,
                                          client_params->u.ecdh.public_key,
                                          &client_params->u.ecdh.key,
                                          &dh_gen_key, &dh_gen_keylen);
        if (ret)
            goto out;
    } else {
	ret = KRB5KRB_ERR_GENERIC;
	krb5_set_error_message(context, ret,
			       "Diffie-Hellman not selected keys");
	goto out;
    }

    ret = _krb5_pk_octetstring2key(context,
				   enctype,
				   dh_gen_key, dh_gen_keylen,
				   NULL, NULL,
				   &client_params->reply_key);

 out:
    if (dh_gen_key)
	free(dh_gen_key);
    if (key.keyvalue.data)
	krb5_free_keyblock_contents(context, &key);

    return ret;
}

static BIGNUM *
integer_to_BN(krb5_context context, const char *field, heim_integer *f)
{
    BIGNUM *bn;

    bn = BN_bin2bn((const unsigned char *)f->data, f->length, NULL);
    if (bn == NULL) {
	krb5_set_error_message(context, KRB5_BADMSGTYPE,
			       "PKINIT: parsing BN failed %s", field);
	return NULL;
    }
    BN_set_negative(bn, f->negative);
    return bn;
}

static krb5_error_code
get_dh_param(krb5_context context,
	     krb5_kdc_configuration *config,
	     SubjectPublicKeyInfo *dh_key_info,
	     pk_client_params *client_params)
{
    DomainParameters dhparam;
    DH *dh = NULL;
    krb5_error_code ret;

    memset(&dhparam, 0, sizeof(dhparam));

    if ((dh_key_info->subjectPublicKey.length % 8) != 0) {
	ret = KRB5_BADMSGTYPE;
	krb5_set_error_message(context, ret,
			       "PKINIT: subjectPublicKey not aligned "
			       "to 8 bit boundary");
	goto out;
    }

    if (dh_key_info->algorithm.parameters == NULL) {
	krb5_set_error_message(context, KRB5_BADMSGTYPE,
			       "PKINIT missing algorithm parameter "
			      "in clientPublicValue");
	return KRB5_BADMSGTYPE;
    }

    ret = decode_DomainParameters(dh_key_info->algorithm.parameters->data,
				  dh_key_info->algorithm.parameters->length,
				  &dhparam,
				  NULL);
    if (ret) {
	krb5_set_error_message(context, ret, "Can't decode algorithm "
			       "parameters in clientPublicValue");
	goto out;
    }

    ret = _krb5_dh_group_ok(context, config->pkinit_dh_min_bits,
			    &dhparam.p, &dhparam.g, dhparam.q, moduli,
			    &client_params->dh_group_name);
    if (ret) {
	/* XXX send back proposal of better group */
	goto out;
    }

    dh = DH_new();
    if (dh == NULL) {
	ret = ENOMEM;
	krb5_set_error_message(context, ret, "Cannot create DH structure");
	goto out;
    }
    ret = KRB5_BADMSGTYPE;
    dh->p = integer_to_BN(context, "DH prime", &dhparam.p);
    if (dh->p == NULL)
	goto out;
    dh->g = integer_to_BN(context, "DH base", &dhparam.g);
    if (dh->g == NULL)
	goto out;

    if (dhparam.q) {
	dh->q = integer_to_BN(context, "DH p-1 factor", dhparam.q);
	if (dh->q == NULL)
	    goto out;
    }

    {
	heim_integer glue;
	size_t size;

	ret = decode_DHPublicKey(dh_key_info->subjectPublicKey.data,
				 dh_key_info->subjectPublicKey.length / 8,
				 &glue,
				 &size);
	if (ret) {
	    krb5_clear_error_message(context);
	    return ret;
	}

	client_params->u.dh.public_key = integer_to_BN(context,
						       "subjectPublicKey",
						       &glue);
	der_free_heim_integer(&glue);
	if (client_params->u.dh.public_key == NULL) {
	    ret = KRB5_BADMSGTYPE;
	    goto out;
	}
    }

    client_params->u.dh.key = dh;
    dh = NULL;
    ret = 0;

 out:
    if (dh)
	DH_free(dh);
    free_DomainParameters(&dhparam);
    return ret;
}

/**
 * @brief Check to see if the certificate's public key matches any
 *        of the trusted keys for this client.
 *
 * @param context[in] krb5_context
 * @param client[in]  client hdb record
 * @param cert[in]    certificate used to sign the request.
 *
 * @return 0 no error
 *         KRB5_KDC_ERR_CLIENT_NOT_TRUSTED certificate public key does not
 *                                         match any of the trusted keys for
 *                                         this client
 *         otherwise an error occurred processing the request.
 */
static krb5_error_code
pk_check_key_trust( krb5_context context, hdb_entry *client, hx509_cert *cert)
{

    krb5_error_code ret = 0;
    SubjectPublicKeyInfo spki;
    HDB_extension *ext = NULL;
    krb5_data buf;
    size_t size = 0;
    HDB_Ext_KeyTrust keys;
    unsigned int i = 0;
    krb5_boolean matched = FALSE;

    memset(&spki, 0, sizeof(spki));
    memset(&buf, 0, sizeof(buf));
    memset(&keys, 0, sizeof(keys));

    ext = hdb_find_extension(client, choice_HDB_extension_data_key_trust);
    if (ext == NULL) {
	ret = KRB5_KDC_ERR_CLIENT_NOT_TRUSTED;
	krb5_set_error_message(context, ret, "Client has no public keys");
	goto out;
    }
    ret = hx509_cert_get_SPKI(context->hx509ctx, *cert, &spki);
    if (ret) {
	ret = KRB5_KDC_ERR_CLIENT_NOT_TRUSTED;
	krb5_set_error_message(
	    context, ret, "Unable to get certificate public key");
	goto out;
    }

    /*
     * Does the certificates public key match any of the trusted public
     * keys for this client?
     */
    ASN1_MALLOC_ENCODE(
	SubjectPublicKeyInfo, buf.data , buf.length, &spki, &size, ret);
    if (ret) {
	krb5_set_error_message(
	    context, ret, "Unable to encode certificate public key");
	goto out1;
    }

    keys = ext->data.u.key_trust;
    for (i = 0; i < keys.len; i++) {
	if (der_heim_octet_string_cmp(&buf, &keys.val[i].pub_key) == 0) {
	    matched = TRUE;
	    break;
	}
    }
    if (!matched) {
	ret = KRB5_KDC_ERR_CLIENT_NOT_TRUSTED;
	krb5_set_error_message(
	    context, ret, "Client public keys do not match");
    }
    der_free_octet_string(&buf);

out1:
    free_SubjectPublicKeyInfo(&spki);
out:
    return ret;
}

/**
 * @brief Match the target name against the value on the certificate
 *
 * name is converted to it's rfc4514 form and compared to the target
 *
 * @param[in] context krb5 context
 * @param[in] name    name on the certificate
 * @param[in] target  value to match name against
 *
 * @return TRUE the name matches
 *         FALSE the name DOES NOT match
 */
static krb5_boolean match_name(
    const krb5_context context,
    const hx509_name *name,
    const heim_octet_string *target)
{
    krb5_boolean matched = FALSE;
    char *ns = NULL;
    char *ts = NULL;
    krb5_error_code ret = 0;

    ret = hx509_name_to_string(*name, &ns);
    if (ret != 0) {
	return FALSE;
    }

    ts = calloc(target->length + 1, sizeof(char));
    if (ts == NULL) {
	goto out;
    }
    memcpy(ts, target->data, target->length);
    if (strncmp(ts, ns, target->length) == 0) {
	matched = TRUE;
    }
    free(ts);

out:
    free(ns);
    return matched;
}

/**
 * @brief does the rfc822 name of the certificate match the value in mapping?
 *
 * @param[in] context krb5 context
 * @param[in] cert    X509 certificate
 * @param[in] m       certificate mapping
 *
 * @return TRUE the certificate matches
 *         FALSE the certificate DOES NOT match
 */
static krb5_boolean
match_rfc822_name(
    const krb5_context context,
    const hx509_cert *cert,
    const HDB_Ext_CertificateMapping *m)
{
    krb5_error_code ret = 0;
    krb5_boolean matched = FALSE;
    size_t j = 0;
    hx509_octet_string_list list;

    ret = hx509_cert_find_subjectAltName_rfc822(context->hx509ctx,
						*cert,
						&list);
    if (ret != 0) {
	return FALSE;
    }

    for (j = 0, matched = FALSE; j < list.len && !matched; j++) {
	if (list.val[j].length == m->rfc822->length &&
	    memcmp(m->rfc822->data, list.val[j].data, list.val[j].length) == 0)
	{
	    matched = TRUE;
	}
    }
    hx509_free_octet_string_list(&list);
    return matched;
}

/**
 * @brief does the SHA1 hash of the certificate public key match the
 *        value in mapping?
 *
 * @param[in] context krb5 context
 * @param[in] cert    X509 certificate
 * @param[in] m       certificate mapping
 *
 * @return TRUE the certificate matches
 *         FALSE the certificate DOES NOT match
 */
static krb5_boolean
match_public_key(
    const krb5_context context,
    const hx509_cert *cert,
    const HDB_Ext_CertificateMapping *m)
{
    krb5_error_code ret = 0;
    krb5_boolean matched = FALSE;
    unsigned char digest[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx = NULL;
    unsigned int size = 0;

    SubjectPublicKeyInfo spki;
    ret = hx509_cert_get_SPKI(context->hx509ctx, *cert, &spki);
    if (ret != 0) {
	return FALSE;
    }

    /*
     * Compute the SHA1 hash of the certificate subject public key
     */
    ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
	goto out;
    }
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(
	ctx, spki.subjectPublicKey.data, spki.subjectPublicKey.length/8);
    EVP_DigestFinal_ex(ctx, digest, &size);
    EVP_MD_CTX_destroy(ctx);

    /*
     * Now compare them
     */
    if (size == m->public_key->length &&
	memcmp(digest, m->public_key->data, m->public_key->length) == 0) {
	matched = TRUE;
    }

out:
    free_SubjectPublicKeyInfo(&spki);
    return matched;
}

/**
 * @brief does the certificate SKI match the SKI in mapping?
 *
 * @param[in] context krb5 context
 * @param[in] cert    X509 certificate
 * @param[in] m       certificate mapping
 *
 * @return TRUE the certificate matches
 *         FALSE the certificate DOES NOT match
 */
static krb5_boolean
match_subject_key_identifier(
    const krb5_context context,
    const hx509_cert *cert,
    const HDB_Ext_CertificateMapping *m)
{
    krb5_error_code ret = 0;
    krb5_boolean matched = FALSE;

    SubjectKeyIdentifier ski;
    ret = hx509_cert_get_subject_key_identifier(context->hx509ctx, *cert, &ski);
    if (ret != 0) {
	return FALSE;
    }
    if (der_heim_octet_string_cmp(m->ski, &ski) == 0) {
	matched = TRUE;
    }
    free_SubjectKeyIdentifier(&ski);
    return matched;
}

/**
 * @brief does the certificate serial number match the serial number in mapping?
 *
 * @param[in] cert X509 certificate
 * @param[in] m    certificate mapping
 *
 * @return TRUE the certificate matches
 *         FALSE the certificate DOES NOT match
 */
static krb5_boolean
match_serial_number(
    const hx509_cert *cert,
    const HDB_Ext_CertificateMapping *m)
{
    krb5_error_code ret = 0;
    krb5_boolean matched = FALSE;
    heim_integer serial_number;

    ret = hx509_cert_get_serialnumber(*cert, &serial_number);
    if (ret != 0) {
	return FALSE;
    }
    if (serial_number.length == m->serial_number->length &&
	memcmp(serial_number.data,
		m->serial_number->data,
		serial_number.length) == 0) {
	matched = TRUE;
    }
    der_free_heim_integer(&serial_number);
    return matched;
}

/**
 * @brief Validate the certificate against the criteria outlined in KB5014754
 *
 * @see KB5014754: Certificate-based authentication changes on Windows domain
 *                 controllers
 *      https://support.microsoft.com/en-us/topic/
 *      kb5014754-certificate-based-authentication-changes-on-windows
 *      -domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
 *
 * @param context[in] krb5 context
 * @param client[in]  client hdb record
 * @param cert[in]    X509 certificate used to sign the request.
 *
 * @return 0 no error
 *         KRB5_KDC_ERR_CLIENT_NOT_TRUSTED certificate fails KB5014754
 *         otherwise an error occurred processing the request.
 */
static krb5_error_code
pk_check_certificate_binding(
    krb5_context context,
    hdb_entry *client,
    hx509_cert *cert)
{

    krb5_error_code ret = 0;
    HDB_extension *ext = NULL;
    HDB_Ext_CertificateMappings mappings;
    unsigned int i = 0;
    krb5_boolean matched = FALSE;
    krb5_boolean strong_mapping = FALSE;

    memset(&mappings, 0, sizeof(mappings));

    /*
	* If there is no extension or the enforcement mode is none
	* then there is nothing to do.
	*/
    ext = hdb_find_extension(client, choice_HDB_extension_data_cert_mappings);
    if (ext == NULL) {
	return 0;
    }
    mappings = ext->data.u.cert_mappings;
    if (mappings.enforcement_mode == hdb_enf_mode_none) {
	ret = 0;
	goto out;
    }

    /*
     * If there are no mappings then reject the logon
     */
    if (mappings.mappings == NULL) {
	ret = KRB5_KDC_ERR_CERTIFICATE_MISMATCH;
	krb5_set_error_message(
	    context, ret, "Client has no certificate mappings");
	goto out;
    }

    for (i = 0, matched = FALSE; i < mappings.mappings->len && !matched; i++) {
	HDB_Ext_CertificateMapping *m = &mappings.mappings->val[i];

	strong_mapping = m->strong_mapping;
	/*
	 * When enforcement mode is full only consider strong mappings
	 */
	if (mappings.enforcement_mode == hdb_enf_mode_full && !strong_mapping) {
	    continue;
	}

	if (m->issuer_name != NULL) {
	    hx509_name issuer;
	    ret = hx509_cert_get_issuer(*cert, &issuer);
	    if (ret != 0) {
		continue;
	    }
	    matched = match_name(context, &issuer, m->issuer_name);
	    hx509_name_free(&issuer);
	    if (!matched) {
		continue;
	    }
	}
	if (m->subject_name != NULL) {
	    hx509_name subject;
	    ret = hx509_cert_get_subject(*cert, &subject);
	    if (ret != 0) {
		continue;
	    }
	    matched = match_name(context, &subject, m->subject_name);
	    hx509_name_free(&subject);
	    if (!matched) {
		continue;
	    }
	}
	if (m->rfc822 != NULL) {
	    matched = match_rfc822_name(context, cert, m);
	    if (!matched) {
		continue;
	    }
	}
	if (m->ski != NULL) {
	    matched = match_subject_key_identifier(context, cert, m);
	    if (!matched) {
		continue;
	    }
	}
	if (m->public_key != NULL) {
	    matched = match_public_key(context, cert, m);
	    if (!matched) {
		continue;
	    }
	}
	if (m->serial_number != NULL) {
	    matched = match_serial_number(cert, m);
	    if (!matched) {
		continue;
	    }
	}
    }

    /*
     * When enforcement mode is compatibility need to consider
     * the age of the certificate for weak mappings
     */
    if (mappings.enforcement_mode == hdb_enf_mode_compatibility &&
	matched &&
	!strong_mapping) {

	time_t certificate_start = hx509_cert_get_notBefore(*cert);
	if (mappings.valid_certificate_start > certificate_start) {
	    matched = FALSE;
	}
    }
    if (!matched) {
	krb5_warnx(context, "PKINIT: No matching certificate mappings");
	ret = KRB5_KDC_ERR_CERTIFICATE_MISMATCH;
    }
out:
    return ret;
}

krb5_error_code
_kdc_pk_rd_padata(astgs_request_t priv,
		  const PA_DATA *pa,
		  pk_client_params **ret_params)
{
    /* XXXrcd: we use priv vs r due to a conflict */
    krb5_context context = priv->context;
    krb5_kdc_configuration *config = priv->config;
    const KDC_REQ *req = &priv->req;
    hdb_entry *client = priv->client;
    pk_client_params *cp;
    krb5_error_code ret;
    heim_oid eContentType = { 0, NULL }, contentInfoOid = { 0, NULL };
    krb5_data eContent = { 0, NULL };
    krb5_data signed_content = { 0, NULL };
    const char *type = "unknown type";
    hx509_certs trust_anchors;
    int have_data = 0;
    const HDB_Ext_PKINIT_cert *pc;

    *ret_params = NULL;

    if (!config->enable_pkinit) {
	kdc_log(context, config, 0, "PKINIT request but PKINIT not enabled");
	krb5_clear_error_message(context);
	return 0;
    }

    cp = calloc(1, sizeof(*cp));
    if (cp == NULL) {
	krb5_clear_error_message(context);
	ret = ENOMEM;
	goto out;
    }

    ret = hx509_certs_init(context->hx509ctx,
			   "MEMORY:trust-anchors",
			   0, NULL, &trust_anchors);
    if (ret) {
	krb5_set_error_message(context, ret, "failed to create trust anchors");
	goto out;
    }

    ret = hx509_certs_merge(context->hx509ctx, trust_anchors,
			    kdc_identity->anchors);
    if (ret) {
	hx509_certs_free(&trust_anchors);
	krb5_set_error_message(context, ret, "failed to create verify context");
	goto out;
    }

    /* Add any registered certificates for this client as trust anchors */
    ret = hdb_entry_get_pkinit_cert(client, &pc);
    if (ret == 0 && pc != NULL) {
	hx509_cert cert;
	unsigned int i;

	for (i = 0; i < pc->len; i++) {
	    cert = hx509_cert_init_data(context->hx509ctx,
					pc->val[i].cert.data,
					pc->val[i].cert.length,
					NULL);
	    if (cert == NULL)
		continue;
	    hx509_certs_add(context->hx509ctx, trust_anchors, cert);
	    hx509_cert_free(cert);
	}
    }

    ret = hx509_verify_init_ctx(context->hx509ctx, &cp->verify_ctx);
    if (ret) {
	hx509_certs_free(&trust_anchors);
	krb5_set_error_message(context, ret, "failed to create verify context");
	goto out;
    }

    hx509_verify_set_time(cp->verify_ctx, kdc_time);
    hx509_verify_attach_anchors(cp->verify_ctx, trust_anchors);
    hx509_certs_free(&trust_anchors);

    hx509_verify_attach_revoke(cp->verify_ctx, kdc_identity->revokectx);

    if (config->pkinit_allow_proxy_certs)
	hx509_verify_set_proxy_certificate(cp->verify_ctx, 1);

    if (pa->padata_type == KRB5_PADATA_PK_AS_REQ_WIN) {
	PA_PK_AS_REQ_Win2k r;

	type = "PK-INIT-Win2k";

	if (_kdc_is_anonymous(context, client->principal)) {
	    ret = KRB5_KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED;
	    krb5_set_error_message(context, ret,
		"Anonymous client not supported in RSA mode");
	    goto out;
	}

	ret = decode_PA_PK_AS_REQ_Win2k(pa->padata_value.data,
					pa->padata_value.length,
					&r,
					NULL);
	if (ret) {
	    krb5_set_error_message(context, ret, "Can't decode "
				   "PK-AS-REQ-Win2k: %d", ret);
	    goto out;
	}

	ret = hx509_cms_unwrap_ContentInfo(&r.signed_auth_pack,
					   &contentInfoOid,
					   &signed_content,
					   &have_data);
	free_PA_PK_AS_REQ_Win2k(&r);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't unwrap ContentInfo(win): %d", ret);
	    goto out;
	}

    } else if (pa->padata_type == KRB5_PADATA_PK_AS_REQ) {
	PA_PK_AS_REQ r;

	type = "PK-INIT-IETF";

	ret = decode_PA_PK_AS_REQ(pa->padata_value.data,
				  pa->padata_value.length,
				  &r,
				  NULL);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't decode PK-AS-REQ: %d", ret);
	    goto out;
	}

	/* XXX look at r.kdcPkId */
	if (r.trustedCertifiers) {
	    ExternalPrincipalIdentifiers *edi = r.trustedCertifiers;
	    unsigned int i, maxedi;

	    ret = hx509_certs_init(context->hx509ctx,
				   "MEMORY:client-anchors",
				   0, NULL,
				   &cp->client_anchors);
	    if (ret) {
		krb5_set_error_message(context, ret,
				       "Can't allocate client anchors: %d",
				       ret);
		goto out;

	    }
	    /*
	     * If the client sent more than 10 EDIs, don't bother
	     * looking at more than 10 for performance reasons.
	     */
	    maxedi = edi->len;
	    if (maxedi > 10)
		maxedi = 10;
	    for (i = 0; i < maxedi; i++) {
		IssuerAndSerialNumber iasn;
		hx509_query *q;
		hx509_cert cert;
		size_t size;

		if (edi->val[i].issuerAndSerialNumber == NULL)
		    continue;

		ret = hx509_query_alloc(context->hx509ctx, &q);
		if (ret) {
		    krb5_set_error_message(context, ret,
					  "Failed to allocate hx509_query");
		    goto out;
		}

		ret = decode_IssuerAndSerialNumber(edi->val[i].issuerAndSerialNumber->data,
						   edi->val[i].issuerAndSerialNumber->length,
						   &iasn,
						   &size);
		if (ret) {
		    hx509_query_free(context->hx509ctx, q);
		    continue;
		}
		ret = hx509_query_match_issuer_serial(q, &iasn.issuer, &iasn.serialNumber);
		free_IssuerAndSerialNumber(&iasn);
		if (ret) {
		    hx509_query_free(context->hx509ctx, q);
		    continue;
		}

		ret = hx509_certs_find(context->hx509ctx,
				       kdc_identity->certs,
				       q,
				       &cert);
		hx509_query_free(context->hx509ctx, q);
		if (ret)
		    continue;
		hx509_certs_add(context->hx509ctx,
				cp->client_anchors, cert);
		hx509_cert_free(cert);
	    }
	}

	ret = hx509_cms_unwrap_ContentInfo(&r.signedAuthPack,
					   &contentInfoOid,
					   &signed_content,
					   &have_data);
	free_PA_PK_AS_REQ(&r);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't unwrap ContentInfo: %d", ret);
	    goto out;
	}

    } else {
	krb5_clear_error_message(context);
	ret = KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
	goto out;
    }

    ret = der_heim_oid_cmp(&contentInfoOid, &asn1_oid_id_pkcs7_signedData);
    if (ret != 0) {
	ret = KRB5KRB_ERR_GENERIC;
	krb5_set_error_message(context, ret,
			       "PK-AS-REQ-Win2k invalid content type oid");
	goto out;
    }

    if (!have_data) {
	ret = KRB5KRB_ERR_GENERIC;
	krb5_set_error_message(context, ret,
			      "PK-AS-REQ-Win2k no signed auth pack");
	goto out;
    }

    {
	hx509_certs signer_certs;
	int flags = HX509_CMS_VS_ALLOW_DATA_OID_MISMATCH; /* BTMM */

	if (_kdc_is_anonymous(context, client->principal)
	    || (config->historical_anon_realm && _kdc_is_anon_request(req)))
	    flags |= HX509_CMS_VS_ALLOW_ZERO_SIGNER;

	ret = hx509_cms_verify_signed(context->hx509ctx,
				      cp->verify_ctx,
				      flags,
				      signed_content.data,
				      signed_content.length,
				      NULL,
				      kdc_identity->certpool,
				      &eContentType,
				      &eContent,
				      &signer_certs);
	if (ret == 0) {
	    if (signer_certs) {
		ret = hx509_get_one_cert(
		    context->hx509ctx, signer_certs, &cp->cert);
		hx509_certs_free(&signer_certs);
	    }
	    if (ret) {
		goto out;
	    }
	    ret = pk_check_certificate_binding(context, client, &cp->cert);
	    if (ret) {
		goto out;
	    }
	} else if (ret == HX509_CMS_NO_RECIPIENT_CERTIFICATE ||
		   ret == HX509_ISSUER_NOT_FOUND) {
	    /*
	     * Certificate not in the chain of trust,
	     * however it could be a self signed certificate for key trust
	     * logon.
	    */
	    int f = flags;
	    f |= HX509_CMS_VS_NO_VALIDATE;
	    ret = hx509_cms_verify_signed(context->hx509ctx,
					  cp->verify_ctx,
					  f,
					  signed_content.data,
					  signed_content.length,
					  NULL,
					  kdc_identity->certpool,
					  &eContentType,
					  &eContent,
					  &signer_certs);
	    if (ret != 0) {
		char *s = hx509_get_error_string(context->hx509ctx, ret);
		krb5_warnx(context,
			   "PKINIT: failed to verify signature: %s: %d",
			   s,
			   ret);
		free(s);
		goto out;
	    }
	    if (signer_certs == NULL) {
		ret = HX509_CMS_NO_RECIPIENT_CERTIFICATE;
		goto out;
	    }
	    ret = hx509_get_one_cert(
		context->hx509ctx, signer_certs, &cp->cert);
	    hx509_certs_free(&signer_certs);
	    if (ret != 0) {
		goto out;
	    }
	    ret = pk_check_key_trust(context, client, &cp->cert);
	    if (ret) {
		goto out;
	    }
	} else {
	    char *s = hx509_get_error_string(context->hx509ctx, ret);
	    krb5_warnx(context, "PKINIT: failed to verify signature: %s: %d",
		       s, ret);
	    free(s);
	    goto out;
	}
    }

    /* Signature is correct, now verify the signed message */
    if (der_heim_oid_cmp(&eContentType, &asn1_oid_id_pkcs7_data) != 0 &&
	der_heim_oid_cmp(&eContentType, &asn1_oid_id_pkauthdata) != 0)
    {
	ret = KRB5_BADMSGTYPE;
	krb5_set_error_message(context, ret, "got wrong oid for PK AuthData");
	goto out;
    }

    if (pa->padata_type == KRB5_PADATA_PK_AS_REQ_WIN) {
	AuthPack_Win2k ap;

	ret = decode_AuthPack_Win2k(eContent.data,
				    eContent.length,
				    &ap,
				    NULL);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't decode AuthPack: %d", ret);
	    goto out;
	}

	ret = pk_check_pkauthenticator_win2k(context,
					     &ap.pkAuthenticator,
					     req);
	if (ret) {
	    free_AuthPack_Win2k(&ap);
	    goto out;
	}

	cp->type = PKINIT_WIN2K;
	cp->nonce = ap.pkAuthenticator.nonce;

	if (ap.clientPublicValue) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(context, ret,
				   "DH not supported for Win2k");
	    free_AuthPack_Win2k(&ap);
	    goto out;
	}
	free_AuthPack_Win2k(&ap);

    } else if (pa->padata_type == KRB5_PADATA_PK_AS_REQ) {
	AuthPack ap;

	ret = decode_AuthPack(eContent.data,
			      eContent.length,
			      &ap,
			      NULL);
	if (ret) {
	    krb5_set_error_message(context, ret,
				   "Can't decode AuthPack: %d", ret);
	    free_AuthPack(&ap);
	    goto out;
	}

	if (_kdc_is_anonymous(context, client->principal) &&
	    ap.clientPublicValue == NULL) {
	    free_AuthPack(&ap);
	    ret = KRB5_KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED;
	    krb5_set_error_message(context, ret,
		"Anonymous client not supported in RSA mode");
	    goto out;
	}

	ret = pk_check_pkauthenticator(context,
				       &ap.pkAuthenticator,
				       req);
	if (ret) {
	    free_AuthPack(&ap);
	    goto out;
	}

	cp->type = PKINIT_27;
	cp->nonce = ap.pkAuthenticator.nonce;

	if (ap.clientPublicValue) {
	    if (der_heim_oid_cmp(&ap.clientPublicValue->algorithm.algorithm, &asn1_oid_id_dhpublicnumber) == 0) {
		cp->keyex = USE_DH;
		ret = get_dh_param(context, config,
				   ap.clientPublicValue, cp);
	    } else if (der_heim_oid_cmp(&ap.clientPublicValue->algorithm.algorithm, &asn1_oid_id_ecPublicKey) == 0) {
		cp->keyex = USE_ECDH;
                ret = _kdc_get_ecdh_param(context, config,
                                          ap.clientPublicValue,
                                          &cp->u.ecdh.public_key);
	    } else {
		ret = KRB5_BADMSGTYPE;
		krb5_set_error_message(context, ret,
		    "PKINIT unknown DH mechanism");
	    }
	    if (ret) {
		free_AuthPack(&ap);
		goto out;
	    }
	} else
	    cp->keyex = USE_RSA;

	ret = hx509_peer_info_alloc(context->hx509ctx,
					&cp->peer);
	if (ret) {
	    free_AuthPack(&ap);
	    goto out;
	}

	if (ap.supportedCMSTypes) {
	    ret = hx509_peer_info_set_cms_algs(context->hx509ctx,
					       cp->peer,
					       ap.supportedCMSTypes->val,
					       ap.supportedCMSTypes->len);
	    if (ret) {
		free_AuthPack(&ap);
		goto out;
	    }
	} else {
	    /* assume old client */
	    hx509_peer_info_add_cms_alg(context->hx509ctx, cp->peer,
					hx509_crypto_des_rsdi_ede3_cbc());
	    hx509_peer_info_add_cms_alg(context->hx509ctx, cp->peer,
					hx509_signature_rsa_with_sha1());
	    hx509_peer_info_add_cms_alg(context->hx509ctx, cp->peer,
					hx509_signature_sha1());
	}

	/*
	 * Copy the freshness token into the out parameters if it is present.
	 */
	if (ap.pkAuthenticator.freshnessToken != NULL) {
	    cp->freshness_token = calloc(1, sizeof (*cp->freshness_token));
	    if (cp->freshness_token == NULL) {
		ret = ENOMEM;
		free_AuthPack(&ap);
		goto out;
	    }

	    ret = der_copy_octet_string(ap.pkAuthenticator.freshnessToken, cp->freshness_token);
	    if (ret) {
		free_AuthPack(&ap);
		goto out;
	    }
	}

	free_AuthPack(&ap);
    } else
	krb5_abortx(context, "internal pkinit error");

    kdc_log(context, config, 0, "PKINIT request of type %s", type);

out:
    if (ret)
	krb5_warn(context, ret, "PKINIT");

    if (signed_content.data)
	free(signed_content.data);
    krb5_data_free(&eContent);
    der_free_oid(&eContentType);
    der_free_oid(&contentInfoOid);
    if (ret) {
        _kdc_pk_free_client_param(context, cp);
    } else
	*ret_params = cp;
    return ret;
}

krb5_timestamp
_kdc_pk_endtime(pk_client_params *pkp)
{
    return pkp->endtime;
}

krb5_timestamp
_kdc_pk_max_life(pk_client_params *pkp)
{
    return pkp->max_life;
}

unsigned
_kdc_pk_nonce(pk_client_params *pkp)
{
    return pkp->nonce;
}

/*
 *
 */

static krb5_error_code
BN_to_integer(krb5_context context, BIGNUM *bn, heim_integer *integer)
{
    integer->length = BN_num_bytes(bn);
    integer->data = malloc(integer->length);
    if (integer->data == NULL) {
	krb5_clear_error_message(context);
	return ENOMEM;
    }
    BN_bn2bin(bn, integer->data);
    integer->negative = BN_is_negative(bn);
    return 0;
}

static krb5_error_code
pk_mk_pa_reply_enckey(krb5_context context,
		      krb5_kdc_configuration *config,
		      pk_client_params *cp,
		      const KDC_REQ *req,
		      const krb5_data *req_buffer,
		      krb5_keyblock *reply_key,
		      ContentInfo *content_info,
		      hx509_cert *kdc_cert)
{
    const heim_oid *envelopedAlg = NULL, *sdAlg = NULL, *evAlg = NULL;
    krb5_error_code ret;
    krb5_data buf, signed_data;
    size_t size = 0;
    int do_win2k = 0;

    krb5_data_zero(&buf);
    krb5_data_zero(&signed_data);

    *kdc_cert = NULL;

    /*
     * If the message client is a win2k-type but it sends pa data
     * 09-binding it expects a IETF (checksum) reply so there can be
     * no replay attacks.
     */

    switch (cp->type) {
    case PKINIT_WIN2K: {
	int i = 0;
	if (_kdc_find_padata(req, &i, KRB5_PADATA_PK_AS_09_BINDING) == NULL
	    && config->pkinit_require_binding == 0)
	{
	    do_win2k = 1;
	}
	sdAlg = &asn1_oid_id_pkcs7_data;
	evAlg = &asn1_oid_id_pkcs7_data;
	envelopedAlg = &asn1_oid_id_rsadsi_des_ede3_cbc;
	break;
    }
    case PKINIT_27:
	sdAlg = &asn1_oid_id_pkrkeydata;
	evAlg = &asn1_oid_id_pkcs7_signedData;
	break;
    default:
	krb5_abortx(context, "internal pkinit error");
    }

    if (do_win2k) {
	ReplyKeyPack_Win2k kp;
	memset(&kp, 0, sizeof(kp));

	ret = copy_EncryptionKey(reply_key, &kp.replyKey);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}
	kp.nonce = cp->nonce;

	ASN1_MALLOC_ENCODE(ReplyKeyPack_Win2k,
			   buf.data, buf.length,
			   &kp, &size,ret);
	free_ReplyKeyPack_Win2k(&kp);
    } else {
	krb5_crypto ascrypto;
	ReplyKeyPack kp;
	memset(&kp, 0, sizeof(kp));

	ret = copy_EncryptionKey(reply_key, &kp.replyKey);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}

	ret = krb5_crypto_init(context, reply_key, 0, &ascrypto);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}

	ret = krb5_create_checksum(context, ascrypto, 6, 0,
				   req_buffer->data, req_buffer->length,
				   &kp.asChecksum);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}

	ret = krb5_crypto_destroy(context, ascrypto);
	if (ret) {
	    krb5_clear_error_message(context);
	    goto out;
	}
	ASN1_MALLOC_ENCODE(ReplyKeyPack, buf.data, buf.length, &kp, &size,ret);
	free_ReplyKeyPack(&kp);
    }
    if (ret) {
	krb5_set_error_message(context, ret, "ASN.1 encoding of ReplyKeyPack "
			       "failed (%d)", ret);
	goto out;
    }
    if (buf.length != size)
	krb5_abortx(context, "Internal ASN.1 encoder error");

    {
	hx509_query *q;
	hx509_cert cert;

	ret = hx509_query_alloc(context->hx509ctx, &q);
	if (ret)
	    goto out;

	hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
	if (config->pkinit_kdc_friendly_name)
	    hx509_query_match_friendly_name(q, config->pkinit_kdc_friendly_name);

	ret = hx509_certs_find(context->hx509ctx,
			       kdc_identity->certs,
			       q,
			       &cert);
	hx509_query_free(context->hx509ctx, q);
	if (ret)
	    goto out;

	ret = hx509_cms_create_signed_1(context->hx509ctx,
					0,
					sdAlg,
					buf.data,
					buf.length,
					NULL,
					cert,
					cp->peer,
					cp->client_anchors,
					kdc_identity->certpool,
					&signed_data);
	*kdc_cert = cert;
    }

    krb5_data_free(&buf);
    if (ret)
	goto out;

    if (cp->type == PKINIT_WIN2K) {
	ret = hx509_cms_wrap_ContentInfo(&asn1_oid_id_pkcs7_signedData,
					 &signed_data,
					 &buf);
	if (ret)
	    goto out;
	krb5_data_free(&signed_data);
	signed_data = buf;
    }

    ret = hx509_cms_envelope_1(context->hx509ctx,
			       HX509_CMS_EV_NO_KU_CHECK,
			       cp->cert,
			       signed_data.data, signed_data.length,
			       envelopedAlg,
			       evAlg, &buf);
    if (ret)
	goto out;

    ret = _krb5_pk_mk_ContentInfo(context,
				  &buf,
				  &asn1_oid_id_pkcs7_envelopedData,
				  content_info);
out:
    if (ret && *kdc_cert) {
        hx509_cert_free(*kdc_cert);
	*kdc_cert = NULL;
    }

    krb5_data_free(&buf);
    krb5_data_free(&signed_data);
    return ret;
}

/*
 *
 */

static krb5_error_code
pk_mk_pa_reply_dh(krb5_context context,
		  krb5_kdc_configuration *config,
      		  pk_client_params *cp,
		  ContentInfo *content_info,
		  hx509_cert *kdc_cert)
{
    KDCDHKeyInfo dh_info;
    krb5_data signed_data, buf;
    ContentInfo contentinfo;
    krb5_error_code ret;
    hx509_cert cert;
    hx509_query *q;
    size_t size = 0;

    memset(&contentinfo, 0, sizeof(contentinfo));
    memset(&dh_info, 0, sizeof(dh_info));
    krb5_data_zero(&signed_data);
    krb5_data_zero(&buf);

    *kdc_cert = NULL;

    if (cp->keyex == USE_DH) {
	DH *kdc_dh = cp->u.dh.key;
	heim_integer i;

	ret = BN_to_integer(context, kdc_dh->pub_key, &i);
	if (ret)
	    return ret;

	ASN1_MALLOC_ENCODE(DHPublicKey, buf.data, buf.length, &i, &size, ret);
	der_free_heim_integer(&i);
	if (ret) {
	    krb5_set_error_message(context, ret, "ASN.1 encoding of "
				   "DHPublicKey failed (%d)", ret);
	    return ret;
	}
	if (buf.length != size)
	    krb5_abortx(context, "Internal ASN.1 encoder error");

	dh_info.subjectPublicKey.length = buf.length * 8;
	dh_info.subjectPublicKey.data = buf.data;
	krb5_data_zero(&buf);
    } else if (cp->keyex == USE_ECDH) {
        unsigned char *p;
        ret = _kdc_serialize_ecdh_key(context, cp->u.ecdh.key, &p,
                                      &dh_info.subjectPublicKey.length);
        if (ret)
            goto out;
        dh_info.subjectPublicKey.data = p;
    } else
	krb5_abortx(context, "no keyex selected ?");


    dh_info.nonce = cp->nonce;

    ASN1_MALLOC_ENCODE(KDCDHKeyInfo, buf.data, buf.length, &dh_info, &size,
		       ret);
    if (ret) {
	krb5_set_error_message(context, ret, "ASN.1 encoding of "
			       "KdcDHKeyInfo failed (%d)", ret);
	goto out;
    }
    if (buf.length != size)
	krb5_abortx(context, "Internal ASN.1 encoder error");

    /*
     * Create the SignedData structure and sign the KdcDHKeyInfo
     * filled in above
     */

    ret = hx509_query_alloc(context->hx509ctx, &q);
    if (ret)
	goto out;

    hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
    if (config->pkinit_kdc_friendly_name)
	hx509_query_match_friendly_name(q, config->pkinit_kdc_friendly_name);

    ret = hx509_certs_find(context->hx509ctx,
			   kdc_identity->certs,
			   q,
			   &cert);
    hx509_query_free(context->hx509ctx, q);
    if (ret)
	goto out;

    ret = hx509_cms_create_signed_1(context->hx509ctx,
				    0,
				    &asn1_oid_id_pkdhkeydata,
				    buf.data,
				    buf.length,
				    NULL,
				    cert,
				    cp->peer,
				    cp->client_anchors,
				    kdc_identity->certpool,
				    &signed_data);
    if (ret) {
	kdc_log(context, config, 0, "Failed signing the DH* reply: %d", ret);
	goto out;
    }
    *kdc_cert = cert;

    ret = _krb5_pk_mk_ContentInfo(context,
				  &signed_data,
				  &asn1_oid_id_pkcs7_signedData,
				  content_info);
    if (ret)
	goto out;

 out:
    if (ret && *kdc_cert) {
	hx509_cert_free(*kdc_cert);
	*kdc_cert = NULL;
    }

    krb5_data_free(&buf);
    krb5_data_free(&signed_data);
    free_KDCDHKeyInfo(&dh_info);

    return ret;
}

/*
 *
 */

krb5_error_code
_kdc_pk_mk_pa_reply(astgs_request_t r, pk_client_params *cp)
{
    krb5_kdc_configuration *config = r->config;
    krb5_enctype sessionetype = r->sessionetype;
    const KDC_REQ *req = &r->req;
    const krb5_data *req_buffer = &r->request;
    krb5_keyblock *reply_key = &r->reply_key;
    krb5_keyblock *sessionkey = &r->session_key;
    METHOD_DATA *md = r->rep.padata;
    krb5_error_code ret;
    void *buf = NULL;
    size_t len = 0, size = 0;
    krb5_enctype enctype;
    int pa_type;
    hx509_cert kdc_cert = NULL;
    size_t i;

    if (!config->enable_pkinit) {
	krb5_clear_error_message(r->context);
	return 0;
    }

    if (req->req_body.etype.len > 0) {
	for (i = 0; i < req->req_body.etype.len; i++)
	    if (krb5_enctype_valid(r->context, req->req_body.etype.val[i]) == 0)
		break;
	if (req->req_body.etype.len <= i) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(r->context, ret,
				   "No valid enctype available from client");
	    goto out;
	}
	enctype = req->req_body.etype.val[i];
    } else
	enctype = ETYPE_DES3_CBC_SHA1;

    if (cp->type == PKINIT_27) {
	PA_PK_AS_REP rep;
	const char *type, *other = "";

	memset(&rep, 0, sizeof(rep));

	pa_type = KRB5_PADATA_PK_AS_REP;

	if (cp->keyex == USE_RSA) {
	    ContentInfo info;

	    type = "enckey";

	    rep.element = choice_PA_PK_AS_REP_encKeyPack;

	    ret = krb5_generate_random_keyblock(r->context, enctype,
						&cp->reply_key);
	    if (ret) {
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }
	    ret = pk_mk_pa_reply_enckey(r->context,
					config,
					cp,
					req,
					req_buffer,
					&cp->reply_key,
					&info,
					&kdc_cert);
	    if (ret) {
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }
	    ASN1_MALLOC_ENCODE(ContentInfo, rep.u.encKeyPack.data,
			       rep.u.encKeyPack.length, &info, &size,
			       ret);
	    free_ContentInfo(&info);
	    if (ret) {
		krb5_set_error_message(r->context, ret, "encoding of Key ContentInfo "
				       "failed %d", ret);
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }
	    if (rep.u.encKeyPack.length != size)
		krb5_abortx(r->context, "Internal ASN.1 encoder error");

	    ret = krb5_generate_random_keyblock(r->context, sessionetype,
						sessionkey);
	    if (ret) {
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }

	} else {
	    ContentInfo info;

	    switch (cp->keyex) {
	    case USE_DH: type = "dh"; break;
	    case USE_ECDH: type = "ecdh"; break;
	    default: krb5_abortx(r->context, "unknown keyex"); break;
	    }

	    if (cp->dh_group_name)
		other = cp->dh_group_name;

	    rep.element = choice_PA_PK_AS_REP_dhInfo;

	    ret = generate_dh_keyblock(r->context, cp, enctype);
	    if (ret)
		return ret;

	    ret = pk_mk_pa_reply_dh(r->context, config,
				    cp,
				    &info,
				    &kdc_cert);
	    if (ret) {
		free_PA_PK_AS_REP(&rep);
		krb5_set_error_message(r->context, ret,
				       "create pa-reply-dh "
				       "failed %d", ret);
		goto out;
	    }

	    ASN1_MALLOC_ENCODE(ContentInfo, rep.u.dhInfo.dhSignedData.data,
			       rep.u.dhInfo.dhSignedData.length, &info, &size,
			       ret);
	    free_ContentInfo(&info);
	    if (ret) {
		krb5_set_error_message(r->context, ret,
				       "encoding of Key ContentInfo "
				       "failed %d", ret);
		free_PA_PK_AS_REP(&rep);
		goto out;
	    }
	    if (rep.u.encKeyPack.length != size)
		krb5_abortx(r->context, "Internal ASN.1 encoder error");

	    /* generate the session key using the method from RFC6112 */
	    {
		krb5_keyblock kdc_contribution_key;
		krb5_crypto reply_crypto;
		krb5_crypto kdccont_crypto;
		krb5_data p1 = { strlen("PKINIT"), "PKINIT"};
		krb5_data p2 = { strlen("KEYEXCHANGE"), "KEYEXCHANGE"};
		void *kckdata;
		size_t kcklen;
		EncryptedData kx;
		void *kxdata;
		size_t kxlen;

		ret = krb5_generate_random_keyblock(r->context, sessionetype,
						&kdc_contribution_key);
		if (ret) {
		    free_PA_PK_AS_REP(&rep);
		    goto out;
		}
		ret = krb5_crypto_init(r->context, &cp->reply_key, enctype, &reply_crypto);
		if (ret) {
		    krb5_free_keyblock_contents(r->context, &kdc_contribution_key);
		    free_PA_PK_AS_REP(&rep);
		    goto out;
		}
		ret = krb5_crypto_init(r->context, &kdc_contribution_key, sessionetype, &kdccont_crypto);
		if (ret) {
		    krb5_crypto_destroy(r->context, reply_crypto);
		    krb5_free_keyblock_contents(r->context, &kdc_contribution_key);
		    free_PA_PK_AS_REP(&rep);
		    goto out;
		}
		/* KRB-FX-CF2 */
		ret = krb5_crypto_fx_cf2(r->context, kdccont_crypto, reply_crypto,
					 &p1, &p2, sessionetype, sessionkey);
		krb5_crypto_destroy(r->context, kdccont_crypto);
		if (ret) {
		    krb5_crypto_destroy(r->context, reply_crypto);
		    krb5_free_keyblock_contents(r->context, &kdc_contribution_key);
		    free_PA_PK_AS_REP(&rep);
		    goto out;
		}
		ASN1_MALLOC_ENCODE(EncryptionKey, kckdata, kcklen,
				   &kdc_contribution_key, &size, ret);
		krb5_free_keyblock_contents(r->context, &kdc_contribution_key);
		if (ret) {
		    krb5_set_error_message(r->context, ret, "encoding of PKINIT-KX Key failed %d", ret);
		    krb5_crypto_destroy(r->context, reply_crypto);
		    free_PA_PK_AS_REP(&rep);
		    goto out;
		}
		if (kcklen != size)
		    krb5_abortx(r->context, "Internal ASN.1 encoder error");
		ret = krb5_encrypt_EncryptedData(r->context, reply_crypto, KRB5_KU_PA_PKINIT_KX,
					kckdata, kcklen, 0, &kx);
		krb5_crypto_destroy(r->context, reply_crypto);
		free(kckdata);
		if (ret) {
		    free_PA_PK_AS_REP(&rep);
		    goto out;
		}
		ASN1_MALLOC_ENCODE(EncryptedData, kxdata, kxlen,
				   &kx, &size, ret);
		free_EncryptedData(&kx);
		if (ret) {
		    krb5_set_error_message(r->context, ret,
				"encoding of PKINIT-KX failed %d", ret);
		    free_PA_PK_AS_REP(&rep);
		    goto out;
		}
		if (kxlen != size)
		    krb5_abortx(r->context, "Internal ASN.1 encoder error");
		/* Add PA-PKINIT-KX */
		ret = krb5_padata_add(r->context, md, KRB5_PADATA_PKINIT_KX, kxdata, kxlen);
		if (ret) {
		    krb5_set_error_message(r->context, ret,
					   "Failed adding PKINIT-KX %d", ret);
		    free(buf);
		    goto out;
		}
	    }
	}

#define use_btmm_with_enckey 0
	if (use_btmm_with_enckey && rep.element == choice_PA_PK_AS_REP_encKeyPack) {
	    PA_PK_AS_REP_BTMM btmm;
	    heim_any any;

	    any.data = rep.u.encKeyPack.data;
	    any.length = rep.u.encKeyPack.length;

	    btmm.dhSignedData = NULL;
	    btmm.encKeyPack = &any;

	    ASN1_MALLOC_ENCODE(PA_PK_AS_REP_BTMM, buf, len, &btmm, &size, ret);
	} else {
	    ASN1_MALLOC_ENCODE(PA_PK_AS_REP, buf, len, &rep, &size, ret);
	}

	free_PA_PK_AS_REP(&rep);
	if (ret) {
	    krb5_set_error_message(r->context, ret,
				   "encode PA-PK-AS-REP failed %d", ret);
	    goto out;
	}
	if (len != size)
	    krb5_abortx(r->context, "Internal ASN.1 encoder error");

	kdc_log(r->context, config, 0, "PKINIT using %s %s", type, other);

    } else if (cp->type == PKINIT_WIN2K) {
	PA_PK_AS_REP_Win2k rep;
	ContentInfo info;

	if (cp->keyex != USE_RSA) {
	    ret = KRB5KRB_ERR_GENERIC;
	    krb5_set_error_message(r->context, ret,
				   "Win2k PKINIT doesn't support DH");
	    goto out;
	}

	memset(&rep, 0, sizeof(rep));

	pa_type = KRB5_PADATA_PK_AS_REP_19;
	rep.element = choice_PA_PK_AS_REP_Win2k_encKeyPack;

	ret = krb5_generate_random_keyblock(r->context, enctype,
					    &cp->reply_key);
	if (ret) {
	    free_PA_PK_AS_REP_Win2k(&rep);
	    goto out;
	}
	ret = pk_mk_pa_reply_enckey(r->context,
				    config,
				    cp,
				    req,
				    req_buffer,
				    &cp->reply_key,
				    &info,
				    &kdc_cert);
	if (ret) {
	    free_PA_PK_AS_REP_Win2k(&rep);
	    goto out;
	}
	ASN1_MALLOC_ENCODE(ContentInfo, rep.u.encKeyPack.data,
			   rep.u.encKeyPack.length, &info, &size,
			   ret);
	free_ContentInfo(&info);
	if (ret) {
	    krb5_set_error_message(r->context, ret, "encoding of Key ContentInfo "
				  "failed %d", ret);
	    free_PA_PK_AS_REP_Win2k(&rep);
	    goto out;
	}
	if (rep.u.encKeyPack.length != size)
	    krb5_abortx(r->context, "Internal ASN.1 encoder error");

	ASN1_MALLOC_ENCODE(PA_PK_AS_REP_Win2k, buf, len, &rep, &size, ret);
	free_PA_PK_AS_REP_Win2k(&rep);
	if (ret) {
	    krb5_set_error_message(r->context, ret,
				  "encode PA-PK-AS-REP-Win2k failed %d", ret);
	    goto out;
	}
	if (len != size)
	    krb5_abortx(r->context, "Internal ASN.1 encoder error");

	ret = krb5_generate_random_keyblock(r->context, sessionetype,
					    sessionkey);
	if (ret) {
	    free(buf);
	    goto out;
	}

    } else
	krb5_abortx(r->context, "PKINIT internal error");


    ret = krb5_padata_add(r->context, md, pa_type, buf, len);
    if (ret) {
	krb5_set_error_message(r->context, ret,
			       "Failed adding PA-PK-AS-REP %d", ret);
	free(buf);
	goto out;
    }

    if (config->pkinit_kdc_ocsp_file) {

	if (ocsp.expire == 0 && ocsp.next_update > kdc_time) {
	    struct stat sb;
	    int fd;

	    krb5_data_free(&ocsp.data);

	    ocsp.expire = 0;
	    ocsp.next_update = kdc_time + 60 * 5;

	    fd = open(config->pkinit_kdc_ocsp_file, O_RDONLY);
	    if (fd < 0) {
		kdc_log(r->context, config, 0,
			"PKINIT failed to open ocsp data file %d", errno);
		goto out_ocsp;
	    }
	    ret = fstat(fd, &sb);
	    if (ret) {
		ret = errno;
		close(fd);
		kdc_log(r->context, config, 0,
			"PKINIT failed to stat ocsp data %d", ret);
		goto out_ocsp;
	    }

	    ret = krb5_data_alloc(&ocsp.data, sb.st_size);
	    if (ret) {
		close(fd);
		kdc_log(r->context, config, 0,
			"PKINIT failed to allocate ocsp data %d", ret);
		goto out_ocsp;
	    }
	    ocsp.data.length = sb.st_size;
	    ret = read(fd, ocsp.data.data, sb.st_size);
	    close(fd);
	    if (ret != sb.st_size) {
		kdc_log(r->context, config, 0,
			"PKINIT failed to read ocsp data %d", errno);
		goto out_ocsp;
	    }

	    ret = hx509_ocsp_verify(r->context->hx509ctx,
				    kdc_time,
				    kdc_cert,
				    0,
				    ocsp.data.data, ocsp.data.length,
				    &ocsp.expire);
	    if (ret) {
		kdc_log(r->context, config, 0,
			"PKINIT failed to verify ocsp data %d", ret);
		krb5_data_free(&ocsp.data);
		ocsp.expire = 0;
	    } else if (ocsp.expire > 180) {
		ocsp.expire -= 180; /* refetch the ocsp before it expires */
		ocsp.next_update = ocsp.expire;
	    } else {
		ocsp.next_update = kdc_time;
	    }
	out_ocsp:
	    ret = 0;
	}

	if (ocsp.expire != 0 && ocsp.expire > kdc_time) {

	    ret = krb5_padata_add(r->context, md,
				  KRB5_PADATA_PA_PK_OCSP_RESPONSE,
				  ocsp.data.data, ocsp.data.length);
	    if (ret) {
		krb5_set_error_message(r->context, ret,
				       "Failed adding OCSP response %d", ret);
		goto out;
	    }
	}
    }

out:
    if (kdc_cert)
	hx509_cert_free(kdc_cert);

    if (ret == 0)
	ret = krb5_copy_keyblock_contents(r->context, &cp->reply_key, reply_key);
    return ret;
}

static int
match_rfc_san(krb5_context context,
	      krb5_kdc_configuration *config,
	      hx509_context hx509ctx,
	      hx509_cert client_cert,
	      krb5_const_principal match)
{
    hx509_octet_string_list list;
    int ret, found = 0;
    size_t i;

    memset(&list, 0 , sizeof(list));

    ret = hx509_cert_find_subjectAltName_otherName(hx509ctx,
						   client_cert,
						   &asn1_oid_id_pkinit_san,
						   &list);
    if (ret)
	goto out;

    for (i = 0; !found && i < list.len; i++) {
	krb5_principal_data principal;
	KRB5PrincipalName kn;
	size_t size;

	ret = decode_KRB5PrincipalName(list.val[i].data,
				       list.val[i].length,
				       &kn, &size);
	if (ret) {
	    const char *msg = krb5_get_error_message(context, ret);
	    kdc_log(context, config, 0,
		    "Decoding Kerberos principal name in certificate failed: %s", msg);
	    krb5_free_error_message(context, msg);
	    break;
	}
	if (size != list.val[i].length) {
	    kdc_log(context, config, 0,
		    "Decoded Kerberos principal name did not have expected length");
	    return KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
	}

	memset(&principal, 0, sizeof (principal));
	principal.name = kn.principalName;
	principal.realm = kn.realm;

	if (krb5_principal_compare(context, &principal, match) == TRUE)
	    found = 1;
	free_KRB5PrincipalName(&kn);
    }

out:
    hx509_free_octet_string_list(&list);
    if (ret)
	return ret;

    if (!found)
	return KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;

    return 0;
}

static int
match_ms_upn_san(krb5_context context,
		 krb5_kdc_configuration *config,
		 hx509_context hx509ctx,
		 hx509_cert client_cert,
		 HDB *clientdb,
		 hdb_entry *client)
{
    hx509_octet_string_list list;
    krb5_principal principal = NULL;
    int ret;
    MS_UPN_SAN upn;
    size_t size;

    memset(&list, 0 , sizeof(list));

    ret = hx509_cert_find_subjectAltName_otherName(hx509ctx,
						   client_cert,
						   &asn1_oid_id_pkinit_ms_san,
						   &list);
    if (ret)
	goto out;

    if (list.len != 1) {
	if (list.len)
	    kdc_log(context, config, 0,
		    "More than one PKINIT MS UPN SAN");
	else
	    kdc_log(context, config, 0,
		    "No PKINIT MS UPN SAN");
	ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
	goto out;
    }

    ret = decode_MS_UPN_SAN(list.val[0].data, list.val[0].length, &upn, &size);
    if (ret) {
	kdc_log(context, config, 0, "Decode of MS-UPN-SAN failed");
	goto out;
    }
    if (size != list.val[0].length) {
	free_MS_UPN_SAN(&upn);
	kdc_log(context, config, 0, "Trailing data in MS UPN SAN");
	ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
	goto out;
    }

    kdc_log(context, config, 0, "found MS UPN SAN: %s", upn);

    ret = krb5_parse_name(context, upn, &principal);
    free_MS_UPN_SAN(&upn);
    if (ret) {
	kdc_log(context, config, 0, "Failed to parse principal in MS UPN SAN");
	goto out;
    }

    if (clientdb->hdb_check_pkinit_ms_upn_match) {
	ret = clientdb->hdb_check_pkinit_ms_upn_match(context, clientdb, client, principal);
    } else {

	/*
	 * This is very wrong, but will do for a fallback
	 */
	strupr(principal->realm);

	if (krb5_principal_compare(context, principal, client->principal) == FALSE)
	    ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
    }

out:
    if (principal)
	krb5_free_principal(context, principal);
    hx509_free_octet_string_list(&list);

    return ret;
}

krb5_error_code
_kdc_pk_check_client(astgs_request_t r,
		     pk_client_params *cp,
		     char **subject_name)
{
    krb5_kdc_configuration *config = r->config;
    HDB *clientdb = r->clientdb;
    hdb_entry *client = r->client;
    const HDB_Ext_PKINIT_acl *acl;
    const HDB_Ext_PKINIT_cert *pc;
    krb5_error_code ret;
    hx509_name name;
    size_t i;

    if (cp->cert == NULL) {
	if (!_kdc_is_anonymous(r->context, client->principal)
	    && !config->historical_anon_realm)
	    return KRB5KDC_ERR_BADOPTION;

	*subject_name = strdup("<unauthenticated anonymous client>");
	if (*subject_name == NULL)
	    return ENOMEM;
	return 0;
    }

    cp->endtime = hx509_cert_get_notAfter(cp->cert);
    cp->max_life = 0;
    if (config->pkinit_max_life_from_cert_extension)
        cp->max_life =
            hx509_cert_get_pkinit_max_life(r->context->hx509ctx, cp->cert,
                                           config->pkinit_max_life_bound);
    if (cp->max_life == 0 && config->pkinit_max_life_from_cert > 0) {
        cp->max_life = cp->endtime - hx509_cert_get_notBefore(cp->cert);
        if (cp->max_life > config->pkinit_max_life_from_cert)
            cp->max_life = config->pkinit_max_life_from_cert;
    }

    ret = hx509_cert_get_base_subject(r->context->hx509ctx,
				      cp->cert,
				      &name);
    if (ret)
	return ret;

    ret = hx509_name_to_string(name, subject_name);
    hx509_name_free(&name);
    if (ret)
	return ret;

    kdc_log(r->context, config, 0,
	    "Trying to authorize PKINIT subject DN %s",
	    *subject_name);

    ret = hdb_entry_get_pkinit_cert(client, &pc);
    if (ret == 0 && pc) {
	hx509_cert cert;
	size_t j;

	for (j = 0; j < pc->len; j++) {
	    cert = hx509_cert_init_data(r->context->hx509ctx,
					pc->val[j].cert.data,
					pc->val[j].cert.length,
					NULL);
	    if (cert == NULL)
		continue;
	    ret = hx509_cert_cmp(cert, cp->cert);
	    hx509_cert_free(cert);
	    if (ret == 0) {
		kdc_log(r->context, config, 5,
			"Found matching PKINIT cert in hdb");
		return 0;
	    }
	}
    }


    if (config->pkinit_princ_in_cert) {
	ret = match_rfc_san(r->context, config,
			    r->context->hx509ctx,
			    cp->cert,
			    client->principal);
	if (ret == 0) {
	    kdc_log(r->context, config, 5,
		    "Found matching PKINIT SAN in certificate");
	    return 0;
	}
	ret = match_ms_upn_san(r->context, config,
			       r->context->hx509ctx,
			       cp->cert,
			       clientdb,
			       client);
	if (ret == 0) {
	    kdc_log(r->context, config, 5,
		    "Found matching MS UPN SAN in certificate");
	    return 0;
	}
    }

    ret = hdb_entry_get_pkinit_acl(client, &acl);
    if (ret == 0 && acl != NULL) {
	/*
	 * Cheat here and compare the generated name with the string
	 * and not the reverse.
	 */
	for (i = 0; i < acl->len; i++) {
	    if (strcmp(*subject_name, acl->val[0].subject) != 0)
		continue;

	    /* Don't support issuer and anchor checking right now */
	    if (acl->val[0].issuer)
		continue;
	    if (acl->val[0].anchor)
		continue;

	    kdc_log(r->context, config, 5,
		    "Found matching PKINIT database ACL");
	    return 0;
	}
    }

    for (i = 0; i < principal_mappings.len; i++) {
	krb5_boolean b;

	b = krb5_principal_compare(r->context,
				   client->principal,
				   principal_mappings.val[i].principal);
	if (b == FALSE)
	    continue;
	if (strcmp(principal_mappings.val[i].subject, *subject_name) != 0)
	    continue;
	kdc_log(r->context, config, 5,
		"Found matching PKINIT FILE ACL");
	return 0;
    }

    ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
    krb5_set_error_message(r->context, ret,
			  "PKINIT no matching principals for %s",
			  *subject_name);

    kdc_log(r->context, config, 5,
	    "PKINIT no matching principals for %s",
	    *subject_name);

    free(*subject_name);
    *subject_name = NULL;

    return ret;
}

krb5_error_code
_kdc_pk_validate_freshness_token(astgs_request_t r,
				 pk_client_params *cp)
{
    krb5_error_code ret = 0;
    uint8_t *token_data = NULL;
    size_t token_len;
    uint8_t *remaining_token_data = NULL;
    size_t remaining_len;
    EncryptedData enc_data;
    size_t size;
    const hdb_entry *krbtgt = NULL;
    krb5_kvno kvno;
    const Keys *keys = NULL;
    Key *key = NULL;
    krb5_crypto crypto;
    krb5_data ts_data;
    PA_ENC_TS_ENC ts_enc;
    long time_diff;

    if (cp->freshness_token == NULL) {
	if (r->config->require_pkinit_freshness) {
	    ret = KRB5KDC_ERR_PREAUTH_FAILED;
	    kdc_log(r->context, r->config, 0, "PKINIT request is missing required freshness token");
	}

	return ret;
    }

    token_data = cp->freshness_token->data;
    token_len = cp->freshness_token->length;

    /* Ensure that the token be not empty. */
    if (token_data == NULL) {
	kdc_log(r->context, r->config, 0, "Got empty freshness token");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* Ensure that the two leading bytes are zero. */
    if (token_len < 2 || token_data[0] || token_data[1]) {
	kdc_log(r->context, r->config, 0, "Freshness token contains invalid data");
	return KRB5KRB_AP_ERR_MODIFIED;
    }

    /* Decrypt the freshness token. */

    remaining_token_data = token_data + 2;
    remaining_len = token_len - 2;

    ret = decode_EncryptedData(remaining_token_data, remaining_len, &enc_data, &size);
    if (ret) {
	kdc_log(r->context, r->config, 0, "Failed to decode freshness token");
	return KRB5KRB_AP_ERR_MODIFIED;
    }
    if (size != remaining_len) {
	kdc_log(r->context, r->config, 0, "Trailing data in EncryptedData of freshness token");
	free_EncryptedData(&enc_data);
	return KRB5KRB_AP_ERR_MODIFIED;
    }

    krbtgt = (r->krbtgt != NULL) ? r->krbtgt : r->server;
    kvno = (enc_data.kvno != NULL) ? *enc_data.kvno : 0;

    /* We will only accept freshness tokens signed by our local krbtgt. */
    keys = hdb_kvno2keys(r->context, krbtgt, kvno);
    if (keys == NULL) {
	kdc_log(r->context, r->config, 0,
		"No key with kvno %"PRId32" to decrypt freshness token",
		kvno);
	free_EncryptedData(&enc_data);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    ret = hdb_enctype2key(r->context, r->client, keys,
			  enc_data.etype, &key);
    if (ret) {
	kdc_log(r->context, r->config, 0,
		"No key with kvno %"PRId32", enctype %d to decrypt freshness token",
		kvno, enc_data.etype);
	free_EncryptedData(&enc_data);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    ret = krb5_crypto_init(r->context, &key->key, 0, &crypto);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
	kdc_log(r->context, r->config, 0,
		"While attempting to decrypt freshness token, krb5_crypto_init failed: %s", msg);
	krb5_free_error_message(r->context, msg);

	free_EncryptedData(&enc_data);
	return ret;
    }

    ret = krb5_decrypt_EncryptedData(r->context,
				     crypto,
				     KRB5_KU_AS_FRESHNESS,
				     &enc_data,
				     &ts_data);
    krb5_crypto_destroy(r->context, crypto);
    free_EncryptedData(&enc_data);
    if (ret) {
	kdc_log(r->context, r->config, 0, "Failed to decrypt freshness token");

	free_EncryptedData(&enc_data);
	return KRB5KRB_AP_ERR_MODIFIED;
    }

    /* Decode the timestamp. */

    ret = decode_PA_ENC_TS_ENC(ts_data.data,
			       ts_data.length,
			       &ts_enc,
			       &size);
    if (ret) {
	kdc_log(r->context, r->config, 0, "Failed to decode PA-ENC-TS-ENC in freshness token");
	krb5_data_free(&ts_data);
	return KRB5KRB_AP_ERR_MODIFIED;
    }
    if (size != ts_data.length) {
	kdc_log(r->context, r->config, 0, "Trailing data in PA-ENC-TS-ENC of freshness token");
	free_PA_ENC_TS_ENC(&ts_enc);
	krb5_data_free(&ts_data);
	return KRB5KRB_AP_ERR_MODIFIED;
    }
    krb5_data_free(&ts_data);

    time_diff = labs(kdc_time - ts_enc.patimestamp);
    if (time_diff > r->context->max_skew) {
	char token_time[100];

	krb5_format_time(r->context, ts_enc.patimestamp,
			 token_time, sizeof(token_time), TRUE);

	kdc_log(r->context, r->config, 4, "Freshness token has too large time skew: "
		"time in token %s is out by %ld > %jd seconds — %s",
		token_time,
		time_diff,
		(intmax_t)(r->context->max_skew),
		r->cname);

	r->e_text = NULL;
	free_PA_ENC_TS_ENC(&ts_enc);
	return KRB5_KDC_ERR_PREAUTH_EXPIRED;
    }

    r->pkinit_freshness_used = TRUE;

    free_PA_ENC_TS_ENC(&ts_enc);
    return 0;
}

static krb5_error_code
add_principal_mapping(krb5_context context,
		      const char *principal_name,
		      const char * subject)
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
_kdc_add_initial_verified_cas(krb5_context context,
			      krb5_kdc_configuration *config,
			      pk_client_params *cp,
			      EncTicketPart *tkt)
{
    AD_INITIAL_VERIFIED_CAS cas;
    krb5_error_code ret;
    krb5_data data;
    size_t size = 0;

    memset(&cas, 0, sizeof(cas));

    /* XXX add CAs to cas here */

    ASN1_MALLOC_ENCODE(AD_INITIAL_VERIFIED_CAS, data.data, data.length,
		       &cas, &size, ret);
    if (ret)
	return ret;
    if (data.length != size)
	krb5_abortx(context, "internal asn.1 encoder error");

    ret = _kdc_tkt_add_if_relevant_ad(context, tkt,
				      KRB5_AUTHDATA_INITIAL_VERIFIED_CAS,
				      &data);
    krb5_data_free(&data);
    return ret;
}

/*
 *
 */

static void
load_mappings(krb5_context context, const char *fn)
{
    krb5_error_code ret;
    char buf[1024];
    unsigned long lineno = 0;
    FILE *f;

    f = fopen(fn, "r");
    if (f == NULL)
	return;

    while (fgets(buf, sizeof(buf), f) != NULL) {
	char *subject_name, *p;

	buf[strcspn(buf, "\n")] = '\0';
	lineno++;

	p = buf + strspn(buf, " \t");

	if (*p == '#' || *p == '\0')
	    continue;

	subject_name = strchr(p, ':');
	if (subject_name == NULL) {
	    krb5_warnx(context, "pkinit mapping file line %lu "
		       "missing \":\" :%s",
		       lineno, buf);
	    continue;
	}
	*subject_name++ = '\0';

	ret = add_principal_mapping(context, p, subject_name);
	if (ret) {
	    krb5_warn(context, ret, "failed to add line %lu \":\" :%s\n",
		      lineno, buf);
	    continue;
	}
    }

    fclose(f);
}

/*
 *
 */

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
krb5_kdc_pk_initialize(krb5_context context,
		       krb5_kdc_configuration *config,
		       const char *user_id,
		       const char *anchors,
		       char **pool,
		       char **revoke_list)
{
    const char *file;
    char *fn = NULL;
    krb5_error_code ret;

    file = krb5_config_get_string(context, NULL,
				  "libdefaults", "moduli", NULL);

    ret = _krb5_parse_moduli(context, file, &moduli);
    if (ret)
	krb5_err(context, 1, ret, "PKINIT: failed to load moduli file");

    principal_mappings.len = 0;
    principal_mappings.val = NULL;

    ret = _krb5_pk_load_id(context,
			   &kdc_identity,
			   user_id,
			   anchors,
			   pool,
			   revoke_list,
			   NULL,
			   NULL,
			   NULL);
    if (ret) {
	krb5_warn(context, ret, "PKINIT: failed to load ID");
	config->enable_pkinit = 0;
	return ret;
    }

    {
	hx509_query *q;
	hx509_cert cert;

	ret = hx509_query_alloc(context->hx509ctx, &q);
	if (ret) {
	    krb5_warnx(context, "PKINIT: out of memory");
	    return ENOMEM;
	}

	hx509_query_match_option(q, HX509_QUERY_OPTION_PRIVATE_KEY);
	if (config->pkinit_kdc_friendly_name)
	    hx509_query_match_friendly_name(q, config->pkinit_kdc_friendly_name);

	ret = hx509_certs_find(context->hx509ctx,
			       kdc_identity->certs,
			       q,
			       &cert);
	hx509_query_free(context->hx509ctx, q);
	if (ret == 0) {
	    if (hx509_cert_check_eku(context->hx509ctx, cert,
				     &asn1_oid_id_pkkdcekuoid, 0)) {
		hx509_name name;
		char *str;
		ret = hx509_cert_get_subject(cert, &name);
		if (ret == 0) {
		    hx509_name_to_string(name, &str);
		    krb5_warnx(context, "WARNING Found KDC certificate (%s) "
			       "is missing the PKINIT KDC EKU, this is bad for "
			       "interoperability.", str);
		    hx509_name_free(&name);
		    free(str);
		}
	    }
	    hx509_cert_free(cert);
	} else
	    krb5_warnx(context, "PKINIT: failed to find a signing "
		       "certificate with a public key");
    }

    if (krb5_config_get_bool_default(context,
				     NULL,
				     FALSE,
				     "kdc",
				     "pkinit_allow_proxy_certificate",
				     NULL))
	config->pkinit_allow_proxy_certs = 1;

    file = krb5_config_get_string(context,
				  NULL,
				  "kdc",
				  "pkinit_mappings_file",
				  NULL);
    if (file == NULL) {
	int aret;

	aret = asprintf(&fn, "%s/pki-mapping", hdb_db_dir(context));
	if (aret == -1) {
	    krb5_warnx(context, "PKINIT: out of memory");
	    return ENOMEM;
	}

	file = fn;
    }

    load_mappings(context, file);
    if (fn)
	free(fn);

    return 0;
}

#endif /* PKINIT */
