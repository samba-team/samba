/*
 * Copyright (c) 2016 Kungliga Tekniska Högskolan
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

#include <config.h>
#include <roken.h>

#ifdef PKINIT

/*
 * As with the other *-ec.c files in Heimdal, this is a bit of a hack.
 *
 * The idea is to use OpenSSL for EC because hcrypto doesn't have the
 * required functionality at this time.  To do this we segregate
 * EC-using code into separate source files and then we arrange for them
 * to get the OpenSSL headers and not the conflicting hcrypto ones.
 *
 * Because of auto-generated *-private.h headers, we end up needing to
 * make sure various types are defined before we include them, thus the
 * strange header include order here.
 */

#ifdef HAVE_HCRYPTO_W_OPENSSL
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/objects.h>
#ifdef HAVE_OPENSSL_30
#include <openssl/core_names.h>
#endif
#define HEIM_NO_CRYPTO_HDRS
#endif /* HAVE_HCRYPTO_W_OPENSSL */

#define NO_HCRYPTO_POLLUTION

#include "kdc_locl.h"
#include <hcrypto/des.h>
#include <heim_asn1.h>
#include <rfc2459_asn1.h>
#include <cms_asn1.h>
#include <pkinit_asn1.h>

#include <hx509.h>
#include "../lib/hx509/hx_locl.h"
#include <hx509-private.h>

void
_kdc_pk_free_client_ec_param(krb5_context context,
                             void *k0,
                             void *k1)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
    EVP_PKEY_free(k0);
    EVP_PKEY_free(k1);
#else
    EC_KEY_free(k0);
    EC_KEY_free(k1);
#endif
#endif
}

#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
static krb5_error_code
generate_ecdh_keyblock_ossl30(krb5_context context,
                              EVP_PKEY *ec_key_pub,   /* the client's public key */
                              EVP_PKEY **ec_key_priv, /* the KDC's ephemeral private */
                              unsigned char **dh_gen_key, /* shared secret */
                              size_t *dh_gen_keylen)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *ephemeral = NULL;
    krb5_error_code ret = 0;
    unsigned char *p = NULL;
    size_t size = 0;

    if (ec_key_pub == NULL)
        /* XXX This seems like an internal error that should be impossible */
        krb5_set_error_message(context, ret = KRB5KRB_ERR_GENERIC,
                               "Missing client ECDH key agreement public key");
    if (ret == 0 &&
        (ephemeral =
             EVP_EC_gen(OSSL_EC_curve_nid2name(NID_X9_62_prime256v1))) == NULL)
        krb5_set_error_message(context, ret = KRB5KRB_ERR_GENERIC,
                               "Could not generate an ECDH key agreement private key");
    if (ret == 0 &&
        (pctx = EVP_PKEY_CTX_new(ephemeral, NULL)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 && EVP_PKEY_derive_init(pctx) != 1)
        ret = krb5_enomem(context);
    if (ret == 0 &&
        EVP_PKEY_CTX_set_ecdh_kdf_type(pctx, EVP_PKEY_ECDH_KDF_NONE) != 1)
        krb5_set_error_message(context, ret = KRB5KRB_ERR_GENERIC,
                               "Could not generate an ECDH key agreement private key "
                               "(EVP_PKEY_CTX_set_dh_kdf_type)");
    if (ret == 0 &&
        EVP_PKEY_derive_set_peer_ex(pctx, ec_key_pub, 1) != 1)
        krb5_set_error_message(context, ret = KRB5KRB_ERR_GENERIC,
                               "Could not generate an ECDH key agreement private key "
                               "(EVP_PKEY_derive_set_peer_ex)");
    if (ret == 0 &&
        (EVP_PKEY_derive(pctx, NULL, &size) != 1 || size == 0))
        krb5_set_error_message(context, ret = KRB5KRB_ERR_GENERIC,
                               "Could not generate an ECDH key agreement private key "
                               "(EVP_PKEY_derive)");
    if (ret == 0 && (p = malloc(size)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 &&
        (EVP_PKEY_derive(pctx, p, &size) != 1 || size == 0))
        krb5_set_error_message(context, ret = KRB5KRB_ERR_GENERIC,
                               "Could not generate an ECDH key agreement private key "
                               "(EVP_PKEY_derive)");

    if (ret) {
        EVP_PKEY_free(ephemeral);
        ephemeral = NULL;
        free(p);
        p = NULL;
        size = 0;
    }

    *ec_key_priv = ephemeral;
    *dh_gen_keylen = size;
    *dh_gen_key = p;

    EVP_PKEY_CTX_free(pctx);
    return ret;
}
#else

/* The empty line above is intentional to work around an mkproto bug */
static krb5_error_code
generate_ecdh_keyblock_ossl11(krb5_context context,
                              EC_KEY *ec_key_pk,    /* the client's public key */
                              EC_KEY **ec_key_key,  /* the KDC's ephemeral private */
                              unsigned char **dh_gen_key, /* shared secret */
                              size_t *dh_gen_keylen)
{
    const EC_GROUP *group;
    EC_KEY *ephemeral;
    krb5_keyblock key;
    krb5_error_code ret;
    unsigned char *p;
    size_t size;
    int len;

    *dh_gen_key = NULL;
    *dh_gen_keylen = 0;
    *ec_key_key = NULL;

    memset(&key, 0, sizeof(key));

    if (ec_key_pk == NULL) {
        ret = KRB5KRB_ERR_GENERIC;
        krb5_set_error_message(context, ret, "public_key");
        return ret;
    }

    group = EC_KEY_get0_group(ec_key_pk);
    if (group == NULL) {
        ret = KRB5KRB_ERR_GENERIC;
        krb5_set_error_message(context, ret, "failed to get the group of "
                               "the client's public key");
        return ret;
    }

    ephemeral = EC_KEY_new();
    if (ephemeral == NULL)
        return krb5_enomem(context);

    EC_KEY_set_group(ephemeral, group);

    if (EC_KEY_generate_key(ephemeral) != 1) {
       EC_KEY_free(ephemeral);
        return krb5_enomem(context);
    }

    size = (EC_GROUP_get_degree(group) + 7) / 8;
    p = malloc(size);
    if (p == NULL) {
        EC_KEY_free(ephemeral);
        return krb5_enomem(context);
    }

    len = ECDH_compute_key(p, size,
                           EC_KEY_get0_public_key(ec_key_pk),
                           ephemeral, NULL);
    if (len <= 0) {
        free(p);
        EC_KEY_free(ephemeral);
        ret = KRB5KRB_ERR_GENERIC;
        krb5_set_error_message(context, ret, "Failed to compute ECDH "
                               "public shared secret");
        return ret;
    }

    *ec_key_key = ephemeral;
    *dh_gen_key = p;
    *dh_gen_keylen = len;

    return 0;
}
#endif
#endif /* HAVE_HCRYPTO_W_OPENSSL */

krb5_error_code
_kdc_generate_ecdh_keyblock(krb5_context context,
                            void *ec_key_pk,    /* the client's public key */
                            void **ec_key_key,  /* the KDC's ephemeral private */
                            unsigned char **dh_gen_key, /* shared secret */
                            size_t *dh_gen_keylen)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
    return generate_ecdh_keyblock_ossl30(context, ec_key_pk,
                                         (EVP_PKEY **)ec_key_key,
                                         dh_gen_key, dh_gen_keylen);
#else
    return generate_ecdh_keyblock_ossl11(context, ec_key_pk,
                                         (EC_KEY **)ec_key_key,
                                         dh_gen_key, dh_gen_keylen);
#endif
#else
    return ENOTSUP;
#endif /* HAVE_HCRYPTO_W_OPENSSL */
}

#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
static krb5_error_code
get_ecdh_param_ossl30(krb5_context context,
                      krb5_kdc_configuration *config,
                      SubjectPublicKeyInfo *dh_key_info,
                      EVP_PKEY **out)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *template = NULL;
    EVP_PKEY *public = NULL;
    OSSL_PARAM params[2];
    krb5_error_code ret = 0;
    ECParameters ecp;
    const unsigned char *p;
    const char *curve_sn = NULL;
    size_t len;
    char *curve_sn_dup = NULL;
    int groupnid = NID_undef;

    /* XXX Algorithm agility; XXX KRB5_BADMSGTYPE?? */

    /*
     * In order for d2i_PublicKey() to work we need to create a template key
     * that has the curve parameters for the subjectPublicKey.
     *
     * Or maybe we could learn to use the OSSL_DECODER(3) API.  But this works,
     * at least until OpenSSL deprecates d2i_PublicKey() and forces us to use
     * OSSL_DECODER(3).
     */

    memset(&ecp, 0, sizeof(ecp));

    if (dh_key_info->algorithm.parameters == NULL)
	krb5_set_error_message(context, ret = KRB5_BADMSGTYPE,
			       "PKINIT missing algorithm parameter "
			       "in clientPublicValue");
    if (ret == 0)
        ret = decode_ECParameters(dh_key_info->algorithm.parameters->data,
                                  dh_key_info->algorithm.parameters->length,
                                  &ecp, &len);
    if (ret == 0 && ecp.element != choice_ECParameters_namedCurve)
        krb5_set_error_message(context, ret = KRB5_BADMSGTYPE,
                               "PKINIT client used an unnamed curve");
    if (ret == 0 &&
        (groupnid = _hx509_ossl_oid2nid(&ecp.u.namedCurve)) == NID_undef)
        krb5_set_error_message(context, ret = KRB5_BADMSGTYPE,
                               "PKINIT client used an unsupported curve");
    if (ret == 0 && (curve_sn = OBJ_nid2sn(groupnid)) == NULL)
        krb5_set_error_message(context, ret = KRB5_BADMSGTYPE,
                               "Could not resolve curve NID %d to its short name",
                               groupnid);
    if (ret == 0 && (curve_sn_dup = strdup(curve_sn)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0) {
        if (der_heim_oid_cmp(&ecp.u.namedCurve, &asn1_oid_id_ec_group_secp256r1) != 0)
            krb5_set_error_message(context, ret = KRB5_BADMSGTYPE,
                                   "PKINIT client used an unsupported curve");
    }
    if (ret == 0) {
        /*
         * Apparently there's no error checking to be done here?  Why does
         * OSSL_PARAM_construct_utf8_string() want a non-const for the value?
         * Is that a bug in OpenSSL?
         */
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                     curve_sn_dup, 0);
        params[1] = OSSL_PARAM_construct_end();

        if ((pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL)
            ret = krb5_enomem(context);
    }
    if (ret == 0 && EVP_PKEY_fromdata_init(pctx) != 1)
        ret = krb5_enomem(context);
    if (ret == 0 &&
        EVP_PKEY_fromdata(pctx, &template, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                          params) != 1)
        krb5_set_error_message(context, ret = KRB5_BADMSGTYPE,
                               "Could not set up to parse key for curve %s",
                               curve_sn);

    p = dh_key_info->subjectPublicKey.data;
    len = dh_key_info->subjectPublicKey.length / 8;
    if (ret == 0 &&
        (public = d2i_PublicKey(EVP_PKEY_EC, &template, &p, len)) == NULL)
        krb5_set_error_message(context, ret = KRB5_BADMSGTYPE,
                               "Could not decode PKINIT client ECDH key");

    if (ret) {
        EVP_PKEY_free(public);
        public = NULL;
    }

    *out = public;

    /* FYI the EVP_PKEY_CTX takes ownership of the `template' key */
    EVP_PKEY_CTX_free(pctx);
    free_ECParameters(&ecp);
    free(curve_sn_dup);
    return ret;
}
#else

static krb5_error_code
get_ecdh_param_ossl11(krb5_context context,
                      krb5_kdc_configuration *config,
                      SubjectPublicKeyInfo *dh_key_info,
                      EC_KEY **out)
{
    ECParameters ecp;
    EC_KEY *public = NULL;
    krb5_error_code ret;
    const unsigned char *p;
    size_t len;
    int nid;

    if (dh_key_info->algorithm.parameters == NULL) {
       krb5_set_error_message(context, KRB5_BADMSGTYPE,
                              "PKINIT missing algorithm parameter "
                              "in clientPublicValue");
       return KRB5_BADMSGTYPE;
    }
    /* XXX Algorithm agility; XXX KRB5_BADMSGTYPE?? */

    memset(&ecp, 0, sizeof(ecp));

    ret = decode_ECParameters(dh_key_info->algorithm.parameters->data,
                             dh_key_info->algorithm.parameters->length, &ecp, &len);
    if (ret)
       goto out;

    if (ecp.element != choice_ECParameters_namedCurve) {
       ret = KRB5_BADMSGTYPE;
       goto out;
    }

    if (der_heim_oid_cmp(&ecp.u.namedCurve, &asn1_oid_id_ec_group_secp256r1) == 0)
       nid = NID_X9_62_prime256v1;
    else {
       ret = KRB5_BADMSGTYPE;
       goto out;
   }

    /* XXX verify group is ok */

    public = EC_KEY_new_by_curve_name(nid);

    p = dh_key_info->subjectPublicKey.data;
    len = dh_key_info->subjectPublicKey.length / 8;
    if (o2i_ECPublicKey(&public, &p, len) == NULL) {
       ret = KRB5_BADMSGTYPE;
       krb5_set_error_message(context, ret,
                              "PKINIT failed to decode ECDH key");
       goto out;
    }
    *out = public;
    public = NULL;

 out:
    if (public)
       EC_KEY_free(public);
    free_ECParameters(&ecp);
    return ret;
}
#endif
#endif /* HAVE_HCRYPTO_W_OPENSSL */

krb5_error_code
_kdc_get_ecdh_param(krb5_context context,
                    krb5_kdc_configuration *config,
                    SubjectPublicKeyInfo *dh_key_info,
                    void **out)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
    return get_ecdh_param_ossl30(context, config, dh_key_info, (EVP_PKEY **)out);
#else
    return get_ecdh_param_ossl11(context, config, dh_key_info, (EC_KEY **)out);
#endif
#else
    return ENOTSUP;
#endif /* HAVE_HCRYPTO_W_OPENSSL */
}


/*
 *
 */

#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
static krb5_error_code
serialize_ecdh_key_ossl30(krb5_context context,
                          EVP_PKEY *key,
                          unsigned char **out,
                          size_t *out_len)
{
    unsigned char *p;
    int len;

    *out = NULL;
    *out_len = 0;

    len = i2d_PublicKey(key, NULL);
    if (len <= 0) {
        krb5_set_error_message(context, EOVERFLOW,
                               "PKINIT failed to encode ECDH key");
        return EOVERFLOW;
    }

    *out = malloc(len);
    if (*out == NULL)
        return krb5_enomem(context);

    p = *out;
    len = i2d_PublicKey(key, &p);
    if (len <= 0) {
        free(*out);
        *out = NULL;
	krb5_set_error_message(context, EINVAL /* XXX Better error please */,
			       "PKINIT failed to encode ECDH key");
        return EINVAL;
    }

    *out_len = len * 8;
    return 0;
}
#else

static krb5_error_code
serialize_ecdh_key_ossl11(krb5_context context,
                          EC_KEY *key,
                          unsigned char **out,
                          size_t *out_len)
{
    unsigned char *p;
    int len;

    *out = NULL;
    *out_len = 0;

    len = i2o_ECPublicKey(key, NULL);
    if (len <= 0) {
        krb5_set_error_message(context, EOVERFLOW,
                               "PKINIT failed to encode ECDH key");
        return EOVERFLOW;
    }

    *out = malloc(len);
    if (*out == NULL)
        return krb5_enomem(context);

    p = *out;
    len = i2o_ECPublicKey(key, &p);
    if (len <= 0) {
        free(*out);
        *out = NULL;
	krb5_set_error_message(context, EINVAL /* XXX Better error please */,
			       "PKINIT failed to encode ECDH key");
        return EINVAL;
    }

    *out_len = len * 8;
    return 0;
}
#endif
#endif

krb5_error_code
_kdc_serialize_ecdh_key(krb5_context context,
                        void *key,
                        unsigned char **out,
                        size_t *out_len)
{
#ifdef HAVE_HCRYPTO_W_OPENSSL
#ifdef HAVE_OPENSSL_30
    return serialize_ecdh_key_ossl30(context, key, out, out_len);
#else
    return serialize_ecdh_key_ossl11(context, key, out, out_len);
#endif
#else
    return ENOTSUP;
#endif
}

#endif
