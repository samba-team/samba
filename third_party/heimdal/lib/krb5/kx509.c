/*
 * Copyright (c) 2019 Kungliga Tekniska Högskolan
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
#include <kx509_asn1.h>
#include <kx509_err.h>
#include "../hx509/hx_locl.h" /* XXX find a better way */
#include "hx509-private.h"

/*
 * This file implements a client for the kx509 protocol -- a Kerberized online
 * CA that can issue a Certificate to a client that authenticates using
 * Kerberos.
 *
 * The kx509 protocol is the inverse of PKINIT.  Whereas PKINIT allows users
 * with PKIX credentials to acquire Kerberos credentials, the kx509 protocol
 * allows users with Kerberos credentials to acquire PKIX credentials.
 *
 * I.e., kx509 is a bridge, just like PKINIT.
 *
 * The kx509 protocol is very simple, and very limited.
 *
 * A request consists of a DER-encoded Kx509Request message prefixed with four
 * bytes identifying the protocol (see `version_2_0' below).
 *
 * A Kx509Request message contains an AP-REQ, a public key, and an HMAC of the
 * public key made with the session key of the AP-REQ's ticket.
 *
 * The service principal can be either kca_service/hostname.fqdn or
 * krbtgt/REALM (a Heimdal innovation).
 *
 * If a request is missing a public key, then the request is a probe intended
 * to discover whether the service is enabled, thus helping the client avoid
 * a possibly-slow private key generation operation.
 *
 * The response is a DER-encoded Kx509Response also prefixed with
 * `version_2_0', and contains: an optional error code and error text, an
 * optional certificate (for the success case), and an optional HMAC of those
 * fields that is present when the service was able to verify the AP-REQ.
 *
 * Limitations:
 *
 *  - no proof of possession for the public key
 *  - only RSA keys are supported
 *  - no way to express options (e.g., what KUs, EKUs, or SANs are desired)
 *  - no sub-session key usage
 *  - no reflection protection other than the HMAC's forgery protection and the
 *    fact that the client could tell that a reflected attack isn't success
 *
 * Future directions:
 *
 *  - Since the public key field of the request is an OCTET STRING, we could
 *    send a CSR, or even an expired certificate (possibly self-signed,
 *    possibly one issued earlier) that can serve as a template.
 *
 *    This solves the first three limitations, as it allows the client to
 *    demonstrate proof of possession, allows arbitrary public key types, and
 *    allows the client to express desires about the to-be-issued certificate.
 *
 *  - Use the AP-REQ's Authenticator's sub-session key for the HMAC, and derive
 *    per-direction sub-sub-keys.
 *
 *  - We might design a new protocol that better fits the RFC4120 KDC message
 *    framework.
 */

static const unsigned char version_2_0[4] = {0 , 0, 2, 0};

struct krb5_kx509_req_ctx_data {
    krb5_auth_context   ac;
    krb5_data           given_csr;
    hx509_request       csr;
    Kx509CSRPlus        csr_plus;
    char                *realm;     /* Realm to which to send request */
    krb5_keyblock       *hmac_key;  /* For HMAC validation */
    hx509_private_key   *keys;
    hx509_private_key   priv_key;
    unsigned int        expect_chain;
};

/**
 * Create a kx509 request context.
 *
 * @param context The Kerberos library context
 * @param out Where to place the kx509 request context
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_init(krb5_context context, krb5_kx509_req_ctx *out)
{
    krb5_kx509_req_ctx ctx;
    krb5_error_code ret;
    hx509_name name = NULL;

    ALLOC(ctx, 1);
    if (ctx == NULL)
        return krb5_enomem(context);
    ctx->given_csr.data = NULL;
    ctx->priv_key = NULL;
    ctx->hmac_key = NULL;
    ctx->realm = NULL;
    ctx->keys = NULL;
    ctx->csr = NULL;
    ret = hx509_request_init(context->hx509ctx, &ctx->csr);
    if (ret == 0)
        ret = hx509_parse_name(context->hx509ctx, "", &name);
    if (ret == 0)
        ret = hx509_request_set_name(context->hx509ctx, ctx->csr, name);
    if (ret == 0)
        ret = krb5_auth_con_init(context, &ctx->ac);
    if (name)
        hx509_name_free(&name);
    if (ret == 0)
        *out = ctx;
    else
        krb5_kx509_ctx_free(context, &ctx);
    return ret;
}

/**
 * Free a kx509 request context.
 *
 * @param context The Kerberos library context
 * @param ctxp Pointer to krb5 request context to free
 *
 * @return A krb5 error code.
 */
void
krb5_kx509_ctx_free(krb5_context context, krb5_kx509_req_ctx *ctxp)
{
    krb5_kx509_req_ctx ctx = *ctxp;

    *ctxp = NULL;
    if (ctx == NULL)
        return;
    krb5_free_keyblock(context, ctx->hmac_key);
    krb5_auth_con_free(context, ctx->ac);
    free_Kx509CSRPlus(&ctx->csr_plus);
    free(ctx->realm);
    hx509_request_free(&ctx->csr);
    krb5_data_free(&ctx->given_csr);
    hx509_private_key_free(&ctx->priv_key);
    _hx509_certs_keys_free(context->hx509ctx, ctx->keys);
    free(ctx);
}

/**
 * Set a realm to send kx509 request to, if different from the client's.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param realm Realm name
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_set_realm(krb5_context context,
                         krb5_kx509_req_ctx kx509_ctx,
                         const char *realm)
{
    return ((kx509_ctx->realm = strdup(realm)) == NULL) ?
        krb5_enomem(context) : 0;
}

/**
 * Sets a CSR for a kx509 request.
 *
 * Normally kx509 will generate a CSR (and even a private key for it)
 * automatically.  If a CSR is given then kx509 will use it instead of
 * generating one.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param csr_der A DER-encoded PKCS#10 CSR
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_set_csr_der(krb5_context context,
                           krb5_kx509_req_ctx ctx,
                           krb5_data *csr_der)
{
    krb5_data_free(&ctx->given_csr);
    return krb5_data_copy(&ctx->given_csr, csr_der->data, csr_der->length);
}

/**
 * Adds an EKU as an additional desired Certificate Extension or in the CSR if
 * the caller does not set a CSR.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param oids A string representation of an OID
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_add_eku(krb5_context context,
                       krb5_kx509_req_ctx kx509_ctx,
                       const char *oids)
{
    krb5_error_code ret;
    heim_oid oid;

    ret = der_parse_heim_oid(oids, NULL, &oid);
    if (ret == 0)
        hx509_request_add_eku(context->hx509ctx, kx509_ctx->csr, &oid);
    der_free_oid(&oid);
    return ret;
}

/**
 * Adds a dNSName SAN (domainname, hostname) as an additional desired
 * Certificate Extension or in the CSR if the caller does not set a CSR.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param dname A string containing a DNS domainname
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_add_san_dns_name(krb5_context context,
                                krb5_kx509_req_ctx kx509_ctx,
                                const char *dname)
{
    return hx509_request_add_dns_name(context->hx509ctx, kx509_ctx->csr,
                                      dname);
}

/**
 * Adds an xmppAddr SAN (jabber address) as an additional desired Certificate
 * Extension or in the CSR if the caller does not set a CSR.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param jid A string containing a Jabber address
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_add_san_xmpp(krb5_context context,
                            krb5_kx509_req_ctx kx509_ctx,
                            const char *jid)
{
    return hx509_request_add_xmpp_name(context->hx509ctx, kx509_ctx->csr, jid);
}

/**
 * Adds an rfc822Name SAN (e-mail address) as an additional desired Certificate
 * Extension or in the CSR if the caller does not set a CSR.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param email A string containing an e-mail address
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_add_san_rfc822Name(krb5_context context,
                                  krb5_kx509_req_ctx kx509_ctx,
                                  const char *email)
{
    return hx509_request_add_email(context->hx509ctx, kx509_ctx->csr, email);
}

/**
 * Adds an pkinit SAN (Kerberos principal name) as an additional desired
 * Certificate Extension or in the CSR if the caller does not set a CSR.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param pname A string containing a representation of a Kerberos principal
 *              name
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_add_san_pkinit(krb5_context context,
                              krb5_kx509_req_ctx kx509_ctx,
                              const char *pname)
{
    return hx509_request_add_pkinit(context->hx509ctx, kx509_ctx->csr, pname);
}

/**
 * Adds a Microsoft-style UPN (user principal name) as an additional desired
 * Certificate Extension or in the CSR if the caller does not set a CSR.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param upn A string containing a representation of a UPN
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_add_san_ms_upn(krb5_context context,
                              krb5_kx509_req_ctx kx509_ctx,
                              const char *upn)
{
    return hx509_request_add_ms_upn_name(context->hx509ctx, kx509_ctx->csr,
                                         upn);
}

/**
 * Adds an registeredID SAN (OID) as an additional desired Certificate
 * Extension or in the CSR if the caller does not set a CSR.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param oids A string representation of an OID
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_add_san_registeredID(krb5_context context,
                                    krb5_kx509_req_ctx kx509_ctx,
                                    const char *oids)
{
    krb5_error_code ret;
    heim_oid oid;

    ret = der_parse_heim_oid(oids, NULL, &oid);
    if (ret == 0)
        hx509_request_add_registered(context->hx509ctx, kx509_ctx->csr, &oid);
    der_free_oid(&oid);
    return ret;
}

static krb5_error_code
load_priv_key(krb5_context context,
              krb5_kx509_req_ctx kx509_ctx,
              const char *fn)
{
    hx509_private_key *keys = NULL;
    hx509_certs certs = NULL;
    krb5_error_code ret;

    ret = hx509_certs_init(context->hx509ctx, fn, 0, NULL, &certs);
    if (ret == ENOENT)
        return 0;
    if (ret == 0)
        ret = _hx509_certs_keys_get(context->hx509ctx, certs, &keys);
    if (ret == 0 && keys[0] == NULL)
        ret = ENOENT;
    if (ret == 0)
        kx509_ctx->priv_key = _hx509_private_key_ref(keys[0]);
    if (ret) {
	char *emsg = hx509_get_error_string(context->hx509ctx, ret);

        krb5_set_error_message(context, ret, "Could not load private key "
                               "from %s for kx509: %s", fn, emsg);
	hx509_free_error_string(emsg);
    }
    hx509_certs_free(&certs);
    return ret;
}

/**
 * Set a private key.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param store The name of a PKIX credential store
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_set_key(krb5_context context,
                       krb5_kx509_req_ctx kx509_ctx,
                       const char *store)
{
    SubjectPublicKeyInfo key;
    krb5_error_code ret;

    memset(&key, 0, sizeof(key));
    hx509_private_key_free(&kx509_ctx->priv_key);
    _hx509_certs_keys_free(context->hx509ctx, kx509_ctx->keys);
    kx509_ctx->keys = NULL;
    ret = load_priv_key(context, kx509_ctx, store);
    if (ret == 0)
        ret = hx509_private_key2SPKI(context->hx509ctx, kx509_ctx->priv_key,
                                     &key);
    if (ret == 0)
        ret = hx509_request_set_SubjectPublicKeyInfo(context->hx509ctx,
                                                     kx509_ctx->csr, &key);
    free_SubjectPublicKeyInfo(&key);
    return ret;
}

static krb5_error_code
gen_priv_key(krb5_context context,
             const char *gen_type,
             unsigned long gen_bits,
             hx509_private_key *key)
{
    struct hx509_generate_private_context *key_gen_ctx = NULL;
    krb5_error_code ret;

    _krb5_debug(context, 1, "kx509: gen priv key");
    if (strcmp(gen_type, "rsa") != 0) {
        krb5_set_error_message(context, ENOTSUP, "Key type %s is not "
                               "supported for kx509; only \"rsa\" is "
                               "supported for kx509 at this time",
                               gen_type);
        return ENOTSUP;
    }

    ret = _hx509_generate_private_key_init(context->hx509ctx,
                                           ASN1_OID_ID_PKCS1_RSAENCRYPTION,
                                           &key_gen_ctx);
    if (ret == 0)
        ret = _hx509_generate_private_key_bits(context->hx509ctx, key_gen_ctx, gen_bits);

    if (ret == 0)
        ret = _hx509_generate_private_key(context->hx509ctx, key_gen_ctx, key);
    _hx509_generate_private_key_free(&key_gen_ctx);
    if (ret) {
	char *emsg = hx509_get_error_string(context->hx509ctx, ret);

        krb5_set_error_message(context, ret,
                               "Could not generate a private key: %s", emsg);
	hx509_free_error_string(emsg);
    }
    return ret;
}

/**
 * Generate a private key.
 *
 * @param context The Kerberos library context
 * @param ctx The kx509 request context
 * @param gen_type The type of key (default: rsa)
 * @param gen_bits The size of the key (for non-ECC, really, for RSA)
 *
 * @return A krb5 error code.
 */
krb5_error_code
krb5_kx509_ctx_gen_key(krb5_context context,
                       krb5_kx509_req_ctx kx509_ctx,
                       const char *gen_type,
                       int gen_bits)
{
    SubjectPublicKeyInfo key;
    krb5_error_code ret;

    memset(&key, 0, sizeof(key));

    if (gen_type == NULL) {
        gen_type = krb5_config_get_string_default(context, NULL, "rsa",
                                                  "libdefaults",
                                                  "kx509_gen_key_type", NULL);
    }
    if (gen_bits == 0) {
        /*
         * The key size is really only for non-ECC, of which we'll only support
         * RSA.  For ECC key sizes will either be implied by the `key_type' or
         * will have to be a magic value that allows us to pick from some small
         * set of curves (e.g., 255 == Curve25519).
         */
        gen_bits = krb5_config_get_int_default(context, NULL, 2048,
                                               "libdefaults",
                                               "kx509_gen_rsa_key_size", NULL);
    }
    hx509_private_key_free(&kx509_ctx->priv_key);
    _hx509_certs_keys_free(context->hx509ctx, kx509_ctx->keys);
    kx509_ctx->keys = NULL;

    ret = gen_priv_key(context, gen_type, gen_bits, &kx509_ctx->priv_key);
    if (ret == 0)
        ret = hx509_private_key2SPKI(context->hx509ctx, kx509_ctx->priv_key,
                                     &key);
    if (ret == 0)
        ret = hx509_request_set_SubjectPublicKeyInfo(context->hx509ctx,
                                                     kx509_ctx->csr, &key);
    free_SubjectPublicKeyInfo(&key);
    return ret;
}

/* Set a cc config entry indicating that the kx509 service is not available */
static void
store_kx509_disabled(krb5_context context, const char *realm, krb5_ccache cc)
{
    krb5_data data;

    if (!cc)
        return;

    data.data = (void *)(uintptr_t)realm;
    data.length = strlen(realm);
    krb5_cc_set_config(context, cc, NULL, "kx509_service_realm", &data);
    data.data = "disabled";
    data.length = strlen(data.data);
    krb5_cc_set_config(context, cc, NULL, "kx509_service_status", &data);
}

static int KRB5_CALLCONV
certs_export_func(hx509_context context, void *d, hx509_cert c)
{
    heim_octet_string os;
    Certificates *cs = d;
    Certificate c2;
    int ret;

    ret = hx509_cert_binary(context, c, &os);
    if (ret)
        return ret;
    ret = decode_Certificate(os.data, os.length, &c2, NULL);
    der_free_octet_string(&os);
    if (ret)
        return ret;
    ret = add_Certificates(cs, &c2);
    free_Certificate(&c2);
    return ret;
}

static krb5_error_code
certs_export(hx509_context context, hx509_certs certs, heim_octet_string *out)
{
    Certificates cs;
    size_t len;
    int ret;

    cs.len = 0;
    cs.val = 0;
    ret = hx509_certs_iter_f(context, certs, certs_export_func, &cs);
    if (ret == 0)
        ASN1_MALLOC_ENCODE(Certificates, out->data, out->length, &cs, &len, ret);
    free_Certificates(&cs);
    return ret;
}

/* Store the private key and certificate where requested */
static krb5_error_code
store(krb5_context context,
      const char *hx509_store,
      const char *realm,
      krb5_ccache cc,
      hx509_private_key key,
      hx509_cert cert,
      hx509_certs chain)
{
    heim_octet_string hdata;
    krb5_error_code ret = 0;
    krb5_data data;

    krb5_clear_error_message(context);

    if (cc) {
        /* Record the realm we used */
        data.data = (void *)(uintptr_t)realm;
        data.length = strlen(realm);
        krb5_cc_set_config(context, cc, NULL, "kx509_service_realm", &data);

        /* Serialize and store the certificate in the ccache */
        ret = hx509_cert_binary(context->hx509ctx, cert, &hdata);
        if (ret == 0)
            ret = krb5_cc_set_config(context, cc, NULL, "kx509cert", &hdata);
        der_free_octet_string(&hdata);

        if (ret == 0 && key) {
            /*
             * Serialized and store the key in the ccache.  Use PKCS#8 so that we
             * store the algorithm OID too, which is needed in order to be able to
             * read the private key back.
             */
            if (ret == 0)
                ret = _hx509_private_key_export(context->hx509ctx, key,
                                                HX509_KEY_FORMAT_PKCS8, &hdata);
            if (ret == 0)
                ret = krb5_cc_set_config(context, cc, NULL, "kx509key", &hdata);
            der_free_octet_string(&hdata);
            if (ret)
                krb5_set_error_message(context, ret, "Could not store kx509 "
                                       "private key and certificate in ccache %s",
                                       krb5_cc_get_name(context, cc));
        }

        if (ret == 0 && chain) {
            ret = certs_export(context->hx509ctx, chain, &hdata);
            if (ret == 0)
                ret = krb5_cc_set_config(context, cc, NULL, "kx509cert-chain",
                                         &hdata);
            der_free_octet_string(&hdata);
        }
    }

    /* Store the private key and cert in an hx509 store */
    if (hx509_store != NULL) {
        hx509_certs certs;

        if (key)
            _hx509_cert_assign_key(cert, key); /* store both in the same store */

        ret = hx509_certs_init(context->hx509ctx, hx509_store,
                               HX509_CERTS_CREATE, NULL, &certs);
        if (ret == 0)
            ret = hx509_certs_add(context->hx509ctx, certs, cert);
        if (ret == 0 && chain != NULL)
            ret = hx509_certs_merge(context->hx509ctx, certs, chain);
        if (ret == 0)
            ret = hx509_certs_store(context->hx509ctx, certs, 0, NULL);
        hx509_certs_free(&certs);
        if (ret)
            krb5_prepend_error_message(context, ret, "Could not store kx509 "
                                       "private key and certificate in key "
                                       "store %s", hx509_store);
    }

    /* Store the name of the hx509 store in the ccache too */
    if (cc && hx509_store) {
        data.data = (void *)(uintptr_t)hx509_store;
        data.length = strlen(hx509_store);
        (void) krb5_cc_set_config(context, cc, NULL, "kx509store", &data);
    }
    return ret;
}

/* Make a Kx509CSRPlus or a raw SPKI */
static krb5_error_code
mk_kx509_req_body(krb5_context context,
                  krb5_kx509_req_ctx kx509_ctx,
                  krb5_data *out)
{
    krb5_error_code ret;
    size_t len;

    if (krb5_config_get_bool_default(context, NULL, FALSE,
                                     "realms", kx509_ctx->realm,
                                     "kx509_req_use_raw_spki", NULL)) {
        SubjectPublicKeyInfo spki;

        /* Interop with old kx509 servers, send a raw SPKI, not a CSR */
        out->data = NULL;
        out->length = 0;
        memset(&spki, 0, sizeof(spki));
        ret = hx509_private_key2SPKI(context->hx509ctx,
                                     kx509_ctx->priv_key, &spki);
        if (ret == 0) {
            out->length = spki.subjectPublicKey.length >> 3;
            out->data = spki.subjectPublicKey.data;
        }
        kx509_ctx->expect_chain = 0;
        return ret;
    }

    /*
     * New kx509 servers use a CSR for proof of possession, and send back a
     * chain of certificates, with the issued certificate first.
     */
    kx509_ctx->expect_chain = 1;

    if (kx509_ctx->given_csr.length) {
        krb5_data exts_der;

        exts_der.data = NULL;
        exts_der.length = 0;

        /* Use the given CSR */
        ret = der_copy_octet_string(&kx509_ctx->given_csr,
                                    &kx509_ctx->csr_plus.csr);

        /*
         * Extract the desired Certificate Extensions from our internal
         * as-yet-unsigned CSR, then decode them into place in the
         * Kx509CSRPlus.
         */
        if (ret == 0)
            ret = hx509_request_get_exts(context->hx509ctx,
                                         kx509_ctx->csr,
                                         &exts_der);
        if (ret == 0 && exts_der.data && exts_der.length &&
            (kx509_ctx->csr_plus.exts =
             calloc(1, sizeof (kx509_ctx->csr_plus.exts[0]))) == NULL)
            ret = krb5_enomem(context);
        if (ret == 0 && exts_der.data && exts_der.length)
            ret = decode_Extensions(exts_der.data, exts_der.length,
                                    kx509_ctx->csr_plus.exts, NULL);
        krb5_data_free(&exts_der);
    } else {
        /*
         * Sign and use our internal CSR, which will carry all our desired
         * Certificate Extensions as an extReq CSR Attribute.
         */
        ret = hx509_request_to_pkcs10(context->hx509ctx,
                                      kx509_ctx->csr,
                                      kx509_ctx->priv_key,
                                      &kx509_ctx->csr_plus.csr);
    }
    if (ret == 0)
        ASN1_MALLOC_ENCODE(Kx509CSRPlus, out->data, out->length,
                           &kx509_ctx->csr_plus, &len, ret);
    return ret;
}

static krb5_error_code
get_start_realm(krb5_context context,
                krb5_ccache cc,
                krb5_const_principal princ,
                char **out)
{
    krb5_error_code ret;
    krb5_data d;

    ret = krb5_cc_get_config(context, cc, NULL, "start_realm", &d);
    if (ret == 0) {
        *out = strndup(d.data, d.length);
        krb5_data_free(&d);
    } else if (princ) {
        *out = strdup(krb5_principal_get_realm(context, princ));
    } else {
        krb5_principal ccprinc = NULL;

        ret = krb5_cc_get_principal(context, cc, &ccprinc);
        if (ret)
            return ret;
        *out = strdup(krb5_principal_get_realm(context, ccprinc));
        krb5_free_principal(context, ccprinc);
    }
    return (*out) ? 0 : krb5_enomem(context);
}

/*
 * Make a request, which is a DER-encoded Kx509Request with version_2_0
 * prefixed to it.
 *
 * If no private key is given, then a probe request will be made.
 */
static krb5_error_code
mk_kx509_req(krb5_context context,
             krb5_kx509_req_ctx kx509_ctx,
             krb5_ccache incc,
             hx509_private_key private_key,
             krb5_data *req)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    SubjectPublicKeyInfo spki;
    struct Kx509Request kx509_req;
    krb5_data pre_req;
    krb5_error_code ret = 0;
    krb5_creds this_cred;
    krb5_creds *cred = NULL;
    HMAC_CTX ctx;
    const char *hostname;
    char *start_realm = NULL;
    size_t len = 0;

    krb5_data_zero(&pre_req);
    memset(&spki, 0, sizeof(spki));
    memset(&this_cred, 0, sizeof(this_cred));
    memset(&kx509_req, 0, sizeof(kx509_req));
    kx509_req.pk_hash.data = digest;
    kx509_req.pk_hash.length = SHA_DIGEST_LENGTH;

    if (private_key || kx509_ctx->given_csr.data) {
        /* Encode the CSR or public key for use in the request */
        ret = mk_kx509_req_body(context, kx509_ctx, &kx509_req.pk_key);
    } else {
        /* Probe */
        kx509_req.pk_key.data = NULL;
        kx509_req.pk_key.length = 0;
    }

    if (ret == 0)
        ret = krb5_cc_get_principal(context, incc, &this_cred.client);
    if (ret == 0)
        ret = get_start_realm(context, incc, this_cred.client, &start_realm);
    if (ret == 0 && kx509_ctx->realm == NULL)
        ret = krb5_kx509_ctx_set_realm(context, kx509_ctx, start_realm);
    if (ret == 0) {
        /*
         * The kx509 protocol as deployed uses kca_service/kdc_hostname, but
         * this is inconvenient in libkrb5: we want to be able to use the
         * send_to_kdc machinery, and since the Heimdal KDC is also the kx509
         * service, we want not to have to specify kx509 hosts separately from
         * KDCs.
         *
         * We'd much rather use krbtgt/CLIENT_REALM@REQUESTED_REALM.  What
         * we do is assume all KDCs for `realm' support the kx509 service and
         * then sendto the KDCs for that realm while using a hostbased service
         * if still desired.
         *
         * Note that upstairs we try to get the start_realm cc config, so if
         * realm wasn't given to krb5_kx509_ext(), then it should be set to
         * that already unless there's no start_realm cc config, in which case
         * we'll use the ccache's default client principal's realm.
         */
        hostname = krb5_config_get_string(context, NULL, "realms",
                                          kx509_ctx->realm, "kx509_hostname",
                                          NULL);
        if (hostname == NULL)
            hostname = krb5_config_get_string(context, NULL, "libdefaults",
                                              "kx509_hostname", NULL);
        if (hostname) {
            ret = krb5_sname_to_principal(context, hostname, "kca_service",
                                          KRB5_NT_SRV_HST, &this_cred.server);
            if (ret == 0)
                ret = krb5_principal_set_realm(context, this_cred.server,
                                               kx509_ctx->realm);
        } else {
            ret = krb5_make_principal(context, &this_cred.server,
                                      start_realm,
                                      KRB5_TGS_NAME,
                                      kx509_ctx->realm,
                                      NULL);
        }
    }

    /* Make the AP-REQ and extract the HMAC key */
    if (ret == 0)
        ret = krb5_get_credentials(context, 0, incc, &this_cred, &cred);
    if (ret == 0)
        ret = krb5_mk_req_extended(context, &kx509_ctx->ac, AP_OPTS_USE_SUBKEY,
                                   NULL, cred, &kx509_req.authenticator);
    krb5_free_keyblock(context, kx509_ctx->hmac_key);
    kx509_ctx->hmac_key = NULL;
    if (ret == 0)
        ret = krb5_auth_con_getkey(context, kx509_ctx->ac,
                                   &kx509_ctx->hmac_key);

    if (ret)
        goto out;

    /* Add the the key and HMAC to the message */
    HMAC_CTX_init(&ctx);
    if (HMAC_Init_ex(&ctx, kx509_ctx->hmac_key->keyvalue.data,
                     kx509_ctx->hmac_key->keyvalue.length,
                     EVP_sha1(), NULL) == 0) {
        HMAC_CTX_cleanup(&ctx);
        ret = krb5_enomem(context);
    } else {
        HMAC_Update(&ctx, version_2_0, sizeof(version_2_0));
        if (private_key || kx509_ctx->given_csr.data) {
            HMAC_Update(&ctx, kx509_req.pk_key.data, kx509_req.pk_key.length);
        } else {
            /* Probe */
            HMAC_Update(&ctx, kx509_req.authenticator.data, kx509_req.authenticator.length);
        }
        HMAC_Final(&ctx, kx509_req.pk_hash.data, 0);
        HMAC_CTX_cleanup(&ctx);
    }

    /* Encode the message, prefix `version_2_0', output the result */
    if (ret == 0)
        ASN1_MALLOC_ENCODE(Kx509Request, pre_req.data, pre_req.length, &kx509_req, &len, ret);
    if (ret == 0)
        ret = krb5_data_alloc(req, pre_req.length + sizeof(version_2_0));
    if (ret == 0) {
        memcpy(req->data, version_2_0, sizeof(version_2_0));
        memcpy(((unsigned char *)req->data) + sizeof(version_2_0),
               pre_req.data, pre_req.length);
    }

out:
    free(start_realm);
    free(pre_req.data);
    krb5_free_creds(context, cred);
    kx509_req.pk_hash.data = NULL;
    kx509_req.pk_hash.length = 0;
    free_Kx509Request(&kx509_req);
    free_SubjectPublicKeyInfo(&spki);
    krb5_free_cred_contents(context, &this_cred);
    if (ret == 0 && req->length != len + sizeof(version_2_0)) {
        krb5_data_free(req);
        krb5_set_error_message(context, ret = ERANGE,
                               "Could not make a kx509 request");
    }
    return ret;
}

static krb5_error_code
rd_chain(krb5_context context,
         heim_octet_string *d,
         hx509_cert *cert,
         hx509_certs *chain,
         heim_error_t *herr)
{
    krb5_error_code ret;
    Certificates certs;
    size_t i, len;

    *cert = NULL;
    *chain = NULL;

    if ((ret = decode_Certificates(d->data, d->length, &certs, &len)))
        return ret;
    if (certs.len == 0) {
        *herr = heim_error_create(EINVAL, "Server sent empty Certificate list");
        return EINVAL;
    }
    *cert = hx509_cert_init(context->hx509ctx, &certs.val[0], herr);
    if (*cert == NULL) {
        free_Certificates(&certs);
        return errno;
    }
    if (certs.len == 1)
        _krb5_debug(context, 1, "kx509 server sent certificate but no chain");
    else
        _krb5_debug(context, 1, "kx509 server sent %llu certificates",
                    (unsigned long long)certs.len);

    ret = hx509_certs_init(context->hx509ctx, "MEMORY:anonymous",
                           HX509_CERTS_CREATE, NULL, chain);
    if (ret) {
        hx509_cert_free(*cert);
        *cert = NULL;
        free_Certificates(&certs);
        return ret;
    }

    for (i = 1; ret == 0 && i < certs.len; i++) {
        hx509_cert c = hx509_cert_init(context->hx509ctx, &certs.val[i], herr);

        if (c == NULL)
            ret = errno;
        else
            ret = hx509_certs_add(context->hx509ctx, *chain, c);
        hx509_cert_free(c);
    }
    free_Certificates(&certs);
    if (ret) {
        hx509_certs_free(chain);
        hx509_cert_free(*cert);
        *cert = NULL;
    }
    return ret;
}

/* Parse and validate a kx509 reply */
static krb5_error_code
rd_kx509_resp(krb5_context context,
              krb5_kx509_req_ctx kx509_ctx,
              krb5_data *rep,
              hx509_cert *cert,
              hx509_certs *chain)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    Kx509Response r;
    krb5_error_code code = 0;
    krb5_error_code ret = 0;
    heim_string_t hestr;
    heim_error_t herr = NULL;
    const char *estr;
    HMAC_CTX ctx;
    size_t hdr_len = sizeof(version_2_0);
    size_t len;

    *cert = NULL;
    *chain = NULL;

    /* Strip `version_2_0' prefix */
    if (rep->length < hdr_len || memcmp(rep->data, version_2_0, hdr_len) != 0) {
        krb5_set_error_message(context, ENOTSUP,
                               "KDC does not support kx509 protocol");
        return ENOTSUP; /* XXX */
    }

    /* Decode */
    ret = decode_Kx509Response(((unsigned char *)rep->data) + 4,
                               rep->length - 4, &r, &len);
    if (ret == 0 && len + hdr_len != rep->length)
        ret = EINVAL; /* XXX */
    if (ret) {
        krb5_set_error_message(context, ret, "kx509 response is not valid");
        return ret;
    }

    HMAC_CTX_init(&ctx);
    if (HMAC_Init_ex(&ctx, kx509_ctx->hmac_key->keyvalue.data,
                     kx509_ctx->hmac_key->keyvalue.length, EVP_sha1(), NULL) == 0) {
        free_Kx509Response(&r);
        HMAC_CTX_cleanup(&ctx);
        return krb5_enomem(context);
    }

    HMAC_Update(&ctx, version_2_0, sizeof(version_2_0));

    {
        int32_t t = r.error_code;
        unsigned char encint[sizeof(t) + 1];
        size_t k;

        /*
         * RFC6717 says this about how the error-code is included in the HMAC:
         *
         *  o DER representation of the error-code exclusive of the tag and
         *    length, if it is present.
         *
         * So we use der_put_integer(), which encodes from the right.
         *
         * RFC6717 does not constrain the error-code's range.  We assume it to
         * be a 32-bit, signed integer, for which we'll need no more than 5
         * bytes.
         */
        ret = der_put_integer(&encint[sizeof(encint) - 1],
                              sizeof(encint), &t, &k);
        if (ret == 0)
            HMAC_Update(&ctx, &encint[sizeof(encint)] - k, k);

        /* Normalize error code */
        if (r.error_code == 0) {
            code = 0; /* No error */
        } else if (r.error_code < 0) {
            code = KRB5KRB_ERR_GENERIC; /* ??? */
        } else if (r.error_code <= KX509_ERR_SRV_OVERLOADED) {
            /*
             * RFC6717 (kx509) error code.  These are actually not used on the
             * wire in any existing implementations that we are aware of.  Just
             * in case, however, we'll map these.
             */
            code = KX509_ERR_CLNT_FATAL + r.error_code;
        } else if (r.error_code < kx509_krb5_error_base) {
            /* Unknown error codes */
            code = KRB5KRB_ERR_GENERIC;
        } else {
            /*
             * Heimdal-specific enhancement to RFC6171: Kerberos wire protocol
             * error codes.
             */
            code = KRB5KDC_ERR_NONE + r.error_code - kx509_krb5_error_base;
            if (code >= KRB5_ERR_RCSID)
                code = KRB5KRB_ERR_GENERIC;
            if (code == KRB5KDC_ERR_NONE)
                code = 0;
        }
    }
    if (r.certificate)
        HMAC_Update(&ctx, r.certificate->data, r.certificate->length);
    if (r.e_text)
        HMAC_Update(&ctx, *r.e_text, strlen(*r.e_text));
    HMAC_Final(&ctx, &digest, 0);
    HMAC_CTX_cleanup(&ctx);

    if (r.hash == NULL) {
        /*
         * No HMAC -> unauthenticated [error] response.
         *
         * Do not output any certificate.
         */
        free_Kx509Response(&r);
        return code;
    }

    /*
     * WARNING: We do not validate that `r.certificate' is a DER-encoded
     *          Certificate, not here, and we don't use a different HMAC key
     *          for the response than for the request.
     *
     *          If ever we start sending a Certificate as the Kx509Request
     *          pk-key field, then we'll have a reflection attack.  As the
     *          Certificate we'd send in that case will be expired, the
     *          reflection attack would be just a DoS.
     */
    if (r.hash->length != sizeof(digest) ||
        ct_memcmp(r.hash->data, digest, sizeof(digest)) != 0) {
        krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
                               "kx509 response MAC mismatch");
        free_Kx509Response(&r);
        return KRB5KRB_AP_ERR_BAD_INTEGRITY;
    }

    if (r.certificate == NULL) {
        /* Authenticated response, either an error or probe success */
        free_Kx509Response(&r);
        if (code != KRB5KDC_ERR_POLICY && kx509_ctx->priv_key == NULL)
            return 0; /* Probe success */
        return code ? code : KRB5KDC_ERR_POLICY; /* Not a probe -> must fail */
    }

    /* Import the certificate payload */
    if (kx509_ctx->expect_chain) {
        ret = rd_chain(context, r.certificate, cert, chain, &herr);
    } else {
        *cert = hx509_cert_init_data(context->hx509ctx, r.certificate->data,
                                     r.certificate->length, &herr);
        if (!*cert)
            ret = errno;
    }
    free_Kx509Response(&r);
    if (*cert) {
        heim_release(herr);
        return 0;
    }

    hestr = herr ? heim_error_copy_string(herr) : NULL;
    estr = hestr ? heim_string_get_utf8(hestr) : "(no error message)";
    krb5_set_error_message(context, ret, "Could not parse certificate "
                           "produced by kx509 KDC: %s (%ld)",
                           estr,
                           herr ? (long)heim_error_get_code(herr) : 0L);

    heim_release(hestr);
    heim_release(herr);
    return HEIM_PKINIT_CERTIFICATE_INVALID; /* XXX */
}

/*
 * Make a request, send it, get the response, parse it, and store the
 * private key and certificate.
 */
static krb5_error_code
kx509_core(krb5_context context,
           krb5_kx509_req_ctx kx509_ctx,
           krb5_ccache incc,
           const char *hx509_store,
           krb5_ccache outcc)
{
    krb5_error_code ret;
    hx509_certs chain = NULL;
    hx509_cert cert = NULL;
    krb5_data req, resp;

    krb5_data_zero(&req);
    krb5_data_zero(&resp);

    /* Make the kx509 request */
    ret = mk_kx509_req(context, kx509_ctx, incc, kx509_ctx->priv_key, &req);

    /* Send the kx509 request and get the response */
    if (ret == 0)
        ret = krb5_sendto_context(context, NULL, &req,
                                  kx509_ctx->realm, &resp);
    if (ret == 0)
        ret = rd_kx509_resp(context, kx509_ctx, &resp, &cert, &chain);

    /* Store the key and cert! */
    if (ret == 0 && cert && (kx509_ctx->priv_key || kx509_ctx->given_csr.data))
        ret = store(context, hx509_store, kx509_ctx->realm, outcc,
                    kx509_ctx->priv_key, cert, chain);
    else if (ret == KRB5KDC_ERR_POLICY)
        /* Probe failed -> record that the realm does not support kx509 */
        store_kx509_disabled(context, kx509_ctx->realm, outcc);

    hx509_certs_free(&chain);
    hx509_cert_free(cert);
    krb5_data_free(&resp);
    krb5_data_free(&req);
    return ret;
}

/**
 * Use the kx509 v2 protocol to get a certificate for the client principal.
 *
 * Given a private key this function will get a certificate.  If no private key
 * is given, one will be generated.
 *
 * The private key and certificate will be stored in the given PKIX credential
 * store (e.g, "PEM-FILE:/path/to/file.pem") and/or given output ccache.  When
 * stored in a ccache, the DER-encoded Certificate will be stored as the data
 * payload of a "cc config" named "kx509cert", while the key will be stored as
 * a DER-encoded PKCS#8 PrivateKeyInfo in a cc config named "kx509key".
 *
 * @param context The Kerberos library context
 * @param kx509_ctx A kx509 request context
 * @param incc A credential cache (if NULL use default ccache)
 * @param hx509_store An PKIX credential store into which to store the private
 *                    key and certificate (e.g, "PEM-FILE:/path/to/file.pem")
 * @param outcc A ccache into which to store the private key and certificate
 *              (mandatory)
 *
 * @return A krb5 error code.
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kx509_ext(krb5_context context,
               krb5_kx509_req_ctx kx509_ctx,
               krb5_ccache incc,
               const char *hx509_store,
               krb5_ccache outcc)
{
    krb5_ccache def_cc = NULL;
    krb5_error_code ret;

    if (incc == NULL) {
        if ((ret = krb5_cc_default(context, &def_cc)))
            return ret;
        incc = def_cc;
    }

    if (kx509_ctx->realm == NULL &&
        (ret = get_start_realm(context, incc, NULL, &kx509_ctx->realm))) {
        if (def_cc)
            krb5_cc_close(context, def_cc);
        return ret;
    }

    if (kx509_ctx->priv_key || kx509_ctx->given_csr.data) {
        /* If given a private key, use it */
        ret = kx509_core(context, kx509_ctx, incc, hx509_store, outcc);
        if (def_cc)
            krb5_cc_close(context, def_cc);
        return ret;
    }

    /*
     * No private key given, so we generate one.
     *
     * However, before taking the hit for generating a keypair we probe to see
     * if we're likely to succeeed.
     */

    /* Probe == call kx509_core() w/o a private key */
    ret = kx509_core(context, kx509_ctx, incc, NULL, outcc);
    if (ret == 0 && kx509_ctx->given_csr.data == NULL)
        ret = krb5_kx509_ctx_gen_key(context, kx509_ctx, NULL, 0);
    if (ret == 0)
        ret = kx509_core(context, kx509_ctx, incc, hx509_store, outcc);

    if (def_cc)
        krb5_cc_close(context, def_cc);
    return ret;
}

/**
 * Generates a public key and uses the kx509 v2 protocol to get a certificate
 * for that key and the client principal's subject name.
 *
 * The private key and certificate will be stored in the given ccache, and also
 * in a corresponding PKIX credential store if one is configured via
 * [libdefaults] kx509_store.
 *
 * XXX NOTE: Dicey feature here...  Review carefully!
 *
 * @param context The Kerberos library context
 * @param cc A credential cache
 * @param realm A realm from which to get the certificate (uses the client
 *              principal's realm if NULL)
 *
 * @return A krb5 error code.
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kx509(krb5_context context, krb5_ccache cc, const char *realm)
{
    krb5_kx509_req_ctx kx509_ctx;
    krb5_error_code ret;
    const char *defcc;
    char *ccache_full_name = NULL;
    char *store_exp = NULL;

    ret = krb5_kx509_ctx_init(context, &kx509_ctx);
    if (ret)
        return ret;
    if (realm)
        ret = krb5_kx509_ctx_set_realm(context, kx509_ctx, realm);

    /*
     * The idea is that IF we are asked to do kx509 w/ creds from a default
     * ccache THEN we should store the kx509 certificate (if we get one) and
     * private key in the default hx509 store for kx509.
     *
     * Ideally we could have HTTP user-agents and/or TLS libraries look for
     * client certificates and private keys in that default hx509 store.
     *
     * Of course, those user-agents / libraries should be configured to use
     * those credentials with specific hostnames/domainnames, not the entire
     * Internet, as the latter leaks the user's identity to the world.
     *
     * So we check if the full name for `cc' is the same as that of the default
     * ccache name, and if so we get the [libdefaults] kx509_store string and
     * expand it, then use it.
     */
    if (ret == 0 &&
        (defcc = krb5_cc_configured_default_name(context)) &&
        krb5_cc_get_full_name(context, cc, &ccache_full_name) == 0 &&
        strcmp(defcc, ccache_full_name) == 0) {

        /* Find an hx509 store */
        const char *store = krb5_config_get_string(context, NULL,
                                                   "libdefaults",
                                                   "kx509_store", NULL);
        if (store)
            ret = _krb5_expand_path_tokens(context, store, 1, &store_exp);

        /*
         * If there's a private key in the store already, we'll use it, else
         * we'll let krb5_kx509_ext() generate one, so we ignore this return
         * value:
         */
        (void) krb5_kx509_ctx_set_key(context, kx509_ctx, store);
    }

    /*
     * If we did settle on a default hx509 store, we'll use it for reading the
     * private key from (if it exists) as well as for storing the certificate
     * (and private key) into, which may save us some key generation cycles.
     */
    if (ret == 0)
        ret = krb5_kx509_ext(context, kx509_ctx, cc, store_exp, cc);
    krb5_kx509_ctx_free(context, &kx509_ctx);
    free(ccache_full_name);
    free(store_exp);
    return ret;
}
