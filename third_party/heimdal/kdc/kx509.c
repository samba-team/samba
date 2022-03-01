/*
 * Copyright (c) 2006 - 2019 Kungliga Tekniska Högskolan
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
#include <hex.h>
#include <rfc2459_asn1.h>
#include <hx509.h>
#include <hx509_err.h>
#include <kx509_err.h>

#include <stdarg.h>

/*
 * This file implements the kx509 service.
 *
 * The protocol, its shortcomings, and its future are described in
 * lib/krb5/hx509.c.  See also lib/asn1/kx509.asn1.
 *
 * The service handles requests, decides whether to issue a certificate, and
 * does so by populating a "template" to generate a TBSCertificate and signing
 * it with a configured CA issuer certificate and private key.  See ca.c for
 * details.
 *
 * A "template" is a Certificate that has ${variable} references in its
 * subjectName, and may have EKUs.
 *
 * Some SANs may be included in issued certificates.  See below.
 *
 * Besides future protocol improvements described in lib/krb5/hx509.c, here is
 * a list of KDC functionality we'd like to add:
 *
 *  - support templates as strings (rather than filenames) in configuration?
 *  - lookup an hx509 template for the client principal in its HDB entry?
 *  - lookup subjectName, SANs for a principal in its HDB entry
 *  - lookup a host-based client principal's HDB entry and add its canonical
 *    name / aliases as dNSName SANs
 *    (this would have to be if requested by the client, perhaps; see
 *     commentary about the protocol in lib/krb5/kx509.c)
 *  - add code to build a template on the fly
 *
 *    (just SANs, with empty subjectName?
 *     or
 *     CN=component0,CN=component1,..,CN=componentN,DC=<from-REALM>
 *     and set KU and EKUs)
 *
 * Processing begins in _kdc_do_kx509().
 *
 * The sequence of events in _kdc_do_kx509() is:
 *
 *  - parse outer request
 *  - authenticate request
 *  - extract CSR and AP-REQ Authenticator authz-data elements
 *  - characterize request as one of
 *     - default client cert req (no cert exts requested, client user princ)
 *     - default server cert req (no cert exts requested, client service princ)
 *     - client cert req (cert exts requested denoting client use)
 *     - server cert req (cert exts requested denoting server use)
 *     - mixed  cert req (cert exts requested denoting client and server use)
 *  - authorize request based only on the request's details
 *     - there is a default authorizer, and a plugin authorizer
 *  - get configuration sub-tree corresponding to the request as characterized
 *     - missing configuration sub-tree -> reject (we have multiple ways to
 *       express "no")
 *  - get common config params from that sub-tree
 *  - set TBS template and details from CSR and such
 *  - issue certificate by signing TBS
 */

#ifdef KX509

static const unsigned char version_2_0[4] = {0 , 0, 2, 0};

/*
 * Taste the request to see if it's a kx509 request.
 */
krb5_error_code
_kdc_try_kx509_request(kx509_req_context r)
{
    const unsigned char *p = (const void *)(uintptr_t)r->request.data;
    size_t len = r->request.length;
    size_t sz;

    if (len < sizeof(version_2_0))
        return -1;
    if (memcmp(version_2_0, p, sizeof(version_2_0)) != 0)
        return -1;
    p += sizeof(version_2_0);
    len -= sizeof(version_2_0);
    if (len == 0)
        return -1;
    memset(&r->req, 0, sizeof(r->req));
    return decode_Kx509Request(p, len, &r->req, &sz);
}

static krb5_boolean
get_bool_param(krb5_context context,
               krb5_boolean def,
               const char *crealm,
               const char *name)
{
    krb5_boolean global_default;

    global_default = krb5_config_get_bool_default(context, NULL, def, "kdc",
                                                  name, NULL);
    if (!crealm)
        return global_default;
    return krb5_config_get_bool_default(context, NULL, global_default,
                                        "kdc", "realms", crealm, name, NULL);
}

/*
 * Verify the HMAC in the request.
 */
static krb5_error_code
verify_req_hash(krb5_context context,
                const Kx509Request *req,
                krb5_keyblock *key)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    HMAC_CTX ctx;

    if (req->pk_hash.length != sizeof(digest)) {
        krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
                               "pk-hash has wrong length: %lu",
                               (unsigned long)req->pk_hash.length);
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    HMAC_CTX_init(&ctx);
    if (HMAC_Init_ex(&ctx, key->keyvalue.data, key->keyvalue.length,
                     EVP_sha1(), NULL) == 0) {
        HMAC_CTX_cleanup(&ctx);
        return krb5_enomem(context);
    }
    if (sizeof(digest) != HMAC_size(&ctx))
        krb5_abortx(context, "runtime error, hmac buffer wrong size in kx509");
    HMAC_Update(&ctx, version_2_0, sizeof(version_2_0));
    if (req->pk_key.length)
        HMAC_Update(&ctx, req->pk_key.data, req->pk_key.length);
    else
        HMAC_Update(&ctx, req->authenticator.data, req->authenticator.length);
    HMAC_Final(&ctx, digest, 0);
    HMAC_CTX_cleanup(&ctx);

    if (ct_memcmp(req->pk_hash.data, digest, sizeof(digest)) != 0) {
        krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
                               "kx509 request MAC mismatch");
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    return 0;
}

/*
 * Set the HMAC in the response.
 */
static krb5_error_code
calculate_reply_hash(krb5_context context,
                     krb5_keyblock *key,
                     Kx509Response *rep)
{
    krb5_error_code ret = 0;
    HMAC_CTX ctx;

    HMAC_CTX_init(&ctx);

    if (HMAC_Init_ex(&ctx, key->keyvalue.data, key->keyvalue.length,
                     EVP_sha1(), NULL) == 0)
        ret = krb5_enomem(context);

    if (ret == 0)
        ret = krb5_data_alloc(rep->hash, HMAC_size(&ctx));
    if (ret) {
        HMAC_CTX_cleanup(&ctx);
        return krb5_enomem(context);
    }

    HMAC_Update(&ctx, version_2_0, sizeof(version_2_0));
    {
        int32_t t = rep->error_code;
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
    }
    if (rep->certificate)
        HMAC_Update(&ctx, rep->certificate->data, rep->certificate->length);
    if (rep->e_text)
        HMAC_Update(&ctx, (unsigned char *)*rep->e_text, strlen(*rep->e_text));

    HMAC_Final(&ctx, rep->hash->data, 0);
    HMAC_CTX_cleanup(&ctx);

    return 0;
}

static void
frees(char **s)
{
    free(*s);
    *s = NULL;
}

/* Check that a krbtgt's second component is a local realm */
static krb5_error_code
is_local_realm(krb5_context context,
               kx509_req_context reqctx,
               const char *realm)
{
    krb5_error_code ret;
    krb5_principal tgs;
    HDB *db;
    hdb_entry *ent = NULL;

    ret = krb5_make_principal(context, &tgs, realm, KRB5_TGS_NAME, realm,
                              NULL);
    if (ret)
        return ret;
    if (ret == 0)
        ret = _kdc_db_fetch(context, reqctx->config, tgs, HDB_F_GET_KRBTGT,
                            NULL, &db, &ent);
    if (ent)
        _kdc_free_ent(context, db, ent);
    krb5_free_principal(context, tgs);
    if (ret == HDB_ERR_NOENTRY || ret == HDB_ERR_NOT_FOUND_HERE)
        return KRB5KRB_AP_ERR_NOT_US;
    return ret;
}

/*
 * Since we're using the HDB as a keytab we have to check that the client used
 * an acceptable name for the kx509 service.
 *
 * We accept two names: kca_service/hostname and krbtgt/REALM.
 *
 * We allow cross-realm requests.
 *
 *     Maybe x-realm support should be configurable.  Requiring INITIAL tickets
 *     does NOT preclude x-realm support!  (Cross-realm TGTs can be INITIAL.)
 *
 *     Support for specific client realms is configurable by configuring issuer
 *     credentials and TBS templates on a per-realm basis and configuring no
 *     default.  But maybe we should have an explicit configuration parameter
 *     to enable support for clients from different realms than the service.
 */
static krb5_error_code
kdc_kx509_verify_service_principal(krb5_context context,
                                   kx509_req_context reqctx,
                                   krb5_principal sprincipal)
{
    krb5_error_code ret = 0;
    krb5_principal principal = NULL;
    char *expected = NULL;
    char localhost[MAXHOSTNAMELEN];

    if (krb5_principal_get_num_comp(context, sprincipal) != 2)
        goto err;

    /* Check if sprincipal is a krbtgt/REALM name */
    if (strcmp(krb5_principal_get_comp_string(context, sprincipal, 0),
               KRB5_TGS_NAME) == 0) {
        const char *r = krb5_principal_get_comp_string(context, sprincipal, 1);
        if ((ret = is_local_realm(context, reqctx, r)))
            kdc_audit_addreason((kdc_request_t)reqctx,
                                "Client used wrong krbtgt for kx509");
        goto out;
    }

    /* Must be hostbased kca_service name then */
    ret = gethostname(localhost, sizeof(localhost) - 1);
    if (ret != 0) {
        ret = errno;
        kdc_log(context, reqctx->config, 0, "Failed to get local hostname");
        kdc_audit_addreason((kdc_request_t)reqctx,
                            "Failed to get local hostname");
        return ret;
    }
    localhost[sizeof(localhost) - 1] = '\0';

    ret = krb5_make_principal(context, &principal, "", "kca_service",
                              localhost, NULL);
    if (ret)
        goto out;

    if (krb5_principal_compare_any_realm(context, sprincipal, principal))
        goto out;       /* found a match */

err:
    ret = krb5_unparse_name(context, sprincipal, &expected);
    if (ret)
        goto out;

    ret = KRB5KDC_ERR_SERVER_NOMATCH;
    kdc_audit_addreason((kdc_request_t)reqctx, "Client used wrong kx509 "
                        "service principal (expected %s)", expected);

out:
    krb5_xfree(expected);
    krb5_free_principal(context, principal);

    return ret;
}

static krb5_error_code
encode_reply(krb5_context context,
             kx509_req_context reqctx,
             Kx509Response *r)
{
    krb5_error_code ret;
    krb5_data data;
    size_t size;

    reqctx->reply->data = NULL;
    reqctx->reply->length = 0;
    ASN1_MALLOC_ENCODE(Kx509Response, data.data, data.length, r, &size, ret);
    if (ret)
        return ret;
    if (size != data.length)
        krb5_abortx(context, "ASN1 internal error");

    ret = krb5_data_alloc(reqctx->reply, data.length + sizeof(version_2_0));
    if (ret == 0) {
        memcpy(reqctx->reply->data, version_2_0, sizeof(version_2_0));
        memcpy(((unsigned char *)reqctx->reply->data) + sizeof(version_2_0),
               data.data, data.length);
    }
    free(data.data);
    return ret;
}

/* Make an error response, and log the error message as well */
static krb5_error_code
mk_error_response(krb5_context context,
                  kx509_req_context reqctx,
                  int level,
                  int32_t code,
                  const char *fmt,
                  ...)
{
    krb5_error_code ret = code;
    krb5_error_code ret2;
    Kx509Response rep;
    const char *msg;
    char *freeme0 = NULL;
    char *freeme1 = NULL;
    va_list ap;

    if (code != 0) {
        /* Log errors where _kdc_audit_trail() is not enough */
        if (code == ENOMEM)
            level = 0;
        if (level < 3) {
            va_start(ap, fmt);
            kdc_vlog(context, reqctx->config, level, fmt, ap);
            va_end(ap);
        }

        va_start(ap, fmt);
        kdc_audit_vaddreason((kdc_request_t)reqctx, fmt, ap);
        va_end(ap);
    }

    if (!reqctx->config->enable_kx509)
        code = KRB5KDC_ERR_POLICY;

    /* Make sure we only send RFC4120 and friends wire protocol error codes */
    if (code) {
        if (code == KX509_ERR_NONE) {
            code = 0;
        } else if (code > KX509_ERR_NONE && code <= KX509_ERR_SRV_OVERLOADED) {
            code -= KX509_ERR_NONE;
        } else {
            if (code < KRB5KDC_ERR_NONE || code >= KRB5_ERR_RCSID)
                code = KRB5KRB_ERR_GENERIC;
            code -= KRB5KDC_ERR_NONE;
            code += kx509_krb5_error_base;
        }
    }

    va_start(ap, fmt);
    if (vasprintf(&freeme0, fmt, ap) == -1 || freeme0 == NULL)
        msg = "Could not format error message (out of memory)";
    else
        msg = freeme0;
    va_end(ap);

    if (!reqctx->config->enable_kx509 &&
        asprintf(&freeme1, "kx509 service is disabled (%s)", msg) > -1 &&
        freeme1 != NULL) {
        msg = freeme1;
    }

    rep.hash = NULL;
    rep.certificate = NULL;
    rep.error_code = code;
    if (ALLOC(rep.e_text))
        *rep.e_text = (void *)(uintptr_t)msg;

    if (reqctx->key) {
        if (ALLOC(rep.hash) != NULL &&
            calculate_reply_hash(context, reqctx->key, &rep)) {
            free(rep.hash);
            rep.hash = NULL;
        }
    }

    if ((ret2 = encode_reply(context, reqctx, &rep)))
        ret = ret2;
    if (rep.hash)
        krb5_data_free(rep.hash);
    free(rep.e_text);
    free(rep.hash);
    free(freeme0);
    free(freeme1);
    return ret;
}

/* Wrap a bare public (RSA) key with a CSR (not signed it, since we can't) */
static krb5_error_code
make_csr(krb5_context context, kx509_req_context reqctx, krb5_data *key)
{
    krb5_error_code ret;
    SubjectPublicKeyInfo spki;
    heim_any any;

    ret = hx509_request_init(context->hx509ctx, &reqctx->csr);
    if (ret)
        return ret;

    memset(&spki, 0, sizeof(spki));
    spki.subjectPublicKey.data = key->data;
    spki.subjectPublicKey.length = key->length * 8;

    ret = der_copy_oid(&asn1_oid_id_pkcs1_rsaEncryption,
                       &spki.algorithm.algorithm);

    any.data = "\x05\x00";
    any.length = 2;
    spki.algorithm.parameters = &any;

    if (ret == 0)
        ret = hx509_request_set_SubjectPublicKeyInfo(context->hx509ctx,
                                                     reqctx->csr, &spki);
    der_free_oid(&spki.algorithm.algorithm);
    if (ret)
        hx509_request_free(&reqctx->csr);

    /*
     * TODO: Move a lot of the templating stuff here so we can let clients
     *       leave out extensions they don't want.
     */
    return ret;
}

/* Update a CSR with desired Certificate Extensions */
static krb5_error_code
update_csr(krb5_context context, kx509_req_context reqctx, Extensions *exts)
{
    krb5_error_code ret = 0;
    size_t i, k;

    if (exts == NULL)
        return 0;

    for (i = 0; ret == 0 && i < exts->len; i++) {
        Extension *e = &exts->val[i];

        if (der_heim_oid_cmp(&e->extnID, &asn1_oid_id_x509_ce_keyUsage) == 0) {
            KeyUsage ku;

            ret = decode_KeyUsage(e->extnValue.data, e->extnValue.length, &ku,
                                  NULL);
            if (ret)
                return ret;
            ret = hx509_request_set_ku(context->hx509ctx, reqctx->csr, ku);
        } else if (der_heim_oid_cmp(&e->extnID,
                                    &asn1_oid_id_x509_ce_extKeyUsage) == 0) {
            ExtKeyUsage eku;

            ret = decode_ExtKeyUsage(e->extnValue.data, e->extnValue.length,
                                     &eku, NULL);
            for (k = 0; ret == 0 && k < eku.len; k++) {
                ret = hx509_request_add_eku(context->hx509ctx, reqctx->csr,
                                            &eku.val[k]);
            }
            free_ExtKeyUsage(&eku);
        } else if (der_heim_oid_cmp(&e->extnID,
                                    &asn1_oid_id_x509_ce_subjectAltName) == 0) {
            GeneralNames san;

            ret = decode_GeneralNames(e->extnValue.data, e->extnValue.length,
                                      &san, NULL);
            for (k = 0; ret == 0 && k < san.len; k++) {
                ret = hx509_request_add_GeneralName(context->hx509ctx,
                                                    reqctx->csr, &san.val[k]);
            }
            free_GeneralNames(&san);
        }
    }
    if (ret) {
	const char *emsg = krb5_get_error_message(context, ret);
        kdc_log(context, reqctx->config, 1,
                "Error handling requested extensions: %s", emsg);
        kdc_audit_addreason((kdc_request_t)reqctx,
                            "Error handling requested extensions: %s",
                            emsg);
	krb5_free_error_message(context, emsg);
    }
    return ret;
}


/*
 * Parse the `pk_key' from the request as a CSR or raw public key, and if the
 * latter, wrap it in a non-signed CSR.
 */
static krb5_error_code
get_csr(krb5_context context, kx509_req_context reqctx)
{
    krb5_error_code ret;
    RSAPublicKey rsapkey;
    heim_octet_string pk_key = reqctx->req.pk_key;
    size_t size;

    ret = decode_Kx509CSRPlus(pk_key.data, pk_key.length, &reqctx->csr_plus,
                              &size);
    if (ret == 0) {
        reqctx->have_csr = 1;
        reqctx->send_chain = 1;

        /* Parse CSR */
        ret = hx509_request_parse_der(context->hx509ctx, &reqctx->csr_plus.csr,
                                      &reqctx->csr);
        /*
         * Handle any additional Certificate Extensions requested out of band
         * of the CSR.
         */
        if (ret == 0)
            return update_csr(context, reqctx, reqctx->csr_plus.exts);
        kdc_audit_addreason((kdc_request_t)reqctx, "Invalid CSR");
        return ret;
    }
    reqctx->send_chain = 0;
    reqctx->have_csr = 0;

    /* Check if proof of possession is required by configuration */
    if (!get_bool_param(context, FALSE, reqctx->realm, "require_csr")) {
        kdc_audit_addreason((kdc_request_t)reqctx,
                            "CSRs required but client did not send one");
        krb5_set_error_message(context, KX509_STATUS_CLIENT_USE_CSR,
                               "CSRs required but kx509 client did not send "
                               "one");
        return KX509_STATUS_CLIENT_USE_CSR;
    }

    /* Attempt to decode pk_key as RSAPublicKey */
    ret = decode_RSAPublicKey(reqctx->req.pk_key.data,
                              reqctx->req.pk_key.length,
                              &rsapkey, &size);
    free_RSAPublicKey(&rsapkey);
    if (ret == 0 && size == reqctx->req.pk_key.length)
        return make_csr(context, reqctx, &pk_key); /* Make pretend CSR */

    /* Not an RSAPublicKey or garbage follows it */
    if (ret == 0) {
        ret = KRB5KDC_ERR_NULL_KEY;
        kdc_audit_addreason((kdc_request_t)reqctx,
                            "Request has garbage after key");
        krb5_set_error_message(context, ret, "Request has garbage after key");
        return ret;
    }

    kdc_audit_addreason((kdc_request_t)reqctx,
                        "Could not decode CSR or RSA subject public key");
    krb5_set_error_message(context, ret,
                           "Could not decode CSR or RSA subject public key");
    return ret;
}

/*
 * Host-based principal _clients_ might ask for a cert for their host -- but
 * which services are permitted to do that?  This function answers that
 * question.
 */
static int
check_authz_svc_ok(krb5_context context, const char *svc)
{
    const char *def[] = { "host", "HTTP", 0 };
    const char * const *svcs;
    char **strs;

    strs = krb5_config_get_strings(context, NULL, "kdc",
                                   "kx509_permitted_hostbased_services", NULL);
    for (svcs = strs ? (const char * const *)strs : def; svcs[0]; svcs++) {
        if (strcmp(svcs[0], svc) == 0) {
            krb5_config_free_strings(strs);
            return 1;
        }
    }
    krb5_config_free_strings(strs);
    return 0;
}

static krb5_error_code
check_authz(krb5_context context,
            kx509_req_context reqctx,
            krb5_principal cprincipal)
{
    krb5_error_code ret;
    const char *comp0 = krb5_principal_get_comp_string(context, cprincipal, 0);
    const char *comp1 = krb5_principal_get_comp_string(context, cprincipal, 1);
    unsigned int ncomp = krb5_principal_get_num_comp(context, cprincipal);
    hx509_san_type san_type;
    KeyUsage ku, ku_allowed;
    size_t i;
    const heim_oid *eku_whitelist[] = {
        &asn1_oid_id_pkix_kp_serverAuth,
        &asn1_oid_id_pkix_kp_clientAuth,
        &asn1_oid_id_pkekuoid,
        &asn1_oid_id_pkinit_ms_eku
    };
    char *cprinc = NULL;
    char *s = NULL;

    /*
     * In the no-CSR case we'll derive cert contents from client name and its
     * HDB entry -- authorization is implied.
     */
    if (!reqctx->have_csr)
        return 0;
    ret = kdc_authorize_csr(context, reqctx->config->app, reqctx->csr,
                            cprincipal);
    if (ret == 0) {
        kdc_audit_setkv_bool((kdc_request_t)reqctx, "authorized", TRUE);

        ret = hx509_request_get_san(reqctx->csr, 0, &san_type, &s);
        if (ret == 0) {
            const char *san_type_s;

            /* This should be an hx509 function... */
            switch (san_type) {
            case HX509_SAN_TYPE_EMAIL: san_type_s = "rfc822Name"; break;
            case HX509_SAN_TYPE_DNSNAME: san_type_s = "dNSName"; break;
            case HX509_SAN_TYPE_DN: san_type_s = "DN"; break;
            case HX509_SAN_TYPE_REGISTERED_ID: san_type_s = "registeredID"; break;
            case HX509_SAN_TYPE_XMPP: san_type_s = "xMPPName"; break;
            case HX509_SAN_TYPE_PKINIT: san_type_s = "krb5PrincipalName"; break;
            case HX509_SAN_TYPE_MS_UPN: san_type_s = "ms-UPN"; break;
            default: san_type_s = "unknown"; break;
            }
            kdc_audit_addkv((kdc_request_t)reqctx, 0, "san0_type", "%s",
                            san_type_s);
            kdc_audit_addkv((kdc_request_t)reqctx, 0, "san0", "%s", s);
        }
	frees(&s);
        ret = hx509_request_get_eku(reqctx->csr, 0, &s);
        if (ret == 0)
            kdc_audit_addkv((kdc_request_t)reqctx, 0, "eku0", "%s", s);
	free(s);
        return 0;
    }
    if (ret != KRB5_PLUGIN_NO_HANDLE) {
        kdc_audit_addreason((kdc_request_t)reqctx,
                             "Requested extensions rejected by plugin");
        return ret;
    }

    /* Default authz */
    if ((ret = krb5_unparse_name(context, cprincipal, &cprinc)))
        return ret;

    for (i = 0; ret == 0; i++) {

        frees(&s);
        ret = hx509_request_get_san(reqctx->csr, i, &san_type, &s);
        if (ret)
            break;
        switch (san_type) {
        case HX509_SAN_TYPE_DNSNAME:
            if (ncomp != 2 || strcasecmp(comp1, s) != 0 ||
                strchr(s, '.') == NULL ||
                !check_authz_svc_ok(context, comp0)) {
                kdc_audit_addreason((kdc_request_t)reqctx,
                                    "Requested extensions rejected by "
                                    "default policy (dNSName SAN "
                                    "does not match client)");
                goto eacces;
            }
            break;
        case HX509_SAN_TYPE_PKINIT:
            if (strcmp(cprinc, s) != 0) {
                kdc_audit_addreason((kdc_request_t)reqctx,
                                    "Requested extensions rejected by "
                                    "default policy (PKINIT SAN "
                                    "does not match client)");
                goto eacces;
            }
            break;
        default:
            kdc_audit_addreason((kdc_request_t)reqctx,
                                "Requested extensions rejected by "
                                "default policy (non-default SAN "
                                "requested)");
            goto eacces;
        }
    }
    frees(&s);
    if (ret == HX509_NO_ITEM)
        ret = 0;
    if (ret)
        goto out;

    for (i = 0; ret == 0; i++) {
        heim_oid oid;
        size_t k;

        frees(&s);
        ret = hx509_request_get_eku(reqctx->csr, i, &s);
        if (ret)
            break;

        if ((ret = der_parse_heim_oid(s, ".", &oid))) {
            goto out;
        }
        for (k = 0; k < sizeof(eku_whitelist)/sizeof(eku_whitelist[0]); k++) {
            if (der_heim_oid_cmp(eku_whitelist[k], &oid) == 0)
                break;
        }
        der_free_oid(&oid);
        if (k == sizeof(eku_whitelist)/sizeof(eku_whitelist[0])) {
            kdc_audit_addreason((kdc_request_t)reqctx,
                                "Requested EKU rejected by default policy");
            goto eacces;
        }
    }
    if (ret == HX509_NO_ITEM)
        ret = 0;
    if (ret)
        goto out;

    memset(&ku_allowed, 0, sizeof(ku_allowed));
    ku_allowed.digitalSignature = 1;
    ku_allowed.nonRepudiation = 1;
    ret = hx509_request_get_ku(context->hx509ctx, reqctx->csr, &ku);
    if (ret)
        goto out;
    if (KeyUsage2int(ku) != (KeyUsage2int(ku) & KeyUsage2int(ku_allowed)))
        goto eacces;

    kdc_audit_setkv_bool((kdc_request_t)reqctx, "authorized", TRUE);
    free(cprinc);
    return 0;

eacces:
    ret = EACCES;
    goto out2;

out:
    /* XXX Display error code */
    kdc_audit_addreason((kdc_request_t)reqctx,
                         "Error handling requested extensions");
out2:
    free(cprinc);
    free(s);
    return ret;
}

static int
chain_add1_func(hx509_context context, void *d, hx509_cert c)
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
encode_cert_and_chain(hx509_context hx509ctx,
                      hx509_certs certs,
                      krb5_data *out)
{
    krb5_error_code ret;
    Certificates cs;
    size_t len;

    cs.len = 0;
    cs.val = 0;

    ret = hx509_certs_iter_f(hx509ctx, certs, chain_add1_func, &cs);
    if (ret == 0)
        ASN1_MALLOC_ENCODE(Certificates, out->data, out->length,
                           &cs, &len, ret);
    free_Certificates(&cs);
    return ret;
}

/*
 * Process a request, produce a reply.
 */

krb5_error_code
_kdc_do_kx509(kx509_req_context r)
{
    krb5_error_code ret = 0;
    krb5_ticket *ticket = NULL;
    krb5_flags ap_req_options;
    krb5_principal cprincipal = NULL;
    krb5_principal sprincipal = NULL;
    krb5_keytab id = NULL;
    Kx509Response rep;
    hx509_certs certs = NULL;
    int is_probe = 0;

    r->csr_plus.csr.data = NULL;
    r->csr_plus.exts = NULL;
    r->sname = NULL;
    r->cname = NULL;
    r->realm = NULL;
    r->key = NULL;
    r->csr = NULL;
    r->ac = NULL;

    /*
     * In order to support authenticated error messages we defer checking
     * whether the kx509 service is enabled until after accepting the AP-REQ.
     */

    krb5_data_zero(r->reply);
    memset(&rep, 0, sizeof(rep));

    if (r->req.authenticator.length == 0) {
        /*
         * Unauthenticated kx509 service availability probe.
         *
         * mk_error_response() will check whether the service is enabled and
         * possibly change the error code and message.
         */
        is_probe = 1;
        kdc_audit_addkv((kdc_request_t)r, 0, "probe", "unauthenticated");
        ret = mk_error_response(r->context, r, 4, 0,
                                "kx509 service is available");
        goto out;
    }

    /* Authenticate the request (consume the AP-REQ) */
    ret = krb5_kt_resolve(r->context, "HDBGET:", &id);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
        ret = mk_error_response(r->context, r, 1,
                                KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,
                                "Can't open HDB/keytab for kx509: %s",
				msg);
	krb5_free_error_message(r->context, msg);
        goto out;
    }

    ret = krb5_rd_req(r->context,
                      &r->ac,
                      &r->req.authenticator,
                      NULL,
                      id,
                      &ap_req_options,
                      &ticket);
    if (ret == 0)
        ret = krb5_auth_con_getkey(r->context, r->ac, &r->key);
    if (ret == 0 && r->key == NULL)
        ret = KRB5KDC_ERR_NULL_KEY;
    /*
     * Provided we got the session key, errors past this point will be
     * authenticated.
     */
    if (ret == 0)
        ret = krb5_ticket_get_client(r->context, ticket, &cprincipal);

    /* Optional: check if Ticket is INITIAL */
    if (ret == 0 &&
        !ticket->ticket.flags.initial &&
        !get_bool_param(r->context, TRUE,
                        krb5_principal_get_realm(r->context, cprincipal),
                        "require_initial_kca_tickets")) {
        ret = mk_error_response(r->context, r, 4, KRB5KDC_ERR_POLICY,
                                "Client used non-INITIAL tickets, but kx509 "
                                "service is configured to require INITIAL "
                                "tickets");
        goto out;
    }

    if (ret == 0)
	ret = krb5_unparse_name(r->context, cprincipal, &r->cname);

    /* Check that the service name is a valid kx509 service name */
    if (ret == 0)
        ret = krb5_ticket_get_server(r->context, ticket, &sprincipal);
    if (ret == 0)
        r->realm = krb5_principal_get_realm(r->context, sprincipal);
    if (ret == 0)
        ret = krb5_unparse_name(r->context, sprincipal, &r->sname);
    if (ret == 0)
        ret = kdc_kx509_verify_service_principal(r->context, r, sprincipal);
    if (ret) {
        ret = mk_error_response(r->context, r, 4, ret,
                                "kx509 client used incorrect service name");
        goto out;
    }

    /* Authenticate the rest of the request */
    ret = verify_req_hash(r->context, &r->req, r->key);
    if (ret) {
        ret = mk_error_response(r->context, r, 4, ret,
                                "Incorrect request HMAC on kx509 request");
        goto out;
    }

    if (r->req.pk_key.length == 0) {
        /*
         * The request is an authenticated kx509 service availability probe.
         *
         * mk_error_response() will check whether the service is enabled and
         * possibly change the error code and message.
         */
        is_probe = 1;
        kdc_audit_addkv((kdc_request_t)r, 0, "probe", "authenticated");
        ret = mk_error_response(r->context, r, 4, 0,
                                "kx509 authenticated probe request");
        goto out;
    }

    /* Extract and parse CSR or a DER-encoded RSA public key */
    ret = get_csr(r->context, r);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
        ret = mk_error_response(r->context, r, 3, ret,
                                "Failed to parse CSR: %s", msg);
	krb5_free_error_message(r->context, msg);
        goto out;
    }

    /* Authorize the request */
    ret = check_authz(r->context, r, cprincipal);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
        ret = mk_error_response(r->context, r, 3, ret,
                                "Rejected by policy: %s", msg);
	krb5_free_error_message(r->context, msg);
        goto out;
    }

    /* Issue the certificate */
    ALLOC(rep.hash);
    ALLOC(rep.certificate);
    if (rep.certificate == NULL || rep.hash == NULL) {
        ret = mk_error_response(r->context, r, 0, ENOMEM,
                                "Could allocate memory for response");
        goto out;
    }

    krb5_data_zero(rep.hash);
    krb5_data_zero(rep.certificate);
    krb5_ticket_get_times(r->context, ticket, &r->ticket_times);
    ret = kdc_issue_certificate(r->context, r->config->app, r->logf, r->csr,
                                cprincipal, &r->ticket_times, 0 /*req_life*/,
                                r->send_chain, &certs);
    if (ret) {
        int level = 1;
	const char *msg = krb5_get_error_message(r->context, ret);

        if (ret == KRB5KDC_ERR_POLICY)
            level = 4; /* _kdc_audit_trail() logs at level 3 */
        ret = mk_error_response(r->context, r, level, ret,
                                "Certificate isuance failed: %s", msg);
	krb5_free_error_message(r->context, msg);
        goto out;
    }

    ret = encode_cert_and_chain(r->context->hx509ctx, certs, rep.certificate);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
        ret = mk_error_response(r->context, r, 1, ret,
                                "Could not encode certificate and chain: %s",
				msg);
	krb5_free_error_message(r->context, msg);
        goto out;
    }

    /* Authenticate the response */
    ret = calculate_reply_hash(r->context, r->key, &rep);
    if (ret) {
        ret = mk_error_response(r->context, r, 1, ret,
                                "Failed to compute response HMAC");
        goto out;
    }

    /* Encode and output reply */
    ret = encode_reply(r->context, r, &rep);
    if (ret)
        /* Can't send an error message either in this case, surely */
        kdc_audit_addreason((kdc_request_t)r, "Could not encode response");

out:
    hx509_certs_free(&certs);
    if (ret == 0 && !is_probe)
        kdc_audit_setkv_bool((kdc_request_t)r, "cert_issued", TRUE);
    else
        kdc_audit_setkv_bool((kdc_request_t)r, "cert_issued", FALSE);
    if (r->ac)
        krb5_auth_con_free(r->context, r->ac);
    if (ticket)
        krb5_free_ticket(r->context, ticket);
    if (id)
        krb5_kt_close(r->context, id);
    if (sprincipal)
        krb5_free_principal(r->context, sprincipal);
    if (cprincipal)
        krb5_free_principal(r->context, cprincipal);
    if (r->key)
        krb5_free_keyblock (r->context, r->key);
    hx509_request_free(&r->csr);
    free_Kx509CSRPlus(&r->csr_plus);
    free_Kx509Response(&rep);
    free_Kx509Request(&r->req);

    return ret;
}

#endif /* KX509 */
