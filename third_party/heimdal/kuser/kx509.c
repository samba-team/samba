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

#include "kuser_locl.h"
#include "heimtools-commands.h"
#include <kx509_asn1.h>
#undef HC_DEPRECATED_CRYPTO
#include "../lib/hx509/hx_locl.h"
#include "../lib/krb5/krb5_locl.h"
#include "hx509-private.h"

struct validate_store {
    size_t ncerts;
    int grace;
};

static int KRB5_CALLCONV
validate1(hx509_context hx509ctx, void *d, hx509_cert cert)
{
    struct validate_store *v = d;

    if (hx509_cert_get_notAfter(cert) < time(NULL) + v->grace)
        return HX509_CERT_USED_AFTER_TIME;
    v->ncerts++;
    return 0;
}

static void
validate(krb5_context context,
         int grace,
         const char *hx509_store,
         krb5_data *der_cert,
         krb5_data *pkcs8_priv_key)
{
    hx509_context hx509ctx = NULL;
    hx509_cert cert;
    krb5_error_code ret;

    ret = hx509_context_init(&hx509ctx);
    if (ret)
        krb5_err(context, 1, ret, "hx509 context init");

    if (der_cert->data && pkcs8_priv_key->data) {
        hx509_private_key key = NULL;

        cert = hx509_cert_init_data(hx509ctx, der_cert->data,
                                    der_cert->length, NULL);
        if (cert == NULL)
            krb5_err(context, 1, errno, "certificate could not be loaded");
        ret = hx509_parse_private_key(hx509ctx, NULL, pkcs8_priv_key->data,
                                      pkcs8_priv_key->length,
                                      HX509_KEY_FORMAT_PKCS8, &key);
        if (ret)
            krb5_err(context, 1, ret, "certificate could not be loaded");
        if (hx509_cert_get_notAfter(cert) < time(NULL) + grace)
            krb5_errx(context, 1, "certificate is expired");
        hx509_private_key_free(&key);
        hx509_cert_free(cert);
    }
    if (hx509_store) {
        struct validate_store v;
        hx509_certs certs;

        v.ncerts = 0;
        v.grace = grace;

        ret = hx509_certs_init(hx509ctx, hx509_store, 0, NULL, &certs);
        if (ret)
            krb5_err(context, 1, ret, "could not read hx509 store %s",
                     hx509_store);
        ret = hx509_certs_iter_f(hx509ctx, certs, validate1, &v);
        if (ret)
            krb5_err(context, 1, ret, "at least one certificate in %s expired",
                     hx509_store);
        if (!v.ncerts)
            krb5_errx(context, 1, "no certificates in %s", hx509_store);

        hx509_certs_free(&certs);
    }

    hx509_context_free(&hx509ctx);
}

static krb5_error_code KRB5_CALLCONV
add1_2chain(hx509_context hx509ctx, void *d, hx509_cert cert)
{
    heim_octet_string os;
    krb5_error_code ret;
    Certificates *cs = d;
    Certificate c;

    ret = hx509_cert_binary(hx509ctx, cert, &os);
    if (ret == 0)
	ret = decode_Certificate(os.data, os.length, &c, NULL); 
    der_free_octet_string(&os);
    if (ret == 0) {
        add_Certificates(cs, &c);
        free_Certificate(&c);
    }
    return ret;
}

static krb5_error_code
add_chain(hx509_context hx509ctx, hx509_certs certs, krb5_data *chain)
{
    krb5_error_code ret;
    Certificates cs;
    size_t len;

    ret = decode_Certificates(chain->data, chain->length, &cs, &len);
    if (ret == 0) {
        ret = hx509_certs_iter_f(hx509ctx, certs, add1_2chain, &cs);
        free_Certificates(&cs);
    }
    return ret;
}

static void
store(krb5_context context,
      const char *hx509_store,
      krb5_data *der_cert,
      krb5_data *pkcs8_priv_key,
      krb5_data *chain)
{
    hx509_context hx509ctx = NULL;
    hx509_private_key key = NULL;
    hx509_certs certs;
    hx509_cert cert;
    char *store_exp = NULL;
    krb5_error_code ret;

    if (hx509_store == NULL) {
        hx509_store = krb5_config_get_string(context, NULL, "libdefaults",
                                             "kx509_store", NULL);
        if (hx509_store) {
            ret = _krb5_expand_path_tokens(context, hx509_store, 1,
                                           &store_exp);
            if (ret)
                krb5_err(context, 1, ret, "expanding tokens in default "
                         "hx509 store");
            hx509_store = store_exp;
        }
    }
    if (hx509_store == NULL)
        krb5_errx(context, 1, "no hx509 store given and no default hx509 "
                  "store configured");

    ret = hx509_context_init(&hx509ctx);
    if (ret)
        krb5_err(context, 1, ret, "hx509 context init");

    cert = hx509_cert_init_data(hx509ctx, der_cert->data,
                                der_cert->length, NULL);
    if (cert == NULL)
        krb5_err(context, 1, errno, "certificate could not be loaded");
    ret = hx509_parse_private_key(hx509ctx, NULL, pkcs8_priv_key->data,
                                  pkcs8_priv_key->length,
                                  HX509_KEY_FORMAT_PKCS8, &key);
    if (ret)
        krb5_err(context, 1, ret, "certificate could not be loaded");
    (void) _hx509_cert_assign_key(cert, key);

    ret = hx509_certs_init(hx509ctx, hx509_store, HX509_CERTS_CREATE, NULL,
                           &certs);
    if (ret == 0)
        ret = hx509_certs_add(hx509ctx, certs, cert);
    if (ret == 0)
        add_chain(hx509ctx, certs, chain);
    if (ret == 0)
        ret = hx509_certs_store(hx509ctx, certs, 0, NULL);
    if (ret)
        krb5_err(context, 1, ret, "certificate could not be stored");

    hx509_private_key_free(&key);
    hx509_certs_free(&certs);
    hx509_cert_free(cert);
    hx509_context_free(&hx509ctx);
    free(store_exp);
}

static void
set_csr(krb5_context context, krb5_kx509_req_ctx req, const char *csr_file)
{
    krb5_error_code ret;
    krb5_data d;

    if (strncmp(csr_file, "PKCS10:", sizeof("PKCS10:") - 1) != 0)
        krb5_errx(context, 1, "CSR filename must start with \"PKCS10:\"");
    ret = rk_undumpdata(csr_file + sizeof("PKCS10:") - 1, &d.data, &d.length);
    if (ret)
        krb5_err(context, 1, ret, "could not read CSR");
    ret = krb5_kx509_ctx_set_csr_der(context, req, &d);
    if (ret)
        krb5_err(context, 1, ret, "hx509 context init");
}

int
kx509(struct kx509_options *opt, int argc, char **argv)
{
    krb5_kx509_req_ctx req = NULL;
    krb5_context context = heimtools_context;
    krb5_error_code ret = 0;
    krb5_ccache ccout = NULL;
    krb5_ccache cc = NULL;

    if (opt->cache_string)
        ret = krb5_cc_resolve(context, opt->cache_string, &cc);
    else if (opt->save_flag || opt->extract_flag)
        ret = krb5_cc_default(context, &cc);
    if (ret)
        krb5_err(context, 1, ret, "no input credential cache");
    if (opt->save_flag)
        ccout = cc;

    if (opt->test_integer &&
        (opt->extract_flag || opt->csr_string || opt->private_key_string))
        krb5_errx(context, 1, "--test is exclusive of --extract, --csr, and "
                  "--private-key");

    if (opt->extract_flag && (opt->csr_string || opt->private_key_string))
        krb5_errx(context, 1, "--extract is exclusive of --csr and "
                  "--private-key");

    if (opt->test_integer || opt->extract_flag) {
        krb5_data der_cert, pkcs8_key, chain;

        der_cert.data = pkcs8_key.data = chain.data = NULL;
        der_cert.length = pkcs8_key.length = chain.length = 0;
        ret = krb5_cc_get_config(context, cc, NULL, "kx509cert", &der_cert);
        if (ret == 0)
            ret = krb5_cc_get_config(context, cc, NULL, "kx509key",
                                     &pkcs8_key);
        if (ret == 0)
            ret = krb5_cc_get_config(context, cc, NULL, "kx509cert-chain",
                                     &chain);
        if (ret)
            krb5_err(context, 1, ret, "no certificate in credential cache");
        if (opt->test_integer)
            validate(context, opt->test_integer, opt->out_string, &der_cert,
                     &pkcs8_key);
        else
            store(context, opt->out_string, &der_cert, &pkcs8_key, &chain);
        krb5_data_free(&pkcs8_key);
        krb5_data_free(&der_cert);
        krb5_data_free(&chain);
    } else {
        /*
         * XXX We should delete any cc configs that indicate that kx509 is
         * disabled.
         */
        ret = krb5_kx509_ctx_init(context, &req);
        if (ret == 0 && opt->realm_string)
            ret = krb5_kx509_ctx_set_realm(context, req, opt->realm_string);
        if (ret == 0 && opt->csr_string)
            set_csr(context, req, opt->csr_string);
        if (ret == 0 && opt->private_key_string)
            ret = krb5_kx509_ctx_set_key(context, req,
                                         opt->private_key_string);
        if (ret)
            krb5_err(context, 1, ret,
                     "could not set up kx509 request options");

        ret = krb5_kx509_ext(context, req, cc, opt->out_string, ccout);
        if (ret)
            krb5_err(context, 1, ret,
                     "could not acquire certificate with kx509");
        krb5_kx509_ctx_free(context, &req);
    }

    krb5_cc_close(context, cc);
    
    return 0;
}
