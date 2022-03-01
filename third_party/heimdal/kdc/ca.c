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

#include "kdc_locl.h"
#include <hex.h>
#include <rfc2459_asn1.h>
#include "../lib/hx509/hx_locl.h"

#include <stdarg.h>

/*
 * This file implements a singular utility function `kdc_issue_certificate()'
 * for certificate issuance for kx509 and bx509, which takes a principal name,
 * an `hx509_request' resulting from parsing a CSR and possibly adding
 * SAN/EKU/KU extensions, the start/end times of request's authentication
 * method, and whether to include a full certificate chain in the result.
 */

/*
 * Get a configuration sub-tree for kx509 based on what's being requested and
 * by whom.
 *
 * We have a number of cases:
 *
 *  - default certificate (no CSR used, or no certificate extensions requested)
 *     - for client principals
 *     - for service principals
 *  - client certificate requested (CSR used and client-y SANs/EKUs requested)
 *  - server certificate requested (CSR used and server-y SANs/EKUs requested)
 *  - mixed client/server certificate requested (...)
 */
static krb5_error_code
get_cf(krb5_context context,
       const char *app_name,
       krb5_log_facility *logf,
       hx509_request req,
       krb5_principal cprinc,
       const krb5_config_binding **cf)
{
    krb5_error_code ret = ENOTSUP;
    const char *realm = krb5_principal_get_realm(context, cprinc);

    *cf = NULL;
    if (strcmp(app_name, "kdc") == 0)
        *cf = krb5_config_get_list(context, NULL, app_name, "realms", realm,
                                   "kx509", NULL);
    else
        *cf = krb5_config_get_list(context, NULL, app_name, "realms", realm,
                                   NULL);
    if (*cf)
        ret = 0;
    if (ret) {
        krb5_log_msg(context, logf, 3, NULL,
                     "No %s configuration for certification authority [%s] "
                     "realm %s -> kx509 -> ...", app_name,
                     strcmp(app_name, "bx509") == 0 ? "bx509" : "kx509",
                     realm);
        krb5_set_error_message(context, KRB5KDC_ERR_POLICY,
                "No %s configuration for certification authority [%s] "
                "realm %s -> kx509 -> ...", app_name,
                strcmp(app_name, "bx509") == 0 ? "bx509" : "kx509",
                realm);
    }
    return ret;
}

/*
 * Build a certifate for `principal' and its CSR.
 */
KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_issue_certificate(krb5_context context,
                      const char *app_name,
                      krb5_log_facility *logf,
                      hx509_request req,
                      krb5_principal cprinc,
                      krb5_times *auth_times,
                      time_t req_life,
                      int send_chain,
                      hx509_certs *out)
{
    const krb5_config_binding *cf;
    krb5_error_code ret = KRB5KDC_ERR_POLICY;
    KRB5PrincipalName cprinc2;

    *out = NULL;
    cprinc2.principalName = cprinc->name;
    cprinc2.realm = cprinc->realm;

    /* Get configuration */
    ret = get_cf(context, app_name, logf, req, cprinc, &cf);
    if (ret == 0)
        ret = _hx509_ca_issue_certificate(context->hx509ctx,
                                          (const heim_config_binding *)cf,
                                          logf, req, &cprinc2,
                                          auth_times->starttime,
                                          auth_times->endtime,
                                          req_life,
                                          send_chain,
                                          out);
    if (ret == EACCES)
        ret = KRB5KDC_ERR_POLICY;
    return ret;
}
