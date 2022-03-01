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
#include "csr_authorizer_plugin.h"

struct plctx {
    const char              *app;
    hx509_request           csr;
    krb5_const_principal    client;
    krb5_boolean            result;
};

static krb5_error_code KRB5_LIB_CALL
plcallback(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_csr_authorizer_ftable *authorizer = plug;
    struct plctx *plctx = userctx;

    return authorizer->authorize(plugctx, context, plctx->app, plctx->csr,
                                 plctx->client, &plctx->result);
}

static const char *plugin_deps[] = { "krb5", NULL };

static struct heim_plugin_data csr_authorizer_data = {
    "kdc",
    KDC_CSR_AUTHORIZER,
    1,
    plugin_deps,
    krb5_get_instance
};

/*
 * Invoke a plugin to validate a JWT/SAML/OIDC token and partially-evaluate
 * access control.
 */
KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_authorize_csr(krb5_context context,
                  const char *app,
                  hx509_request csr,
                  krb5_const_principal client)
{
    krb5_error_code ret;
    struct plctx ctx;

    ctx.app = app;
    ctx.csr = csr;
    ctx.client = client;
    ctx.result = FALSE;

    ret = _krb5_plugin_run_f(context, &csr_authorizer_data, 0, &ctx,
                             plcallback);
    if (ret)
        krb5_prepend_error_message(context, ret, "Authorization of requested "
                                   "certificate extensions failed");
    else if (!ctx.result)
        krb5_set_error_message(context, ret, "Authorization of requested "
                               "certificate extensions failed");
    return ret;
}
