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
#include "token_validator_plugin.h"

struct plctx {
    const char              *realm;
    const char              *token_kind;
    krb5_data               *token;
    const char * const      *audiences;
    size_t                  naudiences;
    krb5_boolean            result;
    krb5_principal          actual_principal;
    krb5_times              token_times;
};

static krb5_error_code KRB5_LIB_CALL
plcallback(krb5_context context, const void *plug, void *plugctx, void *userctx)
{
    const krb5plugin_token_validator_ftable *validator = plug;
    krb5_error_code ret;
    struct plctx *plctx = userctx;

    ret = validator->validate(plugctx, context, plctx->realm,
                              plctx->token_kind, plctx->token,
                              plctx->audiences, plctx->naudiences,
                              &plctx->result, &plctx->actual_principal,
                              &plctx->token_times);
    if (ret) {
        krb5_free_principal(context, plctx->actual_principal);
        plctx->actual_principal = NULL;
    }
    return ret;
}

static const char *plugin_deps[] = { "krb5", NULL };

static struct heim_plugin_data token_validator_data = {
    "kdc",
    KDC_PLUGIN_BEARER,
    1,
    plugin_deps,
    krb5_get_instance
};

/*
 * Invoke a plugin to validate a JWT/SAML/OIDC token and partially-evaluate
 * access control.
 */
KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_validate_token(krb5_context context,
                   const char *realm,
                   const char *token_kind,
                   krb5_data *token,
                   const char * const *audiences,
                   size_t naudiences,
                   krb5_principal *actual_principal,
                   krb5_times *token_times)
{
    krb5_error_code ret;
    struct plctx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.realm = realm;
    ctx.token_kind = token_kind;
    ctx.token = token;
    ctx.audiences = audiences;
    ctx.naudiences = naudiences;
    ctx.result = FALSE;
    ctx.actual_principal = NULL;

    krb5_clear_error_message(context);
    ret = _krb5_plugin_run_f(context, &token_validator_data, 0, &ctx,
                             plcallback);
    if (ret == 0 && ctx.result && actual_principal) {
        *actual_principal = ctx.actual_principal;
        ctx.actual_principal = NULL;
    }

    if (token_times)
        *token_times = ctx.token_times;

    krb5_free_principal(context, ctx.actual_principal);
    if (ret)
        krb5_prepend_error_message(context, ret, "bearer token validation "
                                   "failed: ");
    else if (!ctx.result)
        krb5_set_error_message(context, ret = EACCES,
                               "bearer token validation failed");
    return ret;
}
