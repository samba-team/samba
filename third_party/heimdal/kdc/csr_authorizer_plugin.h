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

#ifndef HEIMDAL_KDC_CSR_AUTHORIZER_PLUGIN_H
#define HEIMDAL_KDC_CSR_AUTHORIZER_PLUGIN_H 1

#define KDC_CSR_AUTHORIZER "kdc_csr_authorizer"
#define KDC_CSR_AUTHORIZER_VERSION_0 0

/*
 * @param init          Plugin initialization function (see krb5-plugin(7))
 * @param minor_version The plugin minor version number (0)
 * @param fini          Plugin finalization function
 * @param authorize     Plugin CSR authorization function
 *
 * The authorize field is the plugin entry point that performs authorization of
 * CSRs for kx509 however the plugin desires.  It is invoked in no particular
 * order relative to other CSR authorization plugins.  The plugin authorize
 * function must return KRB5_PLUGIN_NO_HANDLE if the rule is not applicable to
 * it.
 *
 * The plugin authorize function has the following arguments, in this
 * order:
 *
 * -# plug_ctx, the context value output by the plugin's init function
 * -# context, a krb5_context
 * -# app, the name of the application
 * -# csr, a hx509_request
 * -# client, a krb5_const_principal
 * -# authorization_result, a pointer to a krb5_boolean
 *
 * @ingroup krb5_support
 */
typedef struct krb5plugin_csr_authorizer_ftable_desc {
    HEIM_PLUGIN_FTABLE_COMMON_ELEMENTS(krb5_context);
    krb5_error_code	(KRB5_LIB_CALL *authorize)(void *,              /*plug_ctx*/
                                                   krb5_context,        /*context*/
                                                   const char *,        /*app*/
                                                   hx509_request,       /*CSR*/
                                                   krb5_const_principal,/*client*/
                                                   krb5_boolean *);     /*authorized*/
} krb5plugin_csr_authorizer_ftable;

#endif /* HEIMDAL_KDC_CSR_AUTHORIZER_PLUGIN_H */
