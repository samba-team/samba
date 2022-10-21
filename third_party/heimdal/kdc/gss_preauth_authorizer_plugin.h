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

#ifndef HEIMDAL_KDC_GSS_PREAUTH_AUTHORIZER_PLUGIN_H
#define HEIMDAL_KDC_GSS_PREAUTH_AUTHORIZER_PLUGIN_H 1

#define KDC_GSS_PREAUTH_AUTHORIZER "kdc_gss_preauth_authorizer"
#define KDC_GSS_PREAUTH_AUTHORIZER_VERSION_1 1

#include <krb5.h>
#include <gssapi/gssapi.h>

/*
 * @param init          Plugin initialization function (see krb5-plugin(7))
 * @param minor_version The plugin minor version number (1)
 * @param fini          Plugin finalization function
 * @param authorize     Plugin name authorization function
 *
 * -# plug_ctx, the context value output by the plugin's init function
 * -# context, a krb5_context
 * -# req, the AS-REQ request
 * -# client_name, the requested client principal name
 * -# client, the requested client HDB entry
 * -# initiator_name, the authenticated GSS initiator name
 * -# ret_flags, the flags returned by GSS_Init_sec_context()
 * -# authorized, indicate whether the initiator was authorized
 * -# mapped_name, the mapped principal name
 *
 * @ingroup krb5_support
 */

typedef struct krb5plugin_gss_preauth_authorizer_ftable_desc {
    HEIM_PLUGIN_FTABLE_COMMON_ELEMENTS(krb5_context);
    krb5_error_code     (KRB5_LIB_CALL *authorize)(void *,              /*plug_ctx*/
                                                   astgs_request_t,	/*r*/
                                                   gss_const_name_t,    /*initiator_name*/
                                                   gss_const_OID,       /*mech_type*/
                                                   OM_uint32,           /*ret_flags*/
                                                   krb5_boolean *,      /*authorized*/
                                                   krb5_principal *);	/*mapped_name*/
    krb5_error_code     (KRB5_LIB_CALL *finalize_pac)(void *,           /*plug_ctx*/
                                                      astgs_request_t); /*r*/
} krb5plugin_gss_preauth_authorizer_ftable;

#endif /* HEIMDAL_KDC_GSS_PREAUTH_AUTHORIZER_PLUGIN_H */
