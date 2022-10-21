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

#ifndef HEIMDAL_KDC_BEARER_TOKEN_PLUGIN_H
#define HEIMDAL_KDC_BEARER_TOKEN_PLUGIN_H 1

#define KDC_PLUGIN_BEARER "kdc_token_validator"
#define KDC_PLUGIN_BEARER_VERSION_0 0

/*
 * @param init          Plugin initialization function (see krb5-plugin(7))
 * @param minor_version The plugin minor version number (0)
 * @param fini          Plugin finalization function
 * @param validate      Plugin token validation function
 *
 * The validate field is the plugin entry point that performs the bearer token
 * validation operation however the plugin desires.  It is invoked in no
 * particular order relative to other bearer token validator plugins.  The
 * plugin validate function must return KRB5_PLUGIN_NO_HANDLE if the rule is
 * not applicable to it.
 *
 * The plugin validate function has the following arguments, in this
 * order:
 *
 * -# plug_ctx, the context value output by the plugin's init function
 * -# context, a krb5_context
 * -# realm, a const char *
 * -# token_type, a const char *
 * -# token, a krb5_data *
 * -# audiences, a const pointer to an array of const char * containing
 *  expected audiences of the token (aka, acceptor names)
 * -# naudiences, a size_t count of audiences
 * -# requested_principal, a krb5_const_principal
 * -# validation result, a pointer to a krb5_boolean
 * -# actual principal, a krb5_principal * output parameter (optional)
 *
 * @ingroup krb5_support
 */
typedef struct krb5plugin_token_validator_ftable_desc {
    HEIM_PLUGIN_FTABLE_COMMON_ELEMENTS(krb5_context);
    krb5_error_code	(KRB5_LIB_CALL *validate)(void *,           /*plug_ctx*/
                                                  krb5_context,
                                                  const char *,     /*realm*/
                                                  const char *,     /*token_type*/
                                                  krb5_data *,      /*token*/
                                                  const char * const *, /*audiences*/
                                                  size_t,           /*naudiences*/
                                                  krb5_boolean *,   /*valid*/
                                                  krb5_principal *, /*actual_principal*/
                                                  krb5_times *);    /*token_times*/
} krb5plugin_token_validator_ftable;

#endif /* HEIMDAL_KDC_BEARER_TOKEN_PLUGIN_H */
