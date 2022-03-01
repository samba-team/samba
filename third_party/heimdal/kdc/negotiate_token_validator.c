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

/*
 * This is a plugin by which bx509d can validate Negotiate tokens.
 *
 * [kdc]
 *     negotiate_token_validator = {
 *         keytab = ...
 *     }
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <base64.h>
#include <roken.h>
#include <heimbase.h>
#include <krb5.h>
#include <common_plugin.h>
#include <gssapi/gssapi.h>
#include <token_validator_plugin.h>

static int
display_status(krb5_context context,
               OM_uint32 major,
               OM_uint32 minor,
               gss_cred_id_t acred,
               gss_ctx_id_t gctx,
               gss_OID mech_type)
{
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    OM_uint32 dmaj, dmin;
    OM_uint32 more = 0;
    char *gmmsg = NULL;
    char *gmsg = NULL;
    char *s = NULL;

    do {
        gss_release_buffer(&dmin, &buf);
        dmaj = gss_display_status(&dmin, major, GSS_C_GSS_CODE, GSS_C_NO_OID,
                                  &more, &buf);
        if (GSS_ERROR(dmaj) ||
            buf.length >= INT_MAX ||
            asprintf(&s, "%s%s%.*s", gmsg ? gmsg : "", gmsg ? ": " : "",
                     (int)buf.length, (char *)buf.value) == -1 ||
            s == NULL) {
            free(gmsg);
            gmsg = NULL;
            break;
        }
        gmsg = s;
        s = NULL;
    } while (!GSS_ERROR(dmaj) && more);
    if (mech_type != GSS_C_NO_OID) {
        do {
            gss_release_buffer(&dmin, &buf);
            dmaj = gss_display_status(&dmin, major, GSS_C_MECH_CODE, mech_type,
                                      &more, &buf);
            if (GSS_ERROR(dmaj) ||
                asprintf(&s, "%s%s%.*s", gmmsg ? gmmsg : "", gmmsg ? ": " : "",
                         (int)buf.length, (char *)buf.value) == -1 ||
                s == NULL) {
                free(gmmsg);
                gmmsg = NULL;
                break;
            }
            gmmsg = s;
            s = NULL;
        } while (!GSS_ERROR(dmaj) && more);
    }
    if (gmsg == NULL)
        krb5_set_error_message(context, ENOMEM, "Error displaying GSS-API "
                               "status");
    else
        krb5_set_error_message(context, EACCES, "%s%s%s%s", gmmsg,
                               gmmsg ? " (" : "", gmmsg ? gmmsg : "",
                               gmmsg ? ")" : "");
    if (acred && gctx)
        krb5_prepend_error_message(context, EACCES, "Failed to validate "
                                   "Negotiate token due to error examining "
                                   "GSS-API security context");
    else if (acred)
        krb5_prepend_error_message(context, EACCES, "Failed to validate "
                                   "Negotiate token due to error accepting "
                                   "GSS-API security context token");
    else
        krb5_prepend_error_message(context, EACCES, "Failed to validate "
                                   "Negotiate token due to error acquiring "
                                   "GSS-API default acceptor credential");
    return EACCES;
}

static KRB5_LIB_CALL krb5_error_code
validate(void *ctx,
         krb5_context context,
         const char *realm,
         const char *token_type,
         krb5_data *token,
         const char * const *audiences,
         size_t naudiences,
         krb5_boolean *result,
         krb5_principal *actual_principal,
         krb5_times *token_times)
{
    gss_buffer_desc adisplay_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc idisplay_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc input_token;
    gss_cred_id_t acred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t gctx = GSS_C_NO_CONTEXT;
    gss_name_t aname = GSS_C_NO_NAME;
    gss_name_t iname = GSS_C_NO_NAME;
    gss_OID mech_type = GSS_C_NO_OID;
    const char *kt = krb5_config_get_string(context, NULL, "kdc",
                                            "negotiate_token_validator",
                                            "keytab", NULL);
    OM_uint32 major, minor, ret_flags, time_rec;
    size_t i;
    char *token_decoded = NULL;
    void *token_copy = NULL;
    char *princ_str = NULL;
    int ret = 0;

    if (strcmp(token_type, "Negotiate") != 0)
        return KRB5_PLUGIN_NO_HANDLE;

    if (kt) {
        gss_key_value_element_desc store_keytab_kv;
        gss_key_value_set_desc store;
        gss_OID_desc mech_set[2] = { *GSS_KRB5_MECHANISM, *GSS_SPNEGO_MECHANISM };
        gss_OID_set_desc mechs = { 2, mech_set };

        store_keytab_kv.key = "keytab";
        store_keytab_kv.value = kt;
        store.elements = &store_keytab_kv;
        store.count = 1;
        major = gss_acquire_cred_from(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                      &mechs, GSS_C_ACCEPT, &store, &acred, NULL,
                                      NULL);
        if (major != GSS_S_COMPLETE)
            return display_status(context, major, minor, acred, gctx, mech_type);

        mechs.count = 1;
        major = gss_set_neg_mechs(&minor, acred, &mechs);
        if (major != GSS_S_COMPLETE)
            return display_status(context, major, minor, acred, gctx, mech_type);
    } /* else we'll use the default credential */

    if ((token_decoded = malloc(token->length)) == NULL ||
        (token_copy = calloc(1, token->length + 1)) == NULL)
        goto enomem;

    memcpy(token_copy, token->data, token->length);
    if ((ret = rk_base64_decode(token_copy, token_decoded)) <= 0) {
        krb5_set_error_message(context, EACCES, "Negotiate token malformed");
        ret = EACCES;
        goto out;
    }

    input_token.value = token_decoded;
    input_token.length = ret;
    major = gss_accept_sec_context(&minor, &gctx, acred, &input_token, NULL,
                                   &iname, &mech_type, &output_token,
                                   &ret_flags, &time_rec, NULL);

    if (mech_type == GSS_C_NO_OID ||
        !gss_oid_equal(mech_type, GSS_KRB5_MECHANISM)) {
        krb5_set_error_message(context, ret = EACCES, "Negotiate token used "
                               "non-Kerberos mechanism");
        goto out;
    }

    if (major != GSS_S_COMPLETE) {
        ret = display_status(context, major, minor, acred, gctx, mech_type);
        if (ret == 0)
            ret = EINVAL;
        goto out;
    }

    major = gss_inquire_context(&minor, gctx, NULL, &aname, NULL, NULL,
                                NULL, NULL, NULL);
    if (major == GSS_S_COMPLETE)
        major = gss_display_name(&minor, aname, &adisplay_name, NULL);
    if (major == GSS_S_COMPLETE)
        major = gss_display_name(&minor, iname, &idisplay_name, NULL);
    if (major != GSS_S_COMPLETE) {
        ret = display_status(context, major, minor, acred, gctx, mech_type);
        if (ret == 0)
            ret = EINVAL;
        goto out;
    }

    for (i = 0; i < naudiences; i++) {
        const char *s = adisplay_name.value;
        size_t slen = adisplay_name.length;
        size_t len = strlen(audiences[i]);

        if (slen >= sizeof("HTTP/") - 1       &&
            slen >= sizeof("HTTP/") - 1 + len &&
            memcmp(s, "HTTP/", sizeof("HTTP/") - 1) == 0 &&
            memcmp(s + sizeof("HTTP/") - 1, audiences[i], len) == 0 &&
            s[sizeof("HTTP/") - 1 + len] == '@')
            break;
    }
    if (i == naudiences) {
        /* This handles the case where naudiences == 0 as an error */
        krb5_set_error_message(context, EACCES, "Negotiate token used "
                               "wrong HTTP service host acceptor name");
        goto out;
    }

    if ((princ_str = calloc(1, idisplay_name.length + 1)) == NULL)
        goto enomem;
    memcpy(princ_str, idisplay_name.value, idisplay_name.length);
    if ((ret = krb5_parse_name(context, princ_str, actual_principal)))
        goto out;

    /* XXX Need name attributes to get authtime/starttime/renew_till */
    token_times->authtime   = 0;
    token_times->starttime  = time(NULL) - 300;
    token_times->endtime    = token_times->starttime + 300 + time_rec;
    token_times->renew_till = 0;

    *result = TRUE;
    goto out;

enomem:
    ret = krb5_enomem(context);
out:
    gss_delete_sec_context(&minor, &gctx, NULL);
    gss_release_buffer(&minor, &adisplay_name);
    gss_release_buffer(&minor, &idisplay_name);
    gss_release_buffer(&minor, &output_token);
    gss_release_cred(&minor, &acred);
    gss_release_name(&minor, &aname);
    gss_release_name(&minor, &iname);
    free(token_decoded);
    free(token_copy);
    free(princ_str);
    return ret;
}

static KRB5_LIB_CALL krb5_error_code
negotiate_init(krb5_context context, void **c)
{
    *c = NULL;
    return 0;
}

static KRB5_LIB_CALL void
negotiate_fini(void *c)
{
}

static krb5plugin_token_validator_ftable plug_desc =
    { 1, negotiate_init, negotiate_fini, validate };

static krb5plugin_token_validator_ftable *plugs[] = { &plug_desc };

static uintptr_t
negotiate_get_instance(const char *libname)
{
    if (strcmp(libname, "krb5") == 0)
        return krb5_get_instance(libname);

    return 0;
}

krb5_plugin_load_ft kdc_token_validator_plugin_load;

krb5_error_code KRB5_CALLCONV
kdc_token_validator_plugin_load(heim_pcontext context,
                                krb5_get_instance_func_t *get_instance,
                                size_t *num_plugins,
                                krb5_plugin_common_ftable_cp **plugins)
{
    *get_instance = negotiate_get_instance;
    *num_plugins = sizeof(plugs) / sizeof(plugs[0]);
    *plugins = (krb5_plugin_common_ftable_cp *)plugs;
    return 0;
}
