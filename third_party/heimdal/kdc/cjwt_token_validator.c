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
 * This is a plugin by which bx509d can validate JWT Bearer tokens using the
 * cjwt library.
 *
 * Configuration:
 *
 *  [kdc]
 *      realm = {
 *          A.REALM.NAME = {
 *              cjwt_jqk = PATH-TO-JWK-PEM-FILE
 *          }
 *      }
 *
 * where AUDIENCE-FOR-KDC is the value of the "audience" (i.e., the target) of
 * the token.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <heimbase.h>
#include <krb5.h>
#include <common_plugin.h>
#include <hdb.h>
#include <roken.h>
#include <token_validator_plugin.h>
#include <cjwt/cjwt.h>
#ifdef HAVE_CJSON
#include <cJSON.h>
#endif

static const char *
get_kv(krb5_context context, const char *realm, const char *k, const char *k2)
{
    return krb5_config_get_string(context, NULL, "bx509", "realms", realm,
                                  k, k2, NULL);
}

static krb5_error_code
get_issuer_pubkeys(krb5_context context,
                   const char *realm,
                   krb5_data *previous,
                   krb5_data *current,
                   krb5_data *next)
{
    krb5_error_code save_ret = 0;
    krb5_error_code ret;
    const char *v;
    size_t nkeys = 0;

    previous->data = current->data = next->data = 0;
    previous->length = current->length = next->length = 0;

    if ((v = get_kv(context, realm, "cjwt_jwk_next", NULL)) &&
        (++nkeys) &&
        (ret = rk_undumpdata(v, &next->data, &next->length)))
        save_ret = ret;
    if ((v = get_kv(context, realm, "cjwt_jwk_previous", NULL)) &&
        (++nkeys) &&
        (ret = rk_undumpdata(v, &previous->data, &previous->length)) &&
        save_ret == 0)
        save_ret = ret;
    if ((v = get_kv(context, realm, "cjwt_jwk_current", NULL)) &&
        (++nkeys) &&
        (ret = rk_undumpdata(v, &current->data, &current->length)) &&
        save_ret == 0)
        save_ret = ret;
    if (nkeys == 0)
        krb5_set_error_message(context, EINVAL, "jwk issuer key not specified in "
                               "[bx509]->realm->%s->cjwt_jwk_{previous,current,next}",
                               realm);
    if (!previous->length && !current->length && !next->length)
        krb5_set_error_message(context, save_ret,
                               "Could not read jwk issuer public key files");
    if (current->length && current->length == next->length &&
        memcmp(current->data, next->data, next->length) == 0) {
        free(next->data);
        next->data = 0;
        next->length = 0;
    }
    if (current->length && current->length == previous->length &&
        memcmp(current->data, previous->data, previous->length) == 0) {
        free(previous->data);
        previous->data = 0;
        previous->length = 0;
    }

    if (previous->data == NULL && current->data == NULL && next->data == NULL)
        return krb5_set_error_message(context, ENOENT, "No JWKs found"),
               ENOENT;
    return 0;
}

static krb5_error_code
check_audience(krb5_context context,
               const char *realm,
               cjwt_t *jwt,
               const char * const *audiences,
               size_t naudiences)
{
    size_t i, k;

    if (!jwt->aud) {
        krb5_set_error_message(context, EACCES, "JWT bearer token has no "
                               "audience");
        return EACCES;
    }
    for (i = 0; i < jwt->aud->count; i++)
        for (k = 0; k < naudiences; k++)
            if (strcasecmp(audiences[k], jwt->aud->names[i]) == 0)
                return 0;
    krb5_set_error_message(context, EACCES, "JWT bearer token's audience "
                           "does not match any expected audience");
    return EACCES;
}

static krb5_error_code
get_princ(krb5_context context,
          const char *realm,
          cjwt_t *jwt,
          krb5_principal *actual_principal)
{
    krb5_error_code ret;
    const char *force_realm = NULL;
    const char *domain;

#ifdef HAVE_CJSON
    if (jwt->private_claims) {
        cJSON *jval;

        if ((jval = cJSON_GetObjectItem(jwt->private_claims, "authz_sub")))
            return krb5_parse_name(context, jval->valuestring, actual_principal);
    }
#endif

    if (jwt->sub == NULL) {
        krb5_set_error_message(context, EACCES, "JWT token lacks 'sub' "
                               "(subject name)!");
        return EACCES;
    }
    if ((domain = strchr(jwt->sub, '@'))) {
        force_realm = get_kv(context, realm, "cjwt_force_realm", ++domain);
        ret = krb5_parse_name(context, jwt->sub, actual_principal);
    } else {
        ret = krb5_parse_name_flags(context, jwt->sub,
                                    KRB5_PRINCIPAL_PARSE_NO_REALM,
                                    actual_principal);
    }
    if (ret)
        krb5_set_error_message(context, ret, "JWT token 'sub' not a valid "
                               "principal name: %s", jwt->sub);
    else if (force_realm)
        ret = krb5_principal_set_realm(context, *actual_principal, realm);
    else if (domain == NULL)
        ret = krb5_principal_set_realm(context, *actual_principal, realm);
    /* else leave the domain as the realm */
    return ret;
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
    heim_octet_string jwk_previous;
    heim_octet_string jwk_current;
    heim_octet_string jwk_next;
    cjwt_t *jwt = NULL;
    char *tokstr = NULL;
    char *defrealm = NULL;
    int ret;

    if (strcmp(token_type, "Bearer") != 0)
        return KRB5_PLUGIN_NO_HANDLE; /* Not us */

    if ((tokstr = calloc(1, token->length + 1)) == NULL)
        return ENOMEM;
    memcpy(tokstr, token->data, token->length);

    if (realm == NULL) {
        ret = krb5_get_default_realm(context, &defrealm);
        if (ret) {
            krb5_set_error_message(context, ret, "could not determine default "
                                   "realm");
            free(tokstr);
            return ret;
        }
        realm = defrealm;
    }

    ret = get_issuer_pubkeys(context, realm, &jwk_previous, &jwk_current,
                             &jwk_next);
    if (ret) {
        free(defrealm);
        free(tokstr);
        return ret;
    }

    if (jwk_current.length && jwk_current.data)
        ret = cjwt_decode(tokstr, 0, &jwt, jwk_current.data,
                          jwk_current.length);
    if (ret && jwk_next.length && jwk_next.data)
        ret = cjwt_decode(tokstr, 0, &jwt, jwk_next.data,
                            jwk_next.length);
    if (ret && jwk_previous.length && jwk_previous.data)
        ret = cjwt_decode(tokstr, 0, &jwt, jwk_previous.data,
                          jwk_previous.length);
    free(jwk_previous.data);
    free(jwk_current.data);
    free(jwk_next.data);
    jwk_previous.data = jwk_current.data = jwk_next.data = NULL;
    free(tokstr);
    tokstr = NULL;
    switch (ret) {
    case 0:
        if (jwt == NULL) {
            krb5_set_error_message(context, EINVAL, "JWT validation failed");
            free(defrealm);
            return EPERM;
        }
        if (jwt->header.alg == alg_none) {
            krb5_set_error_message(context, EINVAL, "JWT signature algorithm "
                                   "not supported");
            free(defrealm);
            return EPERM;
        }
        break;
    case -1:
        krb5_set_error_message(context, EINVAL, "invalid JWT format");
        free(defrealm);
        return EINVAL;
    case -2:
        krb5_set_error_message(context, EINVAL, "JWT signature validation "
                               "failed (wrong issuer?)");
        free(defrealm);
        return EPERM;
    default:
        krb5_set_error_message(context, ret, "misc token validation error");
        free(defrealm);
        return ret;
    }

    /* Success; check audience */
    if ((ret = check_audience(context, realm, jwt, audiences, naudiences))) {
        cjwt_destroy(&jwt);
        free(defrealm);
        return EACCES;
    }

    /* Success; extract principal name */
    if ((ret = get_princ(context, realm, jwt, actual_principal)) == 0) {
        token_times->authtime   = jwt->iat.tv_sec;
        token_times->starttime  = jwt->nbf.tv_sec;
        token_times->endtime    = jwt->exp.tv_sec;
        token_times->renew_till = jwt->exp.tv_sec;
        *result = TRUE;
    }

    cjwt_destroy(&jwt);
    free(defrealm);
    return ret;
}

static KRB5_LIB_CALL krb5_error_code
hcjwt_init(krb5_context context, void **c)
{
    *c = NULL;
    return 0;
}

static KRB5_LIB_CALL void
hcjwt_fini(void *c)
{
}

static krb5plugin_token_validator_ftable plug_desc =
    { 1, hcjwt_init, hcjwt_fini, validate };

static krb5plugin_token_validator_ftable *plugs[] = { &plug_desc };

static uintptr_t
hcjwt_get_instance(const char *libname)
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
    *get_instance = hcjwt_get_instance;
    *num_plugins = sizeof(plugs) / sizeof(plugs[0]);
    *plugins = (krb5_plugin_common_ftable_cp *)plugs;
    return 0;
}
