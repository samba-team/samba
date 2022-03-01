/*
 * Copyright (c) 2003 Kungliga Tekniska Högskolan
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

#include "gsskrb5_locl.h"

static int
same_princ(krb5_context context, krb5_ccache id1, krb5_ccache id2)
{
    krb5_error_code ret;
    krb5_principal p1 = NULL;
    krb5_principal p2 = NULL;
    int same = 0;

    ret = krb5_cc_get_principal(context, id1, &p1);
    if (ret == 0)
        ret = krb5_cc_get_principal(context, id2, &p2);
    /* If either principal is absent, it's the same for our purposes */
    same = ret ? 1 : krb5_principal_compare(context, p1, p2);
    krb5_free_principal(context, p1);
    krb5_free_principal(context, p2);
    return same;
}

static OM_uint32
add_env(OM_uint32 *minor,
        gss_buffer_set_t *env,
        const char *var,
        const char *val)
{
    OM_uint32 major;
    gss_buffer_desc b;
    char *varval = NULL;

    if (asprintf(&varval, "%s=%s", var, val) == -1 || varval == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    b.value = varval;
    b.length = strlen(varval) + 1;
    major = gss_add_buffer_set_member(minor, &b, env);
    free(varval);
    return major;
}

static OM_uint32
set_proc(OM_uint32 *minor, gss_buffer_set_t env)
{
    /*
     * XXX On systems with setpag(), call setpag().  On WIN32... create a
     * session, set the access token, ...?
     */
#ifndef WIN32
    size_t i;

    for (i = 0; i < env->count; i++)
        putenv(env->elements[i].value);
#endif
    return GSS_S_COMPLETE;
}

/*
 * A principal is the best principal for a user IFF
 *
 *  - it has one component
 *  - the one component is the same as the user's name
 *  - the real is the user_realm from configuration
 */
static int
principal_is_best_for_user(krb5_context context,
                           const char *app,
                           krb5_const_principal p,
                           const char *user)
{
    char *default_realm = NULL;
    char *user_realm = NULL;
    int ret;

    (void) krb5_get_default_realm(context, &default_realm);
    krb5_appdefault_string(context, app, NULL, "user_realm", default_realm,
                           &user_realm);
    ret = user_realm &&
        krb5_principal_get_num_comp(context, p) == 1 &&
        strcmp(user_realm, krb5_principal_get_realm(context, p)) == 0 &&
        (!user ||
         strcmp(user, krb5_principal_get_comp_string(context, p, 0)) == 0);
    free(default_realm);
    free(user_realm);
    return ret;
}

static krb5_error_code
check_destination_tgt_policy(krb5_context context,
                             const char *appname,
                             gsskrb5_cred input_cred)
{
    krb5_error_code ret;
    krb5_boolean want_dst_tgt = 0;
    krb5_data v;

    if (input_cred->destination_realm == NULL)
        /*
         * Not a delegated credential, so we can't check the destination TGT
         * policy for the realm of the service -- we don't know the realm of
         * the service.
         */
        return 0;

    krb5_appdefault_boolean(context, appname, input_cred->destination_realm,
                            "require_delegate_destination_tgt", FALSE,
                            &want_dst_tgt);
    if (!want_dst_tgt)
        return 0;

    krb5_data_zero(&v);
    ret = krb5_cc_get_config(context, input_cred->ccache, NULL,
                             "start_realm", &v);
    if (ret == 0 &&
        v.length != strlen(input_cred->destination_realm))
        ret = KRB5_CC_NOTFOUND;
    if (ret == 0 &&
        strncmp(input_cred->destination_realm, v.data, v.length) != 0)
        ret = KRB5_CC_NOTFOUND;
    if (ret)
        krb5_set_error_message(context, ret,
                               "Delegated TGT is not a destination TGT for "
                               "realm \"%s\" but for \"%.*s\"",
                               input_cred->destination_realm,
                               (int)(v.length ? v.length : sizeof("<UNKNOWN>") - 1),
                               v.data ? (const char *)v.data : "<UNKNOWN>");
    krb5_data_free(&v);
    return ret;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_store_cred_into2(OM_uint32         *minor_status,
			  gss_const_cred_id_t input_cred_handle,
			  gss_cred_usage_t  cred_usage,
			  const gss_OID     desired_mech,
			  OM_uint32         store_cred_flags,
			  gss_const_key_value_set_t cred_store,
			  gss_OID_set       *elements_stored,
			  gss_cred_usage_t  *cred_usage_stored,
                          gss_buffer_set_t  *envp)
{
    krb5_context context;
    krb5_error_code ret;
    gsskrb5_cred input_cred;
    krb5_ccache id = NULL;
    time_t exp_current;
    time_t exp_new;
    gss_buffer_set_t env = GSS_C_NO_BUFFER_SET;
    const char *cs_unique_ccache = NULL;
    const char *cs_ccache_name = NULL;
    const char *cs_user_name = NULL;
    const char *cs_app_name = NULL;
    char *ccache_name = NULL;
    OM_uint32 major_status = GSS_S_FAILURE;
    OM_uint32 junk;
    OM_uint32 overwrite_cred = store_cred_flags & GSS_C_STORE_CRED_OVERWRITE;
    int default_for = 0;

    *minor_status = 0;

    /* Sanity check inputs */
    if (cred_usage != GSS_C_INITIATE) {
        /* It'd be nice if we could also do accept, writing a keytab */
	*minor_status = GSS_KRB5_S_G_BAD_USAGE;
	return GSS_S_FAILURE;
    }
    if (desired_mech != GSS_C_NO_OID &&
        gss_oid_equal(desired_mech, GSS_KRB5_MECHANISM) == 0)
	return GSS_S_BAD_MECH;
    if (input_cred_handle == GSS_C_NO_CREDENTIAL)
	return GSS_S_CALL_INACCESSIBLE_READ;
    input_cred = (gsskrb5_cred)input_cred_handle;

    /* Sanity check the input_cred */
    if (input_cred->usage != cred_usage && input_cred->usage != GSS_C_BOTH) {
	*minor_status = GSS_KRB5_S_G_BAD_USAGE;
	return GSS_S_NO_CRED;
    }
    if (input_cred->principal == NULL) {
	*minor_status = GSS_KRB5_S_KG_TGT_MISSING;
	return GSS_S_NO_CRED;
    }

    /* Extract the ccache name from the store if given */
    if (cred_store != GSS_C_NO_CRED_STORE) {
	major_status = __gsskrb5_cred_store_find(minor_status, cred_store,
                                                 "unique_ccache_type",
                                                 &cs_unique_ccache);
	if (GSS_ERROR(major_status))
	    return major_status;
	major_status = __gsskrb5_cred_store_find(minor_status, cred_store,
						 "ccache", &cs_ccache_name);
	if (GSS_ERROR(major_status))
	    return major_status;
	major_status = __gsskrb5_cred_store_find(minor_status, cred_store,
						 "username", &cs_user_name);
	if (GSS_ERROR(major_status))
	    return major_status;
	major_status = __gsskrb5_cred_store_find(minor_status, cred_store,
						 "appname", &cs_app_name);
	if (GSS_ERROR(major_status))
	    return major_status;
    }

    GSSAPI_KRB5_INIT (&context);
    HEIMDAL_MUTEX_lock(&input_cred->cred_id_mutex);

    if (cs_ccache_name && strchr(cs_ccache_name, '%')) {
        ret = _krb5_expand_default_cc_name(context, cs_ccache_name,
                                           &ccache_name);
        if (ret) {
            HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
            *minor_status = ret;
            return GSS_S_FAILURE;
        }
        cs_ccache_name = ccache_name;
    }

    /* More sanity checking of the input_cred (good to fail early) */
    ret = krb5_cc_get_lifetime(context, input_cred->ccache, &exp_new);
    if (ret) {
	HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	*minor_status = ret;
        free(ccache_name);
	return GSS_S_NO_CRED;
    }

    ret = check_destination_tgt_policy(context, cs_app_name, input_cred);
    if (ret) {
	HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	*minor_status = ret;
        free(ccache_name);
	return GSS_S_NO_CRED;
    }

    /*
     * Find an appropriate ccache, which will be one of:
     *
     *  - the one given in the cred_store, if given
     *  - a new unique one for some ccache type in the cred_store, if given
     *  - a subsidiary cache named for the principal in the default collection,
     *    if the principal is the "best principal for the user"
     *  - the default ccache
     */
    if (cs_ccache_name) {
        ret = krb5_cc_resolve(context, cs_ccache_name, &id);
    } else if (cs_unique_ccache) {
        overwrite_cred = 1;
        ret = krb5_cc_new_unique(context, cs_unique_ccache, NULL, &id);
    } else if (principal_is_best_for_user(context, cs_app_name,
                                          input_cred->principal,
                                          cs_user_name)) {
        ret = krb5_cc_default(context, &id);
        if (ret == 0 && !same_princ(context, id, input_cred->ccache)) {
            krb5_cc_close(context, id);
            ret = krb5_cc_default_for(context, input_cred->principal, &id);
            default_for = 1;
        }
    } else {
        ret = krb5_cc_default_for(context, input_cred->principal, &id);
        default_for = 1;
    }

    if (ret || id == NULL) {
	HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
	*minor_status = ret;
        free(ccache_name);
	return ret == 0 ? GSS_S_NO_CRED : GSS_S_FAILURE;
    }

    /*
     * If we're using a subsidiary ccache for this principal and it has some
     * other principal's tickets in it -> overwrite.
     */
    if (!overwrite_cred && default_for &&
        !same_princ(context, id, input_cred->ccache))
        overwrite_cred = 1;
    if (!overwrite_cred && same_princ(context, id, input_cred->ccache)) {
        /*
         * If current creds are for the same princ as we already had creds for,
         * and the new creds live longer than the old, overwrite.
         */
        ret = krb5_cc_get_lifetime(context, id, &exp_current);
        if (ret != 0 || exp_new > exp_current)
            overwrite_cred = 1;
    }

    if (overwrite_cred) {
        ret = krb5_cc_initialize(context, id, input_cred->principal);
        if (ret == 0)
            ret = krb5_cc_copy_match_f(context, input_cred->ccache, id, NULL, NULL,
                                       NULL);
    }

    if ((store_cred_flags & GSS_C_STORE_CRED_SET_PROCESS) && envp == NULL)
        envp = &env;
    if (envp != NULL) {
        char *fullname = NULL;
        
        if ((ret = krb5_cc_get_full_name(context, id, &fullname)) == 0) {
            major_status = add_env(minor_status, envp, "KRB5CCNAME", fullname);
            free(fullname);
            if (major_status)
                ret = *minor_status;
        }
    }
    (void) krb5_cc_close(context, id);

    HEIMDAL_MUTEX_unlock(&input_cred->cred_id_mutex);
    if (ret == 0 && (store_cred_flags & GSS_C_STORE_CRED_SET_PROCESS) &&
        (major_status = set_proc(minor_status, *envp)) != GSS_S_COMPLETE)
        ret = *minor_status;
    (void) gss_release_buffer_set(&junk, &env);
    free(ccache_name);
    *minor_status = ret;
    return ret ? major_status : GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_store_cred_into(OM_uint32         *minor_status,
			 gss_const_cred_id_t input_cred_handle,
			 gss_cred_usage_t  cred_usage,
			 const gss_OID     desired_mech,
			 OM_uint32         overwrite_cred,
			 OM_uint32         default_cred,
			 gss_const_key_value_set_t cred_store,
			 gss_OID_set       *elements_stored,
			 gss_cred_usage_t  *cred_usage_stored)
{
    OM_uint32 store_cred_flags =
        (overwrite_cred ? GSS_C_STORE_CRED_OVERWRITE : 0) |
        (default_cred ? GSS_C_STORE_CRED_DEFAULT : 0);

    return _gsskrb5_store_cred_into2(minor_status, input_cred_handle,
                                     cred_usage, desired_mech,
                                     store_cred_flags, cred_store,
                                     elements_stored, cred_usage_stored, NULL);
}
