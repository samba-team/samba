/*
 * Copyright (c) 1997 - 2005 Kungliga Tekniska Högskolan
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

/*
 * Find an element in a cred store. Returns GSS_S_COMPLETE if the cred store
 * is absent or well formed, irrespective of whether the element exists. The
 * caller should check for *value != NULL before using; values are typically
 * optional, hence this behavior. (The caller should validate the return
 * value at least once though, to check it is well-formed.)
 */
OM_uint32
__gsskrb5_cred_store_find(OM_uint32 *minor_status,
			  gss_const_key_value_set_t cred_store,
			  const char *key,
			  const char **value)
{
    size_t i;

    *value = NULL;

    if (cred_store == GSS_C_NO_CRED_STORE)
	return GSS_S_COMPLETE;
    else if (cred_store->count == 0) {
	*minor_status = GSS_KRB5_S_G_BAD_USAGE;
	return GSS_S_NO_CRED;
    }

    for (i = 0; i < cred_store->count; i++) {
	if (strcmp(key, cred_store->elements[i].key) == 0) {
	    if (*value) {
		*value = NULL;
		*minor_status = GSS_KRB5_S_G_BAD_USAGE;
		return GSS_S_DUPLICATE_ELEMENT;
	    }
	    *value = cred_store->elements[i].value;
	}
    }

    return GSS_S_COMPLETE;
}

OM_uint32
__gsskrb5_ccache_lifetime(OM_uint32 *minor_status,
			  krb5_context context,
			  krb5_ccache id,
			  krb5_principal principal,
			  OM_uint32 *lifetime)
{
    krb5_error_code kret;
    time_t left;

    kret = krb5_cc_get_lifetime(context, id, &left);
    if (kret) {
        *minor_status = kret;
        return GSS_S_FAILURE;
    }

    *lifetime = left;

    return GSS_S_COMPLETE;
}




static krb5_error_code
get_system_keytab(krb5_context context,
		  gss_const_key_value_set_t cred_store,
		  krb5_keytab *keytab)
{
    krb5_error_code kret;
    const char *cs_ktname;
    OM_uint32 tmp;

    __gsskrb5_cred_store_find(&tmp, cred_store, "keytab", &cs_ktname);

    HEIMDAL_MUTEX_lock(&gssapi_keytab_mutex);

    if (cs_ktname)
	kret = krb5_kt_resolve(context, cs_ktname, keytab);
    else if (_gsskrb5_keytab != NULL) {
	char *name = NULL;

	kret = krb5_kt_get_full_name(context, _gsskrb5_keytab, &name);
	if (kret == 0) {
	    kret = krb5_kt_resolve(context, name, keytab);
	    krb5_xfree(name);
	}
    } else
	kret = krb5_kt_default(context, keytab);

    HEIMDAL_MUTEX_unlock(&gssapi_keytab_mutex);

    return (kret);
}

static krb5_error_code
get_client_keytab(krb5_context context,
		  gss_const_key_value_set_t cred_store,
		  krb5_const_principal principal,
		  krb5_keytab *keytab)
{
    krb5_error_code ret;
    const char *cs_ktname;
    OM_uint32 tmp;

    __gsskrb5_cred_store_find(&tmp, cred_store, "client_keytab", &cs_ktname);

    if (cs_ktname)
	ret = krb5_kt_resolve(context, cs_ktname, keytab);
    else {
	char *name = NULL;
	ret = _krb5_kt_client_default_name(context, &name);
	if (ret == 0)
	    ret = krb5_kt_resolve(context, name, keytab);
	krb5_xfree(name);
    }

    if (ret == 0 && principal) {
	krb5_keytab_entry entry;

	ret = krb5_kt_get_entry(context, *keytab, principal,
				 0, 0, &entry);
	if (ret == 0)
	    krb5_kt_free_entry(context, &entry);
    }

    if (ret) {
	if (*keytab) {
	    krb5_kt_close(context, *keytab);
	    *keytab = NULL;
	}

	ret = get_system_keytab(context, GSS_C_NO_CRED_STORE, keytab);
    }

    return ret;
}

static krb5_boolean
is_valid_password_cred_store(gss_const_key_value_set_t cred_store)
{
    size_t i;

    if (cred_store == GSS_C_NO_CRED_STORE)
	return TRUE;

    /* XXX don't check keytab, someday we will allow password+acceptor creds */
    for (i = 0; i < cred_store->count; i++) {
	if (strcmp(cred_store->elements[i].key, "ccache") == 0 ||
	    strcmp(cred_store->elements[i].key, "client_keytab") == 0)
	    return FALSE;
    }

    return TRUE;
}

/*
 * This function produces a cred with a MEMORY ccache containing a TGT
 * acquired with a password.
 */
static OM_uint32
acquire_cred_with_password(OM_uint32 *minor_status,
                           krb5_context context,
                           const char *password,
                           OM_uint32 time_req,
                           gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           gss_const_key_value_set_t cred_store,
                           gsskrb5_cred handle)
{
    OM_uint32 ret = GSS_S_FAILURE;
    krb5_creds cred;
    krb5_init_creds_context ctx = NULL;
    krb5_get_init_creds_opt *opt = NULL;
    krb5_ccache ccache = NULL;
    krb5_error_code kret;
    time_t now;
    OM_uint32 left;
    const char *realm;

    if (!is_valid_password_cred_store(cred_store)) {
	*minor_status = GSS_KRB5_S_G_BAD_PASSWORD_CRED_STORE;
	return GSS_S_NO_CRED;
    }

    if (cred_usage == GSS_C_ACCEPT) {
        /*
         * TODO: Here we should eventually support user2user (when we get
         *       support for that via an extension to the mechanism
         *       allowing for more than two security context tokens),
         *       and/or new unique MEMORY keytabs (we have MEMORY keytab
         *       support, but we don't have a keytab equivalent of
         *       krb5_cc_new_unique()).  Either way, for now we can't
         *       support this.
         */
        *minor_status = ENOTSUP; /* XXX Better error? */
        return GSS_S_FAILURE;
    }

    memset(&cred, 0, sizeof(cred));

    if (handle->principal == NULL) {
        kret = krb5_get_default_principal(context, &handle->principal);
        if (kret)
            goto end;
    }
    realm = krb5_principal_get_realm(context, handle->principal);

    kret = krb5_get_init_creds_opt_alloc(context, &opt);
    if (kret == 0) {
        krb5_get_init_creds_opt_set_default_flags(context, "gss_krb5", realm,
                                                  opt);
        kret = krb5_init_creds_init(context, handle->principal, NULL, NULL, 0,
                                    opt, &ctx);
    }
    if (kret == 0)
        kret = _krb5_init_creds_set_fast_anon_pkinit_optimistic(context, ctx);
    if (kret == 0)
        kret = krb5_init_creds_set_password(context, ctx, password);

    /*
     * Get the current time before the AS exchange so we don't
     * accidentally end up returning a value that puts advertised
     * expiration past the real expiration.
     *
     * We need to do this because krb5_cc_get_lifetime() returns a
     * relative time that we need to add to the current time.  We ought
     * to have a version of krb5_cc_get_lifetime() that returns absolute
     * time...
     */
    krb5_timeofday(context, &now);

    if (kret == 0)
        kret = krb5_init_creds_get(context, ctx);
    if (kret == 0)
        kret = krb5_init_creds_get_creds(context, ctx, &cred);
    if (kret == 0)
        kret = krb5_cc_new_unique(context, krb5_cc_type_memory, NULL, &ccache);
    if (kret == 0)
        kret = krb5_cc_initialize(context, ccache, cred.client);
    if (kret == 0)
        kret = krb5_init_creds_store(context, ctx, ccache);
    if (kret == 0)
        kret = krb5_cc_store_cred(context, ccache, &cred);
    if (kret)
        goto end;

    handle->cred_flags |= GSS_CF_DESTROY_CRED_ON_RELEASE;

    ret = __gsskrb5_ccache_lifetime(minor_status, context, ccache,
                                    handle->principal, &left);
    if (ret != GSS_S_COMPLETE)
        goto end;
    handle->endtime = now + left;
    handle->ccache = ccache;
    ccache = NULL;
    ret = GSS_S_COMPLETE;

end:
    krb5_get_init_creds_opt_free(context, opt);
    if (ctx)
        krb5_init_creds_free(context, ctx);
    if (ccache != NULL)
        krb5_cc_destroy(context, ccache);
    if (cred.client != NULL)
	krb5_free_cred_contents(context, &cred);
    if (ret != GSS_S_COMPLETE)
	*minor_status = kret;
    return (ret);
}

/*
 * Acquires an initiator credential from a ccache or using a keytab.
 */
static OM_uint32
acquire_initiator_cred(OM_uint32 *minor_status,
                       krb5_context context,
                       OM_uint32 time_req,
                       gss_OID_set desired_mechs,
                       gss_cred_usage_t cred_usage,
                       gss_const_key_value_set_t cred_store,
                       gsskrb5_cred handle)
{
    OM_uint32 ret;
    krb5_creds cred;
    krb5_get_init_creds_opt *opt;
    krb5_principal def_princ = NULL;
    krb5_ccache def_ccache = NULL;
    krb5_ccache ccache = NULL;  /* we may store into this ccache */
    krb5_keytab keytab = NULL;
    krb5_error_code kret = 0;
    OM_uint32 left;
    const char *cs_ccache_name;
    time_t lifetime = 0;
    time_t now;

    memset(&cred, 0, sizeof(cred));

    ret = __gsskrb5_cred_store_find(minor_status, cred_store,
				    "ccache", &cs_ccache_name);
    if (GSS_ERROR(ret))
	return ret;

    ret = GSS_S_FAILURE;

    /*
     * Get current time early so we can set handle->endtime to a value that
     * cannot accidentally be past the real endtime.  We need a variant of
     * krb5_cc_get_lifetime() that returns absolute endtime.
     */
    krb5_timeofday(context, &now);

    /*
     * First look for a ccache that has the desired_name (which may be
     * the default credential name), unless a specific credential cache
     * was included in cred_store.
     *
     * If we don't have an unexpired credential, acquire one with a
     * keytab.
     *
     * If we acquire one with a keytab, save it in the ccache we found
     * with the expired credential, if any.
     *
     * If we don't have any such ccache, then use a MEMORY ccache.
     */

    if (handle->principal != NULL && cs_ccache_name == NULL) {
        /*
         * Not default credential case.  See if we can find a ccache in
         * the cccol for the desired_name.
         */
	kret = krb5_cc_cache_match(context,
				   handle->principal,
				   &ccache);
	if (kret == 0) {
            kret = krb5_cc_get_lifetime(context, ccache, &lifetime);
            if (kret == 0) {
                if (lifetime > 0)
                    goto found;
                else
                    goto try_keytab;
            }
	}
        /*
         * Fall through.  We shouldn't find this in the default ccache
         * either, but we'll give it a try, then we'll try using a keytab.
         */
    }

    /*
     * Either desired_name was GSS_C_NO_NAME (default cred) or
     * krb5_cc_cache_match() failed (or found expired).
     */
    if (cs_ccache_name)
	kret = krb5_cc_resolve(context, cs_ccache_name, &def_ccache);
    else
	kret = krb5_cc_default(context, &def_ccache);
    if (kret != 0)
        goto try_keytab;
    kret = krb5_cc_get_lifetime(context, def_ccache, &lifetime);
    if (kret != 0)
        lifetime = 0;
    kret = krb5_cc_get_principal(context, def_ccache, &def_princ);
    if (kret != 0)
        goto try_keytab;
    /*
     * Have a default ccache; see if it matches desired_name.
     */
    if (handle->principal == NULL ||
        krb5_principal_compare(context, handle->principal,
                               def_princ) == TRUE) {
        /*
         * It matches.
         *
         * If we end up trying a keytab then we can write the result to
         * the default ccache.
         */
        if (handle->principal == NULL) {
            kret = krb5_copy_principal(context, def_princ, &handle->principal);
            if (kret)
                goto end;
        }
        if (ccache != NULL)
            krb5_cc_close(context, ccache);
        ccache = def_ccache;
        def_ccache = NULL;
        if (lifetime > 0)
            goto found;
        /* else we fall through and try using a keytab */
    }

try_keytab:
    if (handle->principal == NULL) {
        /* We need to know what client principal to use */
        kret = krb5_get_default_principal(context, &handle->principal);
        if (kret)
            goto end;
    }
    kret = get_client_keytab(context, cred_store, handle->principal, &keytab);
    if (kret)
        goto end;

    kret = krb5_get_init_creds_opt_alloc(context, &opt);
    if (kret)
        goto end;
    krb5_timeofday(context, &now);
    kret = krb5_get_init_creds_keytab(context, &cred, handle->principal,
                                      keytab, 0, NULL, opt);
    krb5_get_init_creds_opt_free(context, opt);
    if (kret)
        goto end;

    /*
     * We got a credential with a keytab.  Save it if we can.
     */
    if (ccache == NULL) {
        /*
         * There's no ccache we can overwrite with the credentials we acquired
         * with a keytab.  We'll use a MEMORY ccache then.
         *
         * Note that an application that falls into this repeatedly will do an
         * AS exchange every time it acquires a credential handle.  Hopefully
         * this doesn't happen much.  A workaround is to kinit -k once so that
         * we always re-initialize the matched/default ccache here.  I.e., once
         * there's a FILE/DIR ccache, we'll keep it frash automatically if we
         * have a keytab, but if there's no FILE/DIR ccache, then we'll
         * get a fresh credential *every* time we're asked.
         */
        kret = krb5_cc_new_unique(context, krb5_cc_type_memory, NULL, &ccache);
        if (kret)
            goto end;
        handle->cred_flags |= GSS_CF_DESTROY_CRED_ON_RELEASE;
    } /* else we'll re-initialize whichever ccache we matched above */

    kret = krb5_cc_initialize(context, ccache, cred.client);
    if (kret)
        goto end;
    kret = krb5_cc_store_cred(context, ccache, &cred);
    if (kret)
        goto end;

found:
    assert(handle->principal != NULL);
    ret = __gsskrb5_ccache_lifetime(minor_status, context, ccache,
                                    handle->principal, &left);
    if (ret != GSS_S_COMPLETE)
        goto end;
    handle->endtime = now + left;
    handle->ccache = ccache;
    ccache = NULL;
    ret = GSS_S_COMPLETE;
    kret = 0;

end:
    if (ccache != NULL) {
        if ((handle->cred_flags & GSS_CF_DESTROY_CRED_ON_RELEASE) != 0)
            krb5_cc_destroy(context, ccache);
        else
            krb5_cc_close(context, ccache);
    }
    if (def_ccache != NULL)
        krb5_cc_close(context, def_ccache);
    if (cred.client != NULL)
	krb5_free_cred_contents(context, &cred);
    if (def_princ != NULL)
	krb5_free_principal(context, def_princ);
    if (keytab != NULL)
	krb5_kt_close(context, keytab);
    if (ret != GSS_S_COMPLETE && kret != 0)
	*minor_status = kret;
    return (ret);
}

static OM_uint32
acquire_acceptor_cred(OM_uint32 * minor_status,
                      krb5_context context,
                      OM_uint32 time_req,
                      gss_OID_set desired_mechs,
                      gss_cred_usage_t cred_usage,
                      gss_const_key_value_set_t cred_store,
                      gsskrb5_cred handle)
{
    OM_uint32 ret;
    krb5_error_code kret;

    ret = GSS_S_FAILURE;

    kret = get_system_keytab(context, cred_store, &handle->keytab);
    if (kret)
	goto end;

    /* check that the requested principal exists in the keytab */
    if (handle->principal) {
	krb5_keytab_entry entry;

	kret = krb5_kt_get_entry(context, handle->keytab,
				 handle->principal, 0, 0, &entry);
	if (kret)
	    goto end;
	krb5_kt_free_entry(context, &entry);
	ret = GSS_S_COMPLETE;
    } else {
	/*
	 * Check if there is at least one entry in the keytab before
	 * declaring it as an useful keytab.
	 */
	krb5_keytab_entry tmp;
	krb5_kt_cursor c;

	kret = krb5_kt_start_seq_get (context, handle->keytab, &c);
	if (kret)
	    goto end;
	if (krb5_kt_next_entry(context, handle->keytab, &tmp, &c) == 0) {
	    krb5_kt_free_entry(context, &tmp);
	    ret = GSS_S_COMPLETE; /* ok found one entry */
	}
	krb5_kt_end_seq_get (context, handle->keytab, &c);
    }
end:
    if (ret != GSS_S_COMPLETE) {
	if (handle->keytab != NULL)
	    krb5_kt_close(context, handle->keytab);
	if (kret != 0) {
	    *minor_status = kret;
	}
    }
    return (ret);
}


OM_uint32 GSSAPI_CALLCONV _gsskrb5_acquire_cred_from
(OM_uint32 * minor_status,
 gss_const_name_t desired_name,
 OM_uint32 time_req,
 gss_OID_set desired_mechs,
 gss_cred_usage_t cred_usage,
 gss_const_key_value_set_t cred_store,
 gss_cred_id_t * output_cred_handle,
 gss_OID_set *actual_mechs,
 OM_uint32 *time_rec
    )
{
    krb5_context context;
    gsskrb5_cred handle;
    OM_uint32 ret;
    const char *password = NULL;

    if (desired_mechs) {
	int present = 0;

	ret = gss_test_oid_set_member(minor_status, GSS_KRB5_MECHANISM,
				      desired_mechs, &present);
	if (ret)
	    return ret;
	if (!present) {
	    *minor_status = 0;
	    return GSS_S_BAD_MECH;
	}
    }

    cred_usage &= GSS_C_OPTION_MASK;

    if (cred_usage != GSS_C_ACCEPT && cred_usage != GSS_C_INITIATE &&
        cred_usage != GSS_C_BOTH) {
	*minor_status = GSS_KRB5_S_G_BAD_USAGE;
	return GSS_S_FAILURE;
    }

    ret = __gsskrb5_cred_store_find(minor_status, cred_store,
				    "password", &password);
    if (GSS_ERROR(ret))
	return ret;

    GSSAPI_KRB5_INIT(&context);

    *output_cred_handle = GSS_C_NO_CREDENTIAL;

    handle = calloc(1, sizeof(*handle));
    if (handle == NULL) {
	*minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    handle->destination_realm = NULL;
    HEIMDAL_MUTEX_init(&handle->cred_id_mutex);

    if (desired_name != GSS_C_NO_NAME) {
	ret = _gsskrb5_canon_name(minor_status, context,
				  desired_name, &handle->principal);
	if (ret) {
	    HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	    free(handle);
	    return ret;
	}
    }

    if (password) {
        ret = acquire_cred_with_password(minor_status, context, password, time_req,
                                         desired_mechs, cred_usage, cred_store, handle);
        if (ret != GSS_S_COMPLETE) {
            HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
            krb5_free_principal(context, handle->principal);
            free(handle);
            return (ret);
        }
    } else {
        /*
         * Acquire a credential from the specified or background credential
         * store (ccache, keytab).
         */
        if (cred_usage == GSS_C_INITIATE || cred_usage == GSS_C_BOTH) {
            ret = acquire_initiator_cred(minor_status, context, time_req,
                                         desired_mechs, cred_usage,
					 cred_store, handle);
            if (ret != GSS_S_COMPLETE) {
                HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
                krb5_free_principal(context, handle->principal);
                free(handle);
                return (ret);
            }
        }
        if (cred_usage == GSS_C_ACCEPT || cred_usage == GSS_C_BOTH) {
            ret = acquire_acceptor_cred(minor_status, context, time_req,
                                        desired_mechs, cred_usage,
					cred_store, handle);
            if (ret != GSS_S_COMPLETE) {
                HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
                krb5_free_principal(context, handle->principal);
                free(handle);
                return (ret);
            }
        }
    }
    ret = gss_create_empty_oid_set(minor_status, &handle->mechanisms);
    if (ret == GSS_S_COMPLETE)
    	ret = gss_add_oid_set_member(minor_status, GSS_KRB5_MECHANISM,
				     &handle->mechanisms);
    handle->usage = cred_usage;
    if (ret == GSS_S_COMPLETE)
	ret = _gsskrb5_inquire_cred(minor_status, (gss_cred_id_t)handle,
				    NULL, time_rec, NULL, actual_mechs);
    if (ret != GSS_S_COMPLETE) {
	if (handle->mechanisms != NULL)
	    gss_release_oid_set(NULL, &handle->mechanisms);
	HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	krb5_free_principal(context, handle->principal);
	free(handle);
	return (ret);
    }
    *minor_status = 0;
    *output_cred_handle = (gss_cred_id_t)handle;
    return (GSS_S_COMPLETE);
}
