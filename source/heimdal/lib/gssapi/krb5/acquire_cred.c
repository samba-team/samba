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

#include "krb5/gsskrb5_locl.h"

RCSID("$Id: acquire_cred.c,v 1.31 2006/10/07 22:13:55 lha Exp $");

OM_uint32
__gsskrb5_ccache_lifetime(OM_uint32 *minor_status,
			     krb5_ccache id,
			     krb5_principal principal,
			     OM_uint32 *lifetime)
{
    krb5_creds in_cred, *out_cred;
    krb5_const_realm realm;
    krb5_error_code kret;

    memset(&in_cred, 0, sizeof(in_cred));
    in_cred.client = principal;
	
    realm = krb5_principal_get_realm(_gsskrb5_context,  principal);
    if (realm == NULL) {
	_gsskrb5_clear_status ();
	*minor_status = KRB5_PRINC_NOMATCH; /* XXX */
	return GSS_S_FAILURE;
    }

    kret = krb5_make_principal(_gsskrb5_context, &in_cred.server, 
			       realm, KRB5_TGS_NAME, realm, NULL);
    if (kret) {
	_gsskrb5_set_error_string();
	*minor_status = kret;
	return GSS_S_FAILURE;
    }

    kret = krb5_get_credentials(_gsskrb5_context, 0, 
				id, &in_cred, &out_cred);
    krb5_free_principal(_gsskrb5_context, in_cred.server);
    if (kret) {
	_gsskrb5_set_error_string();
	*minor_status = kret;
	return GSS_S_FAILURE;
    }

    *lifetime = out_cred->times.endtime;
    krb5_free_creds(_gsskrb5_context, out_cred);

    return GSS_S_COMPLETE;
}




static krb5_error_code
get_keytab(krb5_keytab *keytab)
{
    char kt_name[256];
    krb5_error_code kret;

    HEIMDAL_MUTEX_lock(&gssapi_keytab_mutex);

    if (_gsskrb5_keytab != NULL) {
	kret = krb5_kt_get_name(_gsskrb5_context,
				_gsskrb5_keytab,
				kt_name, sizeof(kt_name));
	if (kret == 0)
	    kret = krb5_kt_resolve(_gsskrb5_context, kt_name, keytab);
    } else
	kret = krb5_kt_default(_gsskrb5_context, keytab);

    HEIMDAL_MUTEX_unlock(&gssapi_keytab_mutex);

    return (kret);
}

static OM_uint32 acquire_initiator_cred
		  (OM_uint32 * minor_status,
		   const gss_name_t desired_name,
		   OM_uint32 time_req,
		   const gss_OID_set desired_mechs,
		   gss_cred_usage_t cred_usage,
		   gsskrb5_cred handle,
		   gss_OID_set * actual_mechs,
		   OM_uint32 * time_rec
		  )
{
    OM_uint32 ret;
    krb5_creds cred;
    krb5_principal def_princ;
    krb5_get_init_creds_opt *opt;
    krb5_ccache ccache;
    krb5_keytab keytab;
    krb5_error_code kret;

    keytab = NULL;
    ccache = NULL;
    def_princ = NULL;
    ret = GSS_S_FAILURE;
    memset(&cred, 0, sizeof(cred));

    /* If we have a preferred principal, lets try to find it in all
     * caches, otherwise, fall back to default cache.  Ignore
     * errors. */
    if (handle->principal)
	kret = krb5_cc_cache_match (_gsskrb5_context,
				    handle->principal,
				    NULL,
				    &ccache);
    
    if (ccache == NULL) {
	kret = krb5_cc_default(_gsskrb5_context, &ccache);
	if (kret)
	    goto end;
    }
    kret = krb5_cc_get_principal(_gsskrb5_context, ccache,
	&def_princ);
    if (kret != 0) {
	/* we'll try to use a keytab below */
	krb5_cc_destroy(_gsskrb5_context, ccache);
	ccache = NULL;
	kret = 0;
    } else if (handle->principal == NULL)  {
	kret = krb5_copy_principal(_gsskrb5_context, def_princ,
	    &handle->principal);
	if (kret)
	    goto end;
    } else if (handle->principal != NULL &&
	krb5_principal_compare(_gsskrb5_context, handle->principal,
	def_princ) == FALSE) {
	/* Before failing, lets check the keytab */
	krb5_free_principal(_gsskrb5_context, def_princ);
	def_princ = NULL;
    }
    if (def_princ == NULL) {
	/* We have no existing credentials cache,
	 * so attempt to get a TGT using a keytab.
	 */
	if (handle->principal == NULL) {
	    kret = krb5_get_default_principal(_gsskrb5_context,
		&handle->principal);
	    if (kret)
		goto end;
	}
	kret = get_keytab(&keytab);
	if (kret)
	    goto end;
	kret = krb5_get_init_creds_opt_alloc(_gsskrb5_context, &opt);
	if (kret)
	    goto end;
	kret = krb5_get_init_creds_keytab(_gsskrb5_context, &cred,
	    handle->principal, keytab, 0, NULL, opt);
	krb5_get_init_creds_opt_free(opt);
	if (kret)
	    goto end;
	kret = krb5_cc_gen_new(_gsskrb5_context, &krb5_mcc_ops,
		&ccache);
	if (kret)
	    goto end;
	kret = krb5_cc_initialize(_gsskrb5_context, ccache, cred.client);
	if (kret)
	    goto end;
	kret = krb5_cc_store_cred(_gsskrb5_context, ccache, &cred);
	if (kret)
	    goto end;
	handle->lifetime = cred.times.endtime;
	handle->cred_flags |= GSS_CF_DESTROY_CRED_ON_RELEASE;
    } else {

	ret = __gsskrb5_ccache_lifetime(minor_status,
					   ccache,
					   handle->principal,
					   &handle->lifetime);
	if (ret != GSS_S_COMPLETE)
	    goto end;
	kret = 0;
    }

    handle->ccache = ccache;
    ret = GSS_S_COMPLETE;

end:
    if (cred.client != NULL)
	krb5_free_cred_contents(_gsskrb5_context, &cred);
    if (def_princ != NULL)
	krb5_free_principal(_gsskrb5_context, def_princ);
    if (keytab != NULL)
	krb5_kt_close(_gsskrb5_context, keytab);
    if (ret != GSS_S_COMPLETE) {
	if (ccache != NULL)
	    krb5_cc_close(_gsskrb5_context, ccache);
	if (kret != 0) {
	    *minor_status = kret;
	    _gsskrb5_set_error_string ();
	}
    }
    return (ret);
}

static OM_uint32 acquire_acceptor_cred
		  (OM_uint32 * minor_status,
		   const gss_name_t desired_name,
		   OM_uint32 time_req,
		   const gss_OID_set desired_mechs,
		   gss_cred_usage_t cred_usage,
		   gsskrb5_cred handle,
		   gss_OID_set * actual_mechs,
		   OM_uint32 * time_rec
		  )
{
    OM_uint32 ret;
    krb5_error_code kret;

    kret = 0;
    ret = GSS_S_FAILURE;
    kret = get_keytab(&handle->keytab);
    if (kret)
	goto end;
    
    /* check that the requested principal exists in the keytab */
    if (handle->principal) {
	krb5_keytab_entry entry;

	kret = krb5_kt_get_entry(_gsskrb5_context, handle->keytab, 
				 handle->principal, 0, 0, &entry);
	if (kret)
	    goto end;
	krb5_kt_free_entry(_gsskrb5_context, &entry);
    }
    ret = GSS_S_COMPLETE;
 
end:
    if (ret != GSS_S_COMPLETE) {
	if (handle->keytab != NULL)
	    krb5_kt_close(_gsskrb5_context, handle->keytab);
	if (kret != 0) {
	    *minor_status = kret;
	    _gsskrb5_set_error_string ();
	}
    }
    return (ret);
}

OM_uint32 _gsskrb5_acquire_cred
(OM_uint32 * minor_status,
 const gss_name_t desired_name,
 OM_uint32 time_req,
 const gss_OID_set desired_mechs,
 gss_cred_usage_t cred_usage,
 gss_cred_id_t * output_cred_handle,
 gss_OID_set * actual_mechs,
 OM_uint32 * time_rec
    )
{
    gsskrb5_cred handle;
    OM_uint32 ret;

    if (cred_usage != GSS_C_ACCEPT && cred_usage != GSS_C_INITIATE && cred_usage != GSS_C_BOTH) {
	*minor_status = GSS_KRB5_S_G_BAD_USAGE;
	return GSS_S_FAILURE;
    }

    GSSAPI_KRB5_INIT ();

    *output_cred_handle = NULL;
    if (time_rec)
	*time_rec = 0;
    if (actual_mechs)
	*actual_mechs = GSS_C_NO_OID_SET;

    if (desired_mechs) {
	int present = 0;

	ret = _gsskrb5_test_oid_set_member(minor_status, GSS_KRB5_MECHANISM,
					   desired_mechs, &present); 
	if (ret)
	    return ret;
	if (!present) {
	    *minor_status = 0;
	    return GSS_S_BAD_MECH;
	}
    }

    handle = calloc(1, sizeof(*handle));
    if (handle == NULL) {
	*minor_status = ENOMEM;
        return (GSS_S_FAILURE);
    }

    HEIMDAL_MUTEX_init(&handle->cred_id_mutex);

    if (desired_name != GSS_C_NO_NAME) {
	krb5_principal name = (krb5_principal)desired_name;
	ret = krb5_copy_principal(_gsskrb5_context, name, &handle->principal);
	if (ret) {
	    HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	    _gsskrb5_set_error_string();
	    *minor_status = ret;
	    free(handle);
	    return GSS_S_FAILURE;
	}
    }
    if (cred_usage == GSS_C_INITIATE || cred_usage == GSS_C_BOTH) {
	ret = acquire_initiator_cred(minor_status, desired_name, time_req,
				     desired_mechs, cred_usage, handle, actual_mechs, time_rec);
    	if (ret != GSS_S_COMPLETE) {
	    HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	    krb5_free_principal(_gsskrb5_context, handle->principal);
	    free(handle);
	    return (ret);
	}
    }
    if (cred_usage == GSS_C_ACCEPT || cred_usage == GSS_C_BOTH) {
	ret = acquire_acceptor_cred(minor_status, desired_name, time_req,
				    desired_mechs, cred_usage, handle, actual_mechs, time_rec);
	if (ret != GSS_S_COMPLETE) {
	    HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	    krb5_free_principal(_gsskrb5_context, handle->principal);
	    free(handle);
	    return (ret);
	}
    }
    ret = _gsskrb5_create_empty_oid_set(minor_status, &handle->mechanisms);
    if (ret == GSS_S_COMPLETE)
    	ret = _gsskrb5_add_oid_set_member(minor_status, GSS_KRB5_MECHANISM,
					  &handle->mechanisms);
    if (ret == GSS_S_COMPLETE)
    	ret = _gsskrb5_inquire_cred(minor_status, (gss_cred_id_t)handle, 
				    NULL, time_rec, NULL, actual_mechs);
    if (ret != GSS_S_COMPLETE) {
	if (handle->mechanisms != NULL)
	    _gsskrb5_release_oid_set(NULL, &handle->mechanisms);
	HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	krb5_free_principal(_gsskrb5_context, handle->principal);
	free(handle);
	return (ret);
    } 
    *minor_status = 0;
    if (time_rec) {
	ret = _gsskrb5_lifetime_left(minor_status,
				   handle->lifetime,
				   time_rec);

	if (ret)
	    return ret;
    }
    handle->usage = cred_usage;
    *output_cred_handle = (gss_cred_id_t)handle;
    return (GSS_S_COMPLETE);
}
