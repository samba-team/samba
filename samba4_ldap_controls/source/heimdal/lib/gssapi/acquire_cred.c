/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

#include "gssapi_locl.h"

RCSID("$Id: acquire_cred.c,v 1.22 2005/01/05 02:32:26 lukeh Exp $");

static krb5_error_code
get_keytab(krb5_context context, krb5_keytab *keytab)
{
    char kt_name[256];
    krb5_error_code kret;

    HEIMDAL_MUTEX_lock(&gssapi_keytab_mutex);

    if (gssapi_krb5_keytab != NULL) {
	kret = krb5_kt_get_name(context,
				gssapi_krb5_keytab,
				kt_name, sizeof(kt_name));
	if (kret == 0)
	    kret = krb5_kt_resolve(context, kt_name, keytab);
    } else
	kret = krb5_kt_default(context, keytab);

    HEIMDAL_MUTEX_unlock(&gssapi_keytab_mutex);

    return (kret);
}

static OM_uint32 acquire_initiator_cred
		  (OM_uint32 * minor_status,
		   krb5_context context,
		   krb5_keytab keytab,
		   krb5_ccache ccache,
		   const gss_name_t desired_name,
		   OM_uint32 time_req,
		   const gss_OID_set desired_mechs,
		   gss_cred_usage_t cred_usage,
		   gss_cred_id_t handle,
		   gss_OID_set * actual_mechs,
		   OM_uint32 * time_rec
		  )
{
    OM_uint32 ret;
    krb5_creds cred;
    krb5_principal def_princ;
    krb5_get_init_creds_opt *opt;
    krb5_error_code kret;
    krb5_boolean made_ccache = FALSE;
    krb5_boolean made_keytab = FALSE;

    def_princ = NULL;
    ret = GSS_S_FAILURE;
    memset(&cred, 0, sizeof(cred));

    if (ccache == NULL) {
	kret = krb5_cc_default(context, &ccache);
        if (kret)
	    goto end;
        made_ccache = TRUE;
    }
    kret = krb5_cc_get_principal(context, ccache,
	&def_princ);
    if (kret != 0) {
	/* we'll try to use a keytab below */
	krb5_cc_destroy(context, ccache);
	made_ccache = FALSE;
	ccache = NULL;
	kret = 0;
    } else if (handle->principal == NULL)  {
	kret = krb5_copy_principal(context, def_princ,
	    &handle->principal);
	if (kret)
	    goto end;
    } else if (handle->principal != NULL &&
	krb5_principal_compare(context, handle->principal,
	def_princ) == FALSE) {
	/* Before failing, lets check the keytab */
	krb5_free_principal(context, def_princ);
	def_princ = NULL;
    }
    if (def_princ == NULL) {
	/* We have no existing credentials cache,
	 * so attempt to get a TGT using a keytab.
	 */
	if (handle->principal == NULL) {
	    kret = krb5_get_default_principal(context,
		&handle->principal);
	    if (kret)
		goto end;
	}
	if (keytab != NULL) {
	    kret = get_keytab(context, &keytab);
	    if (kret)
	        goto end;
            made_keytab = TRUE;
	}
	kret = krb5_get_init_creds_opt_alloc(context, &opt);
	if (kret)
	    goto end;
	kret = krb5_get_init_creds_keytab(context, &cred,
	    handle->principal, keytab, 0, NULL, opt);
	krb5_get_init_creds_opt_free(opt);
	if (kret)
	    goto end;
	if (ccache == NULL) {
	    kret = krb5_cc_gen_new(context, &krb5_mcc_ops,
				   &ccache);
	    if (kret)
	        goto end;
            made_ccache = TRUE;
	}
	kret = krb5_cc_initialize(context, ccache, cred.client);
	if (kret)
	    goto end;
	kret = krb5_cc_store_cred(context, ccache, &cred);
	if (kret)
	    goto end;
	handle->lifetime = cred.times.endtime;
    } else {
	krb5_creds in_cred, *out_cred;
	krb5_const_realm realm;

	memset(&in_cred, 0, sizeof(in_cred));
	in_cred.client = handle->principal;
	
	realm = krb5_principal_get_realm(context, 
					 handle->principal);
	if (realm == NULL) {
	    kret = KRB5_PRINC_NOMATCH; /* XXX */
	    goto end;
	}

	kret = krb5_make_principal(context, &in_cred.server, 
				   realm, KRB5_TGS_NAME, realm, NULL);
	if (kret)
	    goto end;

	kret = krb5_get_credentials(context, 0, 
				    ccache, &in_cred, &out_cred);
	krb5_free_principal(context, in_cred.server);
	if (kret)
	    goto end;

	handle->lifetime = out_cred->times.endtime;
	krb5_free_creds(context, out_cred);
    }

    handle->ccache = ccache;
    handle->made_ccache = made_ccache;
    ret = GSS_S_COMPLETE;

end:
    if (cred.client != NULL)
	krb5_free_cred_contents(context, &cred);
    if (def_princ != NULL)
	krb5_free_principal(context, def_princ);
    if (made_keytab)
	krb5_kt_close(context, keytab);
    if (ret != GSS_S_COMPLETE) {
	if (made_ccache)
	    krb5_cc_close(context, ccache);
	if (kret != 0) {
	    *minor_status = kret;
	    gssapi_krb5_set_error_string ();
	}
    }
    return (ret);
}

static OM_uint32 acquire_acceptor_cred
		  (OM_uint32 * minor_status,
		   krb5_context context,
		   krb5_keytab keytab,
		   OM_uint32 time_req,
		   const gss_OID_set desired_mechs,
		   gss_cred_usage_t cred_usage,
		   gss_cred_id_t handle,
		   gss_OID_set * actual_mechs,
		   OM_uint32 * time_rec
		  )
{
    OM_uint32 ret;
    krb5_error_code kret;

    kret = 0;
    ret = GSS_S_FAILURE;
    if (keytab == NULL) {
        kret = get_keytab(context, &handle->keytab);
	if (kret)
		goto end;
	handle->made_keytab = TRUE;
    } else {
	handle->keytab = keytab;
	handle->made_keytab = FALSE;
    }
    ret = GSS_S_COMPLETE;
 
end:
    if (ret != GSS_S_COMPLETE) {
	if (handle->made_keytab)
	    krb5_kt_close(context, handle->keytab);
	if (kret != 0) {
	    *minor_status = kret;
	    gssapi_krb5_set_error_string ();
	}
    }
    return (ret);
}

OM_uint32 gsskrb5_acquire_cred
           (OM_uint32 * minor_status,
	    struct krb5_keytab_data *keytab,
	    struct krb5_ccache_data *ccache,
            const gss_name_t desired_name,
            OM_uint32 time_req,
            const gss_OID_set desired_mechs,
            gss_cred_usage_t cred_usage,
            gss_cred_id_t * output_cred_handle,
            gss_OID_set * actual_mechs,
            OM_uint32 * time_rec
           )
{
    gss_cred_id_t handle;
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

	ret = gss_test_oid_set_member(minor_status, GSS_KRB5_MECHANISM,
				      desired_mechs, &present); 
	if (ret)
	    return ret;
	if (!present) {
	    *minor_status = 0;
	    return GSS_S_BAD_MECH;
	}
    }

    handle = (gss_cred_id_t)malloc(sizeof(*handle));
    if (handle == GSS_C_NO_CREDENTIAL) {
	*minor_status = ENOMEM;
        return (GSS_S_FAILURE);
    }

    memset(handle, 0, sizeof (*handle));
    HEIMDAL_MUTEX_init(&handle->cred_id_mutex);

    if (desired_name != GSS_C_NO_NAME) {
	ret = gss_duplicate_name(minor_status, desired_name,
	    &handle->principal);
	if (ret != GSS_S_COMPLETE) {
	    HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	    free(handle);
	    return (ret);
	}
    }
    if (cred_usage == GSS_C_INITIATE || cred_usage == GSS_C_BOTH) {
	ret = acquire_initiator_cred(minor_status, gssapi_krb5_context, 
				     keytab, ccache, 
				     desired_name, time_req,
				     desired_mechs, cred_usage, 
				     handle, actual_mechs, time_rec);
    	if (ret != GSS_S_COMPLETE) {
	    HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	    krb5_free_principal(gssapi_krb5_context, handle->principal);
	    free(handle);
	    return (ret);
	}
    }
    if (cred_usage == GSS_C_ACCEPT || cred_usage == GSS_C_BOTH) {
	ret = acquire_acceptor_cred(minor_status, gssapi_krb5_context, 
				    keytab, time_req,
				    desired_mechs, cred_usage, 
				    handle, actual_mechs, time_rec);
	if (ret != GSS_S_COMPLETE) {
	    HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	    krb5_free_principal(gssapi_krb5_context, handle->principal);
	    free(handle);
	    return (ret);
	}
    }
    ret = gss_create_empty_oid_set(minor_status, &handle->mechanisms);
    if (ret == GSS_S_COMPLETE)
    	ret = gss_add_oid_set_member(minor_status, GSS_KRB5_MECHANISM,
				 &handle->mechanisms);
    if (ret == GSS_S_COMPLETE)
    	ret = gss_inquire_cred(minor_status, handle, NULL, time_rec, NULL,
			   actual_mechs);
    if (ret != GSS_S_COMPLETE) {
	if (handle->mechanisms != NULL)
	    gss_release_oid_set(NULL, &handle->mechanisms);
	HEIMDAL_MUTEX_destroy(&handle->cred_id_mutex);
	krb5_free_principal(gssapi_krb5_context, handle->principal);
	free(handle);
	return (ret);
    } 
    *minor_status = 0;
    if (time_rec) {
	ret = gssapi_lifetime_left(minor_status,
				   handle->lifetime,
				   time_rec);

	if (ret)
	    return ret;
    }
    handle->usage = cred_usage;

    *output_cred_handle = handle;
    return (GSS_S_COMPLETE);
}

OM_uint32 gss_acquire_cred
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
	return gsskrb5_acquire_cred(minor_status,
				    NULL, NULL,
				    desired_name,
				    time_req,
				    desired_mechs,
				    cred_usage,
				    output_cred_handle,
				    actual_mechs,
				    time_rec);
}
