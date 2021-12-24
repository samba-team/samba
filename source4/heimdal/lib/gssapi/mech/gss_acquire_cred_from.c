/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
 * Portions Copyright (c) 2011, 2018 PADL Software Pty Ltd.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/gss_acquire_cred.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

/*
 * Shim for gss_acquire_cred_with_password()
 */
static const char *
find_password_in_cred_store(gss_const_key_value_set_t cred_store)
{
    size_t i;

    if (cred_store == GSS_C_NO_CRED_STORE)
	return NULL;

    for (i = 0; i < cred_store->count; i++) {
	if (strcmp(cred_store->elements[i].key, "password") == 0)
	    return cred_store->elements[i].value;
    }

    return NULL;
}

static OM_uint32
acquire_mech_cred(OM_uint32 *minor_status,
		  gssapi_mech_interface m,
		  const struct _gss_mechanism_name *mn,
		  OM_uint32 time_req,
		  gss_cred_usage_t cred_usage,
		  gss_const_key_value_set_t cred_store,
		  struct _gss_mechanism_cred **out,
		  OM_uint32 *time_rec)
{
    OM_uint32 major_status;
    struct _gss_mechanism_cred *mc;
    gss_OID_set_desc mech;
    const char *spassword;

    *out = NULL;
    if (time_rec)
	*time_rec = 0;

    mc = calloc(1, sizeof(struct _gss_mechanism_cred));
    if (mc == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    mc->gmc_mech = m;
    mc->gmc_mech_oid = &m->gm_mech_oid;

    mech.count = 1;
    mech.elements = mc->gmc_mech_oid;

    if (m->gm_acquire_cred_from) {
	major_status = m->gm_acquire_cred_from(minor_status,
					       mn ? mn->gmn_name : GSS_C_NO_NAME,
					       time_req,
					       &mech,
					       cred_usage,
					       cred_store,
					       &mc->gmc_cred,
					       NULL,
					       time_rec);
    } else if ((cred_store == GSS_C_NO_CRED_STORE || cred_store->count == 0) &&
	       m->gm_acquire_cred) {
	major_status = m->gm_acquire_cred(minor_status,
					  mn ? mn->gmn_name : GSS_C_NO_NAME,
					  time_req,
					  &mech,
					  cred_usage,
					  &mc->gmc_cred,
					  NULL,
					  time_rec);
    } else if (m->gm_compat &&
	       m->gm_compat->gmc_acquire_cred_with_password &&
	       (spassword = find_password_in_cred_store(cred_store)) != NULL) {
	gss_buffer_desc password;

	password.length = strlen(spassword);
	password.value = rk_UNCONST(spassword);

	/* compat glue for loadable mechanisms that implement API-as-SPI */
	major_status = m->gm_compat->gmc_acquire_cred_with_password(minor_status,
				mn ? mn->gmn_name : GSS_C_NO_NAME,
				&password,
				time_req,
				&mech,
				cred_usage,
				&mc->gmc_cred,
				NULL,
				time_rec);
    } else
	major_status = GSS_S_UNAVAILABLE;

    heim_assert(major_status == GSS_S_COMPLETE || mc->gmc_cred == NULL,
		"gss_acquire_cred_from: mech succeeded but did not return a credential");

    if (major_status == GSS_S_COMPLETE)
        *out = mc;
    else
        free(mc);

    return major_status;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_acquire_cred_from(OM_uint32 *minor_status,
		      gss_const_name_t desired_name,
		      OM_uint32 time_req,
		      const gss_OID_set desired_mechs,
		      gss_cred_usage_t cred_usage,
		      gss_const_key_value_set_t cred_store,
		      gss_cred_id_t *output_cred_handle,
		      gss_OID_set *actual_mechs,
		      OM_uint32 *time_rec)
{
    OM_uint32 major_status, minor;
    struct _gss_name *name = (struct _gss_name *)desired_name;
    gssapi_mech_interface m;
    struct _gss_cred *cred = NULL;
    size_t i;
    OM_uint32 min_time = GSS_C_INDEFINITE;
    gss_OID_set mechs = GSS_C_NO_OID_SET;

    *minor_status = 0;
    if (output_cred_handle == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ;
    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (actual_mechs)
	*actual_mechs = GSS_C_NO_OID_SET;
    if (time_rec)
	*time_rec = 0;

    _gss_load_mech();

    if (desired_mechs != GSS_C_NO_OID_SET) {
	int only_mg_cred_mechs = -1;

	for (i = 0; i < desired_mechs->count; i++) {
	    m = __gss_get_mechanism(&desired_mechs->elements[i]);
	    if (m != NULL) {
		if ((m->gm_flags & GM_USE_MG_CRED) == 0)
		    only_mg_cred_mechs = 0;
		else if (only_mg_cred_mechs == -1)
		    only_mg_cred_mechs = 1;
	    }
	}
	/*
	 * Now SPNEGO supports GM_USE_MG_CRED it's no longer necessary
	 * to specifically acquire SPNEGO credentials. If the caller
	 * did not specify any concrete mechanisms then we will acquire
	 * credentials for all of them.
	 */
	if (only_mg_cred_mechs == -1) {
	    *minor_status = 0;
	    major_status = GSS_S_BAD_MECH;
	    goto cleanup;
	} else if (only_mg_cred_mechs == 0)
	    mechs = desired_mechs;
	else
	    mechs = _gss_mech_oids;
    } else
	mechs = _gss_mech_oids;

    cred = _gss_mg_alloc_cred();
    if (cred == NULL) {
	*minor_status = ENOMEM;
	major_status = GSS_S_FAILURE;
	goto cleanup;
    }

    if (actual_mechs) {
	major_status = gss_create_empty_oid_set(minor_status, actual_mechs);
	if (GSS_ERROR(major_status))
	    goto cleanup;
    }

    major_status = GSS_S_UNAVAILABLE; /* in case of no mechs */

    for (i = 0; i < mechs->count; i++) {
	struct _gss_mechanism_name *mn = NULL;
	struct _gss_mechanism_cred *mc = NULL;
	OM_uint32 cred_time;

	m = __gss_get_mechanism(&mechs->elements[i]);
	if (m == NULL || (m->gm_flags & GM_USE_MG_CRED) != 0)
	    continue;

	if (desired_name != GSS_C_NO_NAME) {
	    major_status = _gss_find_mn(minor_status, name,
					&mechs->elements[i], &mn);
	    if (major_status != GSS_S_COMPLETE)
		continue;
	}

	major_status = acquire_mech_cred(minor_status, m, mn,
					 time_req, cred_usage,
					 cred_store, &mc, &cred_time);
	if (major_status != GSS_S_COMPLETE) {
            if (mechs->count == 1)
                _gss_mg_error(m, *minor_status);
	    continue;
        }

	_gss_mg_log_name(10, name, &mechs->elements[i],
			 "gss_acquire_cred %s name: %ld/%ld",
			 m->gm_name,
			 (long)major_status, (long)*minor_status);

	HEIM_TAILQ_INSERT_TAIL(&cred->gc_mc, mc, gmc_link);

	if (cred_time < min_time)
	    min_time = cred_time;
	if (actual_mechs != NULL) {
	    major_status = gss_add_oid_set_member(minor_status,
						  mc->gmc_mech_oid,
						  actual_mechs);
	    if (GSS_ERROR(major_status))
		goto cleanup;
	}
    }

    /*
     * If we didn't manage to create a single credential, return
     * an error.
     */
    if (!HEIM_TAILQ_FIRST(&cred->gc_mc)) {
        if (mechs->count > 1) {
	    *minor_status = 0;
	    major_status = GSS_S_NO_CRED;
	}
	heim_assert(major_status != GSS_S_COMPLETE,
		    "lack of credentials must result in an error");
	goto cleanup;
    }

    /* add all GM_USE_MG_CRED mechs such as SPNEGO */
    if (actual_mechs != NULL) {
	struct _gss_mech_switch *ms;

	HEIM_TAILQ_FOREACH(ms, &_gss_mechs, gm_link) {
	    m = &ms->gm_mech;

	    if ((m->gm_flags & GM_USE_MG_CRED) == 0)
		continue;

	    major_status = gss_add_oid_set_member(minor_status,
						  &m->gm_mech_oid,
						  actual_mechs);
	    if (GSS_ERROR(major_status))
		goto cleanup;
	}
    }

    *minor_status = 0;
    major_status = GSS_S_COMPLETE;

    *output_cred_handle = (gss_cred_id_t)cred;
    if (time_rec)
        *time_rec = min_time;

    _gss_mg_log_cred(10, cred, "gss_acquire_cred_from");

cleanup:
    if (major_status != GSS_S_COMPLETE) {
	gss_release_cred(&minor, (gss_cred_id_t *)&cred);
	if (actual_mechs)
	    gss_release_oid_set(&minor, actual_mechs);
    }

    return major_status;
}
