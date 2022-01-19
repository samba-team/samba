/*-
 * Copyright (c) 2005 Doug Rabson
 * Copyright (c) 2018 Kungliga Tekniska Högskolan
 * Copyright (c) 2018 AuriStor, Inc.
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
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
 *	$FreeBSD: src/lib/libgssapi/gss_add_cred.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

OM_uint32
_gss_mg_add_mech_cred(OM_uint32 *minor_status,
		      gssapi_mech_interface m,
		      const struct _gss_mechanism_cred *mc,
		      const struct _gss_mechanism_name *mn,
		      gss_cred_usage_t cred_usage,
		      OM_uint32 initiator_time_req,
		      OM_uint32 acceptor_time_req,
		      gss_const_key_value_set_t cred_store,
		      struct _gss_mechanism_cred **out,
		      OM_uint32 *initiator_time_rec,
		      OM_uint32 *acceptor_time_rec)
{
    OM_uint32 major_status;
    struct _gss_mechanism_cred *new_mc = NULL;

    if (out) {
	*out = NULL;

	new_mc = calloc(1, sizeof(struct _gss_mechanism_cred));
	if (new_mc == NULL) {
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}

	new_mc->gmc_mech = m;
	new_mc->gmc_mech_oid = &m->gm_mech_oid;
    }

    if (m->gm_add_cred_from) {
	major_status = m->gm_add_cred_from(minor_status,
					   mc ? mc->gmc_cred : GSS_C_NO_CREDENTIAL,
					   mn ? mn->gmn_name : GSS_C_NO_NAME,
					   &m->gm_mech_oid,
					   cred_usage,
					   initiator_time_req,
					   acceptor_time_req,
					   cred_store,
					   new_mc ? &new_mc->gmc_cred : NULL,
					   NULL,
					   initiator_time_rec,
					   acceptor_time_rec);
    } else if (cred_store == GSS_C_NO_CRED_STORE && m->gm_add_cred) {
	major_status = m->gm_add_cred(minor_status,
				      mc ? mc->gmc_cred : GSS_C_NO_CREDENTIAL,
				      mn ? mn->gmn_name : GSS_C_NO_NAME,
				      &m->gm_mech_oid,
				      cred_usage,
				      initiator_time_req,
				      acceptor_time_req,
				      new_mc ? &new_mc->gmc_cred : NULL,
				      NULL,
				      initiator_time_rec,
				      acceptor_time_rec);
    } else
	major_status = GSS_S_UNAVAILABLE;

    if (major_status == GSS_S_COMPLETE && out) {
	heim_assert(new_mc->gmc_cred != GSS_C_NO_CREDENTIAL,
		    "mechanism gss_add_cred did not return a cred");
	*out = new_mc;
    } else
        free(new_mc);

    return major_status;
}

static OM_uint32
add_mech_cred_internal(OM_uint32 *minor_status,
		       gss_const_name_t desired_name,
		       gssapi_mech_interface m,
		       gss_cred_usage_t cred_usage,
		       OM_uint32 initiator_time_req,
		       OM_uint32 acceptor_time_req,
		       gss_const_key_value_set_t cred_store,
		       struct _gss_cred *mut_cred,
		       OM_uint32 *initiator_time_rec,
		       OM_uint32 *acceptor_time_rec)
{
    OM_uint32 major_status;
    struct _gss_mechanism_cred *mc;
    struct _gss_mechanism_name *mn;

    heim_assert((m->gm_flags & GM_USE_MG_CRED) == 0,
		"add_mech_cred_internal must be called with concrete mechanism");

    if (desired_name != GSS_C_NO_NAME) {
	major_status = _gss_find_mn(minor_status,
				    (struct _gss_name *)desired_name,
				    &m->gm_mech_oid, &mn);
	if (major_status != GSS_S_COMPLETE)
	    return major_status;
    } else
	mn = NULL;

    /*
     * If we have an existing mechanism credential for mechanism m, then
     * add the desired credential to it; otherwise, create a new one and
     * add it to mut_cred.
     */
    HEIM_TAILQ_FOREACH(mc, &mut_cred->gc_mc, gmc_link) {
	if (gss_oid_equal(&m->gm_mech_oid, mc->gmc_mech_oid))
	    break;
    }

    if (mc) {
	major_status = _gss_mg_add_mech_cred(minor_status, m,
					     mc, mn, cred_usage,
					     initiator_time_req, acceptor_time_req,
					     cred_store, NULL,
					     initiator_time_rec, acceptor_time_rec);
    } else {
	struct _gss_mechanism_cred *new_mc = NULL;

	major_status = _gss_mg_add_mech_cred(minor_status, m,
					     NULL, mn, cred_usage,
					     initiator_time_req, acceptor_time_req,
					     cred_store, &new_mc,
					     initiator_time_rec, acceptor_time_rec);
	if (major_status == GSS_S_COMPLETE)
	    HEIM_TAILQ_INSERT_TAIL(&mut_cred->gc_mc, new_mc, gmc_link);
    }

    return major_status;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_add_cred_from(OM_uint32 *minor_status,
    gss_cred_id_t input_cred_handle,
    gss_const_name_t desired_name,
    const gss_OID desired_mech,
    gss_cred_usage_t cred_usage,
    OM_uint32 initiator_time_req,
    OM_uint32 acceptor_time_req,
    gss_const_key_value_set_t cred_store,
    gss_cred_id_t *output_cred_handle,
    gss_OID_set *actual_mechs,
    OM_uint32 *initiator_time_rec,
    OM_uint32 *acceptor_time_rec)
{
    OM_uint32 major_status;
    gssapi_mech_interface m;
    gss_cred_id_t release_cred = GSS_C_NO_CREDENTIAL;
    struct _gss_cred *mut_cred;
    OM_uint32 junk;

    *minor_status = 0;

    /* Input validation */
    if (output_cred_handle)
        *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (initiator_time_rec)
        *initiator_time_rec = 0;
    if (acceptor_time_rec)
        *acceptor_time_rec = 0;
    if (actual_mechs)
        *actual_mechs = GSS_C_NO_OID_SET;
    if ((m = __gss_get_mechanism(desired_mech)) == NULL)
        return GSS_S_BAD_MECH;
    if (input_cred_handle == GSS_C_NO_CREDENTIAL &&
        output_cred_handle == NULL) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    /* Setup mut_cred to be the credential we mutate */
    if (input_cred_handle != GSS_C_NO_CREDENTIAL &&
        output_cred_handle != NULL) {
        gss_cred_id_t new_cred;

        /* Duplicate the input credential */
        major_status = gss_duplicate_cred(minor_status, input_cred_handle,
                                          &new_cred);
        if (major_status != GSS_S_COMPLETE)
            return major_status;
        mut_cred = (struct _gss_cred *)new_cred;
        release_cred = (gss_cred_id_t)mut_cred;
    } else if (input_cred_handle != GSS_C_NO_CREDENTIAL) {
        /* Mutate the input credentials */
        mut_cred = rk_UNCONST(input_cred_handle);
    } else {
        mut_cred = _gss_mg_alloc_cred();
	if (mut_cred == NULL) {
            *minor_status = ENOMEM;
            return GSS_S_UNAVAILABLE;
        }
        release_cred = (gss_cred_id_t)mut_cred;
    }

    if (m->gm_flags & GM_USE_MG_CRED) {
	struct _gss_mech_switch *ms;
	OM_uint32 initiator_time_min = GSS_C_INDEFINITE;
	OM_uint32 acceptor_time_min = GSS_C_INDEFINITE;

	major_status = GSS_S_UNAVAILABLE; /* in case of no mechs */

	if (input_cred_handle == GSS_C_NO_CREDENTIAL) {
	    HEIM_TAILQ_FOREACH(ms, &_gss_mechs, gm_link) {
		m = &ms->gm_mech; /* for _gss_mg_error() */

		if (m->gm_flags & GM_USE_MG_CRED)
		    continue;

		major_status = add_mech_cred_internal(minor_status, desired_name, m,
						      cred_usage,
						      initiator_time_req, acceptor_time_req,
						      cred_store, mut_cred,
						      initiator_time_rec, acceptor_time_rec);
		if (major_status != GSS_S_COMPLETE)
		    continue;

		if (initiator_time_rec && *initiator_time_rec < initiator_time_min)
		    initiator_time_min = *initiator_time_rec;
		if (acceptor_time_rec && *acceptor_time_rec < acceptor_time_min)
		    acceptor_time_min = *acceptor_time_rec;
	    }
	} else {
	    OM_uint32 lifetime;
	    gss_cred_usage_t usage = GSS_C_BOTH;

	    major_status = gss_inquire_cred(minor_status, input_cred_handle,
					    NULL, &lifetime, &usage, NULL);
	    if (major_status == GSS_S_COMPLETE) {
		if (usage == GSS_C_BOTH || usage == GSS_C_INITIATE)
		    initiator_time_min = lifetime;
		if (usage == GSS_C_BOTH || usage == GSS_C_ACCEPT)
		    acceptor_time_min = lifetime;
	    }
	}

	if (initiator_time_rec)
	    *initiator_time_rec = initiator_time_min;
	if (acceptor_time_rec)
	    *acceptor_time_rec = acceptor_time_min;
    } else {
	major_status = add_mech_cred_internal(minor_status, desired_name, m,
					      cred_usage,
					      initiator_time_req, acceptor_time_req,
					      cred_store, mut_cred,
					      initiator_time_rec, acceptor_time_rec);
    }

    if (major_status != GSS_S_COMPLETE)
	_gss_mg_error(m, *minor_status);

    /* Lastly, we have to inquire the cred to get the actual_mechs */
    if (major_status == GSS_S_COMPLETE && actual_mechs != NULL) {
        major_status = gss_inquire_cred(minor_status,
                                        (gss_const_cred_id_t)mut_cred, NULL,
                                        NULL, NULL, actual_mechs);
    }
    if (major_status == GSS_S_COMPLETE) {
        if (output_cred_handle != NULL)
            *output_cred_handle = (gss_cred_id_t)mut_cred;
    } else {
        gss_release_cred(&junk, &release_cred);
    }
    return major_status;
}

