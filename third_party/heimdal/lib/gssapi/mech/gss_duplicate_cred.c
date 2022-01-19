/*-
 * Copyright (c) 2005 Doug Rabson
 * Copyright (c) 2018 Kungliga Tekniska Högskolan
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

static OM_uint32
copy_cred_element(OM_uint32 *minor_status,
                  struct _gss_mechanism_cred *mc,
                  struct _gss_mechanism_cred **out)
{
    gssapi_mech_interface m = mc->gmc_mech;
    OM_uint32 major_status, tmp;
    struct _gss_mechanism_cred *new_mc;
    OM_uint32 initiator_lifetime, acceptor_lifetime;
    gss_cred_usage_t cred_usage;
    gss_cred_id_t dup_cred = GSS_C_NO_CREDENTIAL;

    *out = NULL;

    if (m->gm_duplicate_cred) {
        major_status = m->gm_duplicate_cred(minor_status,
					    mc->gmc_cred, &dup_cred);
    } else if (m->gm_import_cred && m->gm_export_cred) {
	gss_buffer_desc export;

	major_status = m->gm_export_cred(minor_status, mc->gmc_cred, &export);
	if (major_status == GSS_S_COMPLETE) {
	    major_status = m->gm_import_cred(minor_status, &export, &dup_cred);
	    _gss_secure_release_buffer(&tmp, &export);
	}
    } else {
	struct _gss_mechanism_name mn;

	mn.gmn_mech = m;
	mn.gmn_mech_oid = mc->gmc_mech_oid;
	mn.gmn_name = GSS_C_NO_NAME;

	/* This path won't work for ephemeral creds or cred stores */
	major_status = m->gm_inquire_cred_by_mech(minor_status, mc->gmc_cred,
						  mc->gmc_mech_oid, &mn.gmn_name,
						  &initiator_lifetime,
						  &acceptor_lifetime, &cred_usage);
	if (major_status == GSS_S_COMPLETE) {
	    major_status = _gss_mg_add_mech_cred(minor_status,
						 m,
						 NULL, /* mc */
						 &mn,
						 cred_usage,
						 initiator_lifetime,
						 acceptor_lifetime,
						 GSS_C_NO_CRED_STORE,
						 &new_mc,
						 NULL,
					         NULL);
	    m->gm_release_name(&tmp, &mn.gmn_name);
	}
    }

    if (major_status == GSS_S_COMPLETE) {
	new_mc = calloc(1, sizeof(*new_mc));
	if (new_mc == NULL) {
	    *minor_status = ENOMEM;
	    m->gm_release_cred(&tmp, &dup_cred);
	    return GSS_S_FAILURE;
	}

	new_mc->gmc_mech = m;
	new_mc->gmc_mech_oid = mc->gmc_mech_oid;
	new_mc->gmc_cred = dup_cred;

	*out = new_mc;
    } else
        _gss_mg_error(m, *minor_status);

    return major_status;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_duplicate_cred(OM_uint32 *minor_status,
                   gss_const_cred_id_t input_cred_handle,
                   gss_cred_id_t *output_cred_handle)
{
    struct _gss_mechanism_cred *mc;
    struct _gss_cred *new_cred;
    struct _gss_cred *cred = (struct _gss_cred *)input_cred_handle;
    OM_uint32 major_status, junk;

    if (input_cred_handle == GSS_C_NO_CREDENTIAL) {
        /*
         * "Copy" the default credential by acquiring a cred handle for the
         * default credential's name, GSS_C_NO_NAME.
         */
        return gss_acquire_cred(minor_status, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET, GSS_C_BOTH,
                                output_cred_handle, NULL, NULL);
    }

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    new_cred = _gss_mg_alloc_cred();
    if (!new_cred) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    *minor_status = 0;
    major_status = GSS_S_NO_CRED;

    HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link) {
	struct _gss_mechanism_cred *copy_mc;

        major_status = copy_cred_element(minor_status, mc, &copy_mc);
        if (major_status != GSS_S_COMPLETE)
            break;

        HEIM_TAILQ_INSERT_TAIL(&new_cred->gc_mc, copy_mc, gmc_link);
    }

    if (major_status != GSS_S_COMPLETE) {
        gss_cred_id_t release_cred = (gss_cred_id_t)new_cred;
        gss_release_cred(&junk, &release_cred);
        new_cred = NULL;
    }

    *output_cred_handle = (gss_cred_id_t)new_cred;
    return major_status;
}
