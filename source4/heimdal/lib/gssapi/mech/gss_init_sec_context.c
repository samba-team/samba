/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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
 *	$FreeBSD: src/lib/libgssapi/gss_init_sec_context.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

gss_cred_id_t
_gss_mg_find_mech_cred(
    gss_const_cred_id_t cred_handle,
    gss_const_OID mech_type)
{
	struct _gss_cred *cred = (struct _gss_cred *)cred_handle;
	struct _gss_mechanism_cred *mc;

	if (cred == NULL)
		return GSS_C_NO_CREDENTIAL;

	HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link) {
		if (gss_oid_equal(mech_type, mc->gmc_mech_oid))
			return mc->gmc_cred;
	}
	return GSS_C_NO_CREDENTIAL;
}

static void
log_init_sec_context(struct _gss_context *ctx,
		     struct _gss_name *target,
		     OM_uint32 req_flags,
		     struct _gss_cred *cred,
		     gss_OID mech_type,
		     gss_buffer_t input_token)
{
    gssapi_mech_interface m;

    if (ctx)
	m = ctx->gc_mech;
    else
	m = __gss_get_mechanism(mech_type);
    if (m == NULL)
	return;

    mech_type = &m->gm_mech_oid;

    _gss_mg_log(1, "gss_isc: %s %sfirst flags %08x, %s cred, %stoken",
		m->gm_name,
		(ctx == NULL) ? "" : "not ",
		req_flags,
		(cred != NULL) ? "specific" : "default",
		(input_token != NULL && input_token->length) ? "" : "no ");

    _gss_mg_log_cred(1, cred, "gss_isc cred");

    /* print target name */
    _gss_mg_log_name(1, target, mech_type, "gss_isc: target");
}

/**
 * As the initiator build a context with an acceptor.
 *
 * Returns in the major
 * - GSS_S_COMPLETE - if the context if build
 * - GSS_S_CONTINUE_NEEDED -  if the caller needs  to continue another
 *	round of gss_i nit_sec_context
 * - error code - any other error code
 *
 * @param minor_status minor status code.
 *
 * @param initiator_cred_handle the credential to use when building
 *        the context, if GSS_C_NO_CREDENTIAL is passed, the default
 *        credential for the mechanism will be used.
 *
 * @param context_handle a pointer to a context handle, will be
 * 	  returned as long as there is not an error.
 *
 * @param target_name the target name of acceptor, created using
 * 	  gss_import_name(). The name is can be of any name types the
 * 	  mechanism supports, check supported name types with
 * 	  gss_inquire_names_for_mech().
 *
 * @param input_mech_type mechanism type to use, if GSS_C_NO_OID is
 *        used, Kerberos (GSS_KRB5_MECHANISM) will be tried. Other
 *        available mechanism are listed in the @ref gssapi_mechs_intro
 *        section.
 *
 * @param req_flags flags using when building the context, see @ref
 *        gssapi_context_flags
 *
 * @param time_req time requested this context should be valid in
 *        seconds, common used value is GSS_C_INDEFINITE
 *
 * @param input_chan_bindings Channel bindings used, if not exepected
 *        otherwise, used GSS_C_NO_CHANNEL_BINDINGS
 *
 * @param input_token input token sent from the acceptor, for the
 * 	  initial packet the buffer of { NULL, 0 } should be used.
 *
 * @param actual_mech_type the actual mech used, MUST NOT be freed
 *        since it pointing to static memory.
 *
 * @param output_token if there is an output token, regardless of
 * 	  complete, continue_needed, or error it should be sent to the
 * 	  acceptor
 *
 * @param ret_flags return what flags was negotitated, caller should
 * 	  check if they are accetable. For example, if
 * 	  GSS_C_MUTUAL_FLAG was negotiated with the acceptor or not.
 *
 * @param time_rec amount of time this context is valid for
 *
 * @returns a gss_error code, see gss_display_status() about printing
 *          the error code.
 *
 * @ingroup gssapi
 */



GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_init_sec_context(OM_uint32 * minor_status,
    gss_const_cred_id_t initiator_cred_handle,
    gss_ctx_id_t * context_handle,
    gss_const_name_t target_name,
    const gss_OID input_mech_type,
    OM_uint32 req_flags,
    OM_uint32 time_req,
    const gss_channel_bindings_t input_chan_bindings,
    const gss_buffer_t input_token,
    gss_OID * actual_mech_type,
    gss_buffer_t output_token,
    OM_uint32 * ret_flags,
    OM_uint32 * time_rec)
{
	OM_uint32 major_status;
	gssapi_mech_interface m;
        gss_const_name_t mn_inner = GSS_C_NO_NAME;
	struct _gss_name *name = (struct _gss_name *) target_name;
	struct _gss_mechanism_name *mn;
	struct _gss_context *ctx = (struct _gss_context *) *context_handle;
	gss_const_cred_id_t cred_handle;
	int allocated_ctx;
	gss_OID mech_type = input_mech_type;

	*minor_status = 0;

	_mg_buffer_zero(output_token);
	if (actual_mech_type)
	    *actual_mech_type = GSS_C_NO_OID;
	if (ret_flags)
	    *ret_flags = 0;
	if (time_rec)
	    *time_rec = 0;

	if (mech_type == GSS_C_NO_OID)
	    mech_type = GSS_KRB5_MECHANISM;

	_gss_mg_check_name(target_name);

	if (_gss_mg_log_level(1))
	    log_init_sec_context(ctx, name, req_flags,
				 (struct _gss_cred *)initiator_cred_handle,
				 input_mech_type, input_token);

	/*
	 * If we haven't allocated a context yet, do so now and lookup
	 * the mechanism switch table. If we have one already, make
	 * sure we use the same mechanism switch as before.
	 */
	if (!ctx) {
		ctx = malloc(sizeof(struct _gss_context));
		if (!ctx) {
			*minor_status = ENOMEM;
			return (GSS_S_FAILURE);
		}
		memset(ctx, 0, sizeof(struct _gss_context));
		m = ctx->gc_mech = __gss_get_mechanism(mech_type);
		if (!m) {
			free(ctx);
			*minor_status = 0;
			gss_mg_set_error_string(mech_type, GSS_S_BAD_MECH,
						*minor_status,
						"Unsupported mechanism requested");
			return (GSS_S_BAD_MECH);
		}
		allocated_ctx = 1;
	} else {
		m = ctx->gc_mech;
		mech_type = &ctx->gc_mech->gm_mech_oid;
		allocated_ctx = 0;
	}

	/*
	 * Find the MN for this mechanism.
	 */
        if ((m->gm_flags & GM_USE_MG_NAME)) {
            mn_inner = target_name;
        } else {
            major_status = _gss_find_mn(minor_status, name, mech_type, &mn);
            if (major_status != GSS_S_COMPLETE) {
                    if (allocated_ctx)
                        free(ctx);
                    return major_status;
            }
            if (mn)
                mn_inner = mn->gmn_name;
        }

	/*
	 * If we have a cred, find the cred for this mechanism.
	 */
	if (m->gm_flags & GM_USE_MG_CRED)
		cred_handle = initiator_cred_handle;
	else
		cred_handle = _gss_mg_find_mech_cred(initiator_cred_handle, mech_type);

        if (initiator_cred_handle != GSS_C_NO_CREDENTIAL &&
            cred_handle == NULL) {
	    *minor_status = 0;
            if (allocated_ctx)
                free(ctx);
	    gss_mg_set_error_string(mech_type, GSS_S_UNAVAILABLE,
				    *minor_status,
				    "Credential for the requested mechanism "
				    "not found in credential handle");
            return GSS_S_UNAVAILABLE;
        }

	major_status = m->gm_init_sec_context(minor_status,
	    cred_handle,
	    &ctx->gc_ctx,
	    mn_inner,
	    mech_type,
	    req_flags,
	    time_req,
	    input_chan_bindings,
	    input_token,
	    actual_mech_type,
	    output_token,
	    ret_flags,
	    time_rec);

	if (major_status != GSS_S_COMPLETE
	    && major_status != GSS_S_CONTINUE_NEEDED) {
		if (allocated_ctx)
			free(ctx);
		_mg_buffer_zero(output_token);
		_gss_mg_error(m, *minor_status);
	} else {
		*context_handle = (gss_ctx_id_t) ctx;
	}

	_gss_mg_log(1, "gss_isc: %s maj_stat: %d/%d",
		    m->gm_name, (int)major_status, (int)*minor_status);

	return (major_status);
}
