/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
 * Portions Copyright (c) 2019 AuriStor, Inc. All rights reserved.
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
 */

#include "mech_locl.h"

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gssspi_exchange_meta_data(
    OM_uint32 *minor_status,
    gss_const_OID input_mech_type,
    gss_cred_id_t input_cred_handle,
    gss_ctx_id_t *context_handle,
    gss_const_name_t target_name,
    OM_uint32 req_flags,
    gss_const_buffer_t meta_data)
{
    OM_uint32 major_status, junk;
    gssapi_mech_interface m;
    struct _gss_name *name = (struct _gss_name *) target_name;
    struct _gss_mechanism_name *mn;
    struct _gss_context *ctx = (struct _gss_context *) *context_handle;
    gss_cred_id_t cred_handle;
    int allocated_ctx;
    gss_const_OID mech_type = input_mech_type;

    *minor_status = 0;

    if (mech_type == GSS_C_NO_OID)
	return GSS_S_BAD_MECH;

    if (ctx == NULL) {
	ctx = calloc(1, sizeof(struct _gss_context));
	if (ctx == NULL) {
	    *minor_status = ENOMEM;
	    return GSS_S_FAILURE;
	}

	m = ctx->gc_mech = __gss_get_mechanism(mech_type);
	if (m == NULL) {
	    free(ctx);
	    return GSS_S_BAD_MECH;
	}
	allocated_ctx = 1;
    } else {
	m = ctx->gc_mech;
	mech_type = &m->gm_mech_oid;
	allocated_ctx = 0;
    }

    if (m->gm_exchange_meta_data == NULL) {
	major_status = GSS_S_BAD_MECH;
	goto cleanup;
    }

    major_status = _gss_find_mn(minor_status, name, mech_type, &mn);
    if (major_status != GSS_S_COMPLETE)
	goto cleanup;

    if (m->gm_flags & GM_USE_MG_CRED)
	cred_handle = input_cred_handle;
    else
	cred_handle = _gss_mg_find_mech_cred(input_cred_handle, mech_type);

    if (input_cred_handle != GSS_C_NO_CREDENTIAL &&
	cred_handle == NULL) {
	major_status = GSS_S_NO_CRED;
	goto cleanup;
    }

    /* note: mechanism is not obligated to allocate a context on success */
    major_status = m->gm_exchange_meta_data(minor_status,
	    mech_type,
	    cred_handle,
	    &ctx->gc_ctx,
	    mn ? mn->gmn_name : GSS_C_NO_NAME,
	    req_flags,
	    meta_data);
    if (major_status != GSS_S_COMPLETE)
	_gss_mg_error(m, *minor_status);

cleanup:
    if (allocated_ctx && major_status != GSS_S_COMPLETE)
	gss_delete_sec_context(&junk, (gss_ctx_id_t *)&ctx, GSS_C_NO_BUFFER);

    *context_handle = (gss_ctx_id_t) ctx;

    _gss_mg_log(10, "gss-emd: return %d/%d", (int)major_status, (int)*minor_status);

    return major_status;
}
