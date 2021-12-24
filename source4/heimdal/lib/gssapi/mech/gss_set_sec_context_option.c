/*
 * Copyright (c) 2004, 2020, PADL Software Pty Ltd.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
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
gss_set_sec_context_option (OM_uint32 *minor_status,
			    gss_ctx_id_t *context_handle,
			    const gss_OID object,
			    const gss_buffer_t value)
{
	struct _gss_context	*ctx;
	OM_uint32		major_status;
	gssapi_mech_interface	mi;
	int			allocated_ctx;

	*minor_status = 0;

	if (context_handle == NULL)
		return GSS_S_CALL_INACCESSIBLE_READ;

	_gss_load_mech();

	ctx = (struct _gss_context *) *context_handle;
	if (ctx == NULL) {
		ctx = calloc(1, sizeof(*ctx));
		if (ctx == NULL) {
			*minor_status = ENOMEM;
			return GSS_S_FAILURE;
		}
		allocated_ctx = 1;
	} else {
		allocated_ctx = 0;
	}

	major_status = GSS_S_BAD_MECH;

	if (allocated_ctx) {
		struct _gss_mech_switch	*m;

		HEIM_TAILQ_FOREACH(m, &_gss_mechs, gm_link) {
			mi = &m->gm_mech;

			if (mi->gm_set_sec_context_option == NULL)
				continue;
			major_status = mi->gm_set_sec_context_option(minor_status,
				&ctx->gc_ctx, object, value);
			if (major_status == GSS_S_COMPLETE) {
				ctx->gc_mech = mi;
				break;
			} else {
				_gss_mg_error(mi, *minor_status);
			}
		}
	} else {
		mi = ctx->gc_mech;
		if (mi->gm_set_sec_context_option != NULL) {
			major_status = mi->gm_set_sec_context_option(minor_status,
				&ctx->gc_ctx, object, value);
			if (major_status != GSS_S_COMPLETE)
				_gss_mg_error(mi, *minor_status);
		}
	}

	if (allocated_ctx) {
		if (major_status == GSS_S_COMPLETE)
			*context_handle = (gss_ctx_id_t)ctx;
		else
			free(ctx);
	}

	return major_status;
}
