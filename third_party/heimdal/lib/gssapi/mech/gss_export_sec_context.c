/*-
 * Copyright (c) 2005 Doug Rabson
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
 *	$FreeBSD: src/lib/libgssapi/gss_export_sec_context.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_export_sec_context(OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    gss_buffer_t interprocess_token)
{
        OM_uint32 major_status = GSS_S_FAILURE, tmp_minor;
        krb5_storage *sp;
        krb5_data data;
        krb5_error_code kret;
	struct _gss_context *ctx;
	gssapi_mech_interface m;
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
        unsigned char verflags;

	*minor_status = 0;

        if (!interprocess_token)
	    return GSS_S_CALL_INACCESSIBLE_READ;

        _mg_buffer_zero(interprocess_token);

	if (context_handle == NULL)
	    return GSS_S_NO_CONTEXT;

	ctx = (struct _gss_context *) *context_handle;
        if (ctx == NULL)
            return GSS_S_NO_CONTEXT;

        sp = krb5_storage_emem();
        if (sp == NULL) {
            *minor_status = ENOMEM;
	    goto failure;
        }
        krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_PACKED);

        verflags = 0x00;                /* Version 0 */

        if (ctx->gc_target_len)
            verflags |= EXPORT_CONTEXT_FLAG_ACCUMULATING;

        if (ctx->gc_ctx)
            verflags |= EXPORT_CONTEXT_FLAG_MECH_CTX;

        kret = krb5_store_uint8(sp, verflags);
        if (kret) {
            *minor_status = kret;
            goto failure;
        }

        if (ctx->gc_target_len) {
            _gss_mg_log(10, "gss-esc: exporting partial token %zu/%zu",
                ctx->gc_input.length, ctx->gc_target_len);
            kret = krb5_store_uint8(sp, ctx->gc_initial);
            if (kret) {
                *minor_status = kret;
                goto failure;
            }
            kret = krb5_store_uint32(sp, ctx->gc_target_len);
            if (kret) {
                *minor_status = kret;
                goto failure;
            }
	    major_status = _gss_mg_store_buffer(minor_status, sp,
						&ctx->gc_input);
            if (major_status != GSS_S_COMPLETE)
                goto failure;
        } else if (ctx->gc_ctx == GSS_C_NO_CONTEXT) {
	    gss_delete_sec_context(&tmp_minor, context_handle,
				   GSS_C_NO_BUFFER);
	    return GSS_S_NO_CONTEXT;
        }

	if (ctx->gc_ctx) {
	    m = ctx->gc_mech;

	    major_status = m->gm_export_sec_context(minor_status,
						    &ctx->gc_ctx, &buf);

	    if (major_status != GSS_S_COMPLETE) {
		_gss_mg_error(m, *minor_status);
		goto failure;
	    }

	    major_status = _gss_mg_store_oid(minor_status, sp,
					     &m->gm_mech_oid);
	    if (major_status != GSS_S_COMPLETE)
		goto failure;

	    major_status = _gss_mg_store_buffer(minor_status, sp, &buf);
	    if (major_status != GSS_S_COMPLETE)
		goto failure;
	}

        kret = krb5_storage_to_data(sp, &data);
        if (kret) {
            *minor_status = kret;
            goto failure;
        }

        interprocess_token->length = data.length;
        interprocess_token->value  = data.data;

	major_status = GSS_S_COMPLETE;

        _gss_mg_log(1, "gss-esc: token length %zu", data.length);

failure:
	if (major_status == GSS_S_COMPLETE && *minor_status == 0)
	    gss_delete_sec_context(&tmp_minor, context_handle,
				   GSS_C_NO_BUFFER);
	else if (*minor_status)
	    major_status = GSS_S_FAILURE;

	_gss_secure_release_buffer(minor_status, &buf);
        krb5_storage_free(sp);
        return major_status;
}
