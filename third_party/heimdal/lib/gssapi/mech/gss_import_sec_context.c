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
 *	$FreeBSD: src/lib/libgssapi/gss_import_sec_context.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_import_sec_context(OM_uint32 *minor_status,
    const gss_buffer_t interprocess_token,
    gss_ctx_id_t *context_handle)
{
        OM_uint32 ret = GSS_S_FAILURE, tmp_minor;
        krb5_storage *sp;
	gssapi_mech_interface m;
        struct _gss_context *ctx = NULL;
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
        unsigned char verflags;

        _gss_mg_log(10, "gss-isc called");

        if (!context_handle) {
            *minor_status = EFAULT;
            return GSS_S_CALL_INACCESSIBLE_WRITE;
        }

	*minor_status = 0;
	*context_handle = GSS_C_NO_CONTEXT;

        sp = krb5_storage_from_mem(interprocess_token->value,
                                   interprocess_token->length);
        if (!sp) {
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_PACKED);

        ctx = calloc(1, sizeof(struct _gss_context));
        if (!ctx) {
            *minor_status = ENOMEM;
            goto failure;
        }

        if (krb5_ret_uint8(sp, &verflags))
            goto failure;

        if ((verflags & EXPORT_CONTEXT_VERSION_MASK) != 0) {
            _gss_mg_log(10, "gss-isc failed, token version %d not recognised",
                (int)(verflags & EXPORT_CONTEXT_VERSION_MASK));
            /* We don't recognise the version */
            goto failure;
        }

        if (verflags & EXPORT_CONTEXT_FLAG_ACCUMULATING) {
            uint32_t target_len;

            if (krb5_ret_uint8(sp, &ctx->gc_initial))
                goto failure;

            if (krb5_ret_uint32(sp, &target_len))
                goto failure;

	    ret = _gss_mg_ret_buffer(minor_status, sp, &buf);
            if (ret != GSS_S_COMPLETE)
                goto failure;

            ctx->gc_free_this = ctx->gc_input.value = calloc(target_len, 1);
	    if (ctx->gc_input.value == NULL)
		goto failure;

            ctx->gc_target_len   = target_len;
            ctx->gc_input.length = buf.length;
	    if (buf.value)
		memcpy(ctx->gc_input.value, buf.value, buf.length);

	    gss_release_buffer(&tmp_minor, &buf);
        }

        if (verflags & EXPORT_CONTEXT_FLAG_MECH_CTX) {
	    gss_OID mech_oid;

	    ret = _gss_mg_ret_oid(minor_status, sp, &mech_oid);
            if (ret != GSS_S_COMPLETE)
                goto failure;

	    if (mech_oid == GSS_C_NO_OID) {
		ret = GSS_S_BAD_MECH;
		goto failure;
	    }

            m = __gss_get_mechanism(mech_oid);
            if (m == NULL) {
                ret = GSS_S_DEFECTIVE_TOKEN;
		goto failure;
	    }
            ctx->gc_mech = m;

	    ret = _gss_mg_ret_buffer(minor_status, sp, &buf);
	    if (ret != GSS_S_COMPLETE)
		goto failure;

	    if (buf.value == NULL) {
		ret = GSS_S_DEFECTIVE_TOKEN;
		goto failure;
	    }

            ret = m->gm_import_sec_context(minor_status, &buf, &ctx->gc_ctx);
            if (ret != GSS_S_COMPLETE) {
                _gss_mg_error(m, *minor_status);
                goto failure;
	    }
        }

	*context_handle = (gss_ctx_id_t) ctx;
	ctx = NULL;

	ret = GSS_S_COMPLETE;

failure:
        free(ctx);
        krb5_storage_free(sp);
	_gss_secure_release_buffer(&tmp_minor, &buf);
        return ret;
}
