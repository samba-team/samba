/*
 * Copyright (c) 2019-2020, AuriStor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "sanon_locl.h"


OM_uint32 GSSAPI_CALLCONV
_gss_sanon_delete_sec_context(OM_uint32 *minor,
			      gss_ctx_id_t *context_handle,
			      gss_buffer_t output_token)
{
    sanon_ctx sc;

    *minor = 0;

    if (output_token != GSS_C_NO_BUFFER) {
	output_token->length = 0;
	output_token->value  = NULL;
    }

    if (*context_handle == GSS_C_NO_CONTEXT)
	return GSS_S_COMPLETE;

    sc = (sanon_ctx)*context_handle;

    *context_handle = GSS_C_NO_CONTEXT;

    gss_delete_sec_context(minor, &sc->rfc4121, GSS_C_NO_BUFFER);

    memset_s(sc, sizeof(*sc), 0, sizeof(*sc));
    free(sc);

    return GSS_S_COMPLETE;
}
