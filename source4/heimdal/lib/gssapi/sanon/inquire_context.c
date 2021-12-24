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
_gss_sanon_inquire_context(OM_uint32 *minor,
			   gss_const_ctx_id_t context_handle,
			   gss_name_t *src_name,
			   gss_name_t *targ_name,
			   OM_uint32 *lifetime_rec,
			   gss_OID *mech_type,
			   OM_uint32 *ctx_flags,
			   int *locally_initiated,
			   int *open_context)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;
    OM_uint32 major = GSS_S_COMPLETE;

    *minor = 0;

    if (sc == NULL)
	return GSS_S_NO_CONTEXT;

    if (src_name)
	*src_name = _gss_sanon_anonymous_identity;
    if (targ_name)
	*targ_name = _gss_sanon_anonymous_identity;
    if (lifetime_rec)
	*lifetime_rec = GSS_C_INDEFINITE;
    if (mech_type)
	*mech_type = GSS_SANON_X25519_MECHANISM;
    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
        if (locally_initiated)
            *locally_initiated = sc->is_initiator;
        if (open_context)
            *open_context = 0;
        if (ctx_flags)
            *ctx_flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG |
			 GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_ANON_FLAG;
    } else {
        major = gss_inquire_context(minor, sc->rfc4121, NULL, NULL, NULL,
                                    NULL, ctx_flags, locally_initiated,
                                    open_context);
    }
    return major;
}
