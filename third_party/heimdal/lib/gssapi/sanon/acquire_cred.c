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

/* SAnon credential handles are aliases of their underyling name */

OM_uint32 GSSAPI_CALLCONV
_gss_sanon_acquire_cred_from(OM_uint32 *minor,
			     gss_const_name_t desired_name,
			     OM_uint32 time_req,
			     const gss_OID_set desired_mechs,
			     gss_cred_usage_t cred_usage,
			     gss_const_key_value_set_t cred_stor,
			     gss_cred_id_t *output_cred_handle,
			     gss_OID_set *actual_mechs,
			     OM_uint32 *time_rec)
{
    *minor = 0;

    if (desired_name == GSS_C_NO_NAME ||
	desired_name == _gss_sanon_anonymous_identity)
	*output_cred_handle = _gss_sanon_anonymous_cred;
    else
	*output_cred_handle = _gss_sanon_non_anonymous_cred;

    if (time_rec)
	*time_rec = GSS_C_INDEFINITE;

    return GSS_S_COMPLETE;
}
