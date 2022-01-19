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
_gss_sanon_add_cred_from(OM_uint32 *minor,
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
    *minor = 0;

    if (output_cred_handle != NULL) {
	if (desired_name == GSS_C_NO_NAME ||
	    desired_name == _gss_sanon_anonymous_identity)
	    *output_cred_handle = _gss_sanon_anonymous_cred;
	else
	    *output_cred_handle = _gss_sanon_non_anonymous_cred;
    }

    if (initiator_time_rec)
	*initiator_time_rec = GSS_C_INDEFINITE;
    if (acceptor_time_rec)
	*acceptor_time_rec = GSS_C_INDEFINITE;

    return GSS_S_COMPLETE;
}
