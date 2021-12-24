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
_gss_sanon_inquire_sec_context_by_oid(OM_uint32 *minor,
				      gss_const_ctx_id_t context_handle,
				      const gss_OID desired_object,
				      gss_buffer_set_t *data_set)
{
    const sanon_ctx sc = (const sanon_ctx)context_handle;

    if (sc == NULL)
	return GSS_S_NO_CONTEXT;

    *data_set = GSS_C_NO_BUFFER_SET;

    if (gss_oid_equal(desired_object, GSS_C_INQ_SSPI_SESSION_KEY) ||
        gss_oid_equal(desired_object, GSS_KRB5_GET_SUBKEY_X) ||
        gss_oid_equal(desired_object, GSS_KRB5_GET_INITIATOR_SUBKEY_X) ||
        gss_oid_equal(desired_object, GSS_KRB5_GET_ACCEPTOR_SUBKEY_X) ||
        gss_oid_equal(desired_object, GSS_KRB5_EXPORT_LUCID_CONTEXT_X))
	return gss_inquire_sec_context_by_oid(minor, sc->rfc4121,
					      desired_object, data_set);
    else if (gss_oid_equal(desired_object, GSS_C_INQ_NEGOEX_KEY) ||
	     gss_oid_equal(desired_object, GSS_C_INQ_NEGOEX_VERIFY_KEY))
	return _gss_sanon_inquire_negoex_key(minor, sc, desired_object, data_set);
    else {
	*minor = EINVAL;
	return GSS_S_UNAVAILABLE;
    }
}
