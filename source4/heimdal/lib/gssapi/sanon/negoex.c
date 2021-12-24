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
_gssspi_sanon_query_mechanism_info(OM_uint32 *minor,
				   gss_const_OID mech_oid,
				   unsigned char auth_scheme[16])
{
    heim_assert(gss_oid_equal(mech_oid, GSS_SANON_X25519_MECHANISM),
		"Invalid mechanism OID passed to query_mechanism_info");

    *minor = 0;

    /* {DEE384FF-1086-4E86-BE78-B94170BFD376} */
    memcpy(auth_scheme,
	   "\xff\x84\xe3\xde\x86\x10\x86\x4e\xbe\x78\xb9\x41\x70\xbf\xd3\x76", 16);

    return GSS_S_COMPLETE;
}

OM_uint32
_gss_sanon_inquire_negoex_key(OM_uint32 *minor,
			      const sanon_ctx sc,
			      gss_const_OID desired_object,
			      gss_buffer_set_t *data_set)
{
    OM_uint32 major, tmpMinor;
    int initiator_key;
    uint8_t typebytes[4];
    gss_buffer_desc salt, keyvalue = GSS_C_EMPTY_BUFFER, keytype;

    if (sc->rfc4121 == GSS_C_NO_CONTEXT) {
	*minor = KRB5KRB_AP_ERR_NOKEY;
	return GSS_S_UNAVAILABLE;
    }

    initiator_key = !!(sc->is_initiator);

    if (gss_oid_equal(desired_object, GSS_C_INQ_NEGOEX_VERIFY_KEY))
	initiator_key ^= 1;
    else if (!gss_oid_equal(desired_object, GSS_C_INQ_NEGOEX_KEY))
        return GSS_S_UNAVAILABLE;

    if (initiator_key) {
        salt.length = sizeof("sanon-x25519-initiator-negoex-key") - 1;
        salt.value  = "sanon-x25519-initiator-negoex-key";
    } else {
        salt.length = sizeof("sanon-x25519-acceptor-negoex-key") - 1;
        salt.value  = "sanon-x25519-acceptor-negoex-key";
    }

    _gss_mg_encode_le_uint32(KRB5_ENCTYPE_AES128_CTS_HMAC_SHA256_128, typebytes);

    keytype.length = sizeof(typebytes);
    keytype.value = typebytes;

    major = gss_pseudo_random(minor, sc->rfc4121,
			      GSS_C_PRF_KEY_FULL, &salt,
			      16, &keyvalue);
    if (major == GSS_S_COMPLETE)
	major = gss_add_buffer_set_member(minor, &keyvalue, data_set);
    if (major == GSS_S_COMPLETE)
	major = gss_add_buffer_set_member(minor, &keytype, data_set);

    _gss_secure_release_buffer(&tmpMinor, &keyvalue);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
_gssspi_sanon_query_meta_data(OM_uint32 *minor,
			      gss_const_OID mech_oid,
			      gss_cred_id_t cred_handle,
			      gss_ctx_id_t *context_handle,
			      gss_const_name_t targ_name,
			      OM_uint32 req_flags,
			      gss_buffer_t meta_data)
{
    int is_initiator = (targ_name != GSS_C_NO_NAME);

    *minor = 0;

    if (is_initiator &&
	!_gss_sanon_available_p(cred_handle, targ_name, req_flags))
	return GSS_S_UNAVAILABLE;

    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gssspi_sanon_exchange_meta_data(OM_uint32 *minor,
				 gss_const_OID mech_oid,
				 gss_cred_id_t cred_handle,
				 gss_ctx_id_t *context_handle,
				 gss_const_name_t targ_name,
				 OM_uint32 req_flags,
				 gss_const_buffer_t meta_data)
{
    *minor = 0;
    return GSS_S_COMPLETE;
}
