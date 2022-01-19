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

int
_gss_sanon_available_p(gss_const_cred_id_t claimant_cred_handle,
		       gss_const_name_t target_name,
		       OM_uint32 req_flags)
{
    OM_uint32 minor;
    gss_name_t initiator_name = GSS_C_NO_NAME;
    int available;

    if (claimant_cred_handle != GSS_C_NO_CREDENTIAL) {
	_gss_sanon_inquire_cred(&minor, claimant_cred_handle,
				&initiator_name, NULL, NULL, NULL);
	heim_assert(initiator_name != GSS_C_NO_NAME,
		    "Invalid null SAnon initiator name");
    }

    /*
     * SAnon is available if one of the following is true:
     *
     * The caller set anon_req_flag (GSS_C_ANON_FLAG)
     * The claimant_cred_handle identity is anonymous
     * The claimant_cred_handle is the default credential
     *   and target_name is anonymous
     */
    if (req_flags & GSS_C_ANON_FLAG)
	available = TRUE;
    else if (initiator_name == _gss_sanon_anonymous_identity)
	available = TRUE;
    else if (claimant_cred_handle == GSS_C_NO_CREDENTIAL &&
	target_name == _gss_sanon_anonymous_identity)
	available = TRUE;
    else
	available = FALSE;

    _gss_sanon_release_name(&minor, &initiator_name);
    return available;
}

OM_uint32 GSSAPI_CALLCONV
_gss_sanon_init_sec_context(OM_uint32 *minor,
			    gss_const_cred_id_t cred_handle,
			    gss_ctx_id_t *context_handle,
			    gss_const_name_t target_name,
			    const gss_OID mech_type,
			    OM_uint32 req_flags,
			    OM_uint32 time_req,
			    const gss_channel_bindings_t input_chan_bindings,
			    const gss_buffer_t input_token,
			    gss_OID *actual_mech_type,
			    gss_buffer_t output_token,
			    OM_uint32 *ret_flags,
			    OM_uint32 *time_rec)
{
    gss_buffer_desc mech_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 major, tmp;
    sanon_ctx sc = (sanon_ctx)*context_handle;
    OM_uint32 flags;
    gss_buffer_desc session_key = GSS_C_EMPTY_BUFFER;

    *minor = 0;
    _mg_buffer_zero(output_token);

    if (!_gss_sanon_available_p(cred_handle, target_name, req_flags)) {
	major = GSS_S_UNAVAILABLE;
	goto out;
    }

    /* we always support the following flags */
    flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG |
	    GSS_C_INTEG_FLAG | GSS_C_ANON_FLAG;
    /* we support the following optional flags */
    flags |= req_flags & SANON_PROTOCOL_FLAG_MASK;

    if (sc == NULL) {
	uint8_t pk_and_flags[crypto_scalarmult_curve25519_BYTES + 8];

	if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
	    major = GSS_S_DEFECTIVE_TOKEN;
	    goto out;
	}

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL) {
	    *minor = ENOMEM;
	    major = GSS_S_FAILURE;
	    goto out;
	}

        sc->is_initiator = 1;

	/* compute public and secret keys */
	major = _gss_sanon_curve25519_base(minor, sc);
	if (major != GSS_S_COMPLETE)
	    goto out;

	if (flags & SANON_PROTOCOL_FLAG_MASK) {
	    memcpy(pk_and_flags, sc->pk, sizeof(sc->pk));
	    _gss_mg_encode_be_uint32(0, &pk_and_flags[sizeof(sc->pk)]);
	    _gss_mg_encode_be_uint32(flags & SANON_PROTOCOL_FLAG_MASK,
				     &pk_and_flags[sizeof(sc->pk) + 4]);
	    mech_token.length = sizeof(pk_and_flags);
	    mech_token.value = pk_and_flags;
	} else {
	    mech_token.length = sizeof(sc->pk);
	    mech_token.value = sc->pk;
	}

	/* send public key to acceptor */
	major = gss_encapsulate_token(&mech_token,
				      GSS_SANON_X25519_MECHANISM,
				      output_token);
	if (major != GSS_S_COMPLETE)
	    goto out;

	*context_handle = (gss_ctx_id_t)sc;
	major = GSS_S_CONTINUE_NEEDED;
    } else {
	static gss_buffer_desc empty = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc pk, hok_mic;

	if (input_token == GSS_C_NO_BUFFER ||
	    input_token->length < crypto_scalarmult_curve25519_BYTES) {
	    major = GSS_S_DEFECTIVE_TOKEN;
	    goto out;
	} else if (sc->rfc4121 != GSS_C_NO_CONTEXT || !(sc->is_initiator)) {
	    major = GSS_S_BAD_STATUS;
	    goto out;
	}

	pk.length = crypto_scalarmult_curve25519_BYTES;
	pk.value = input_token->value;

	/* compute shared secret */
	major = _gss_sanon_curve25519(minor, sc, &pk,
				      flags & SANON_PROTOCOL_FLAG_MASK,
				      input_chan_bindings, &session_key);
	if (major != GSS_S_COMPLETE)
	    goto out;

	flags |= GSS_C_TRANS_FLAG;

	major = _gss_sanon_import_rfc4121_context(minor, sc, flags, &session_key);
	if (major != GSS_S_COMPLETE)
	    goto out;

	/* verify holder of key MIC */
	hok_mic.length = input_token->length - pk.length;
	hok_mic.value = (uint8_t *)input_token->value + pk.length;

	major = _gss_sanon_verify_mic(minor, (gss_const_ctx_id_t)sc,
				      &empty, &hok_mic, NULL);
	if (major != GSS_S_COMPLETE)
	    goto out;
    }

    if (ret_flags)
	*ret_flags = flags;
    if (time_rec)
	*time_rec = GSS_C_INDEFINITE;

out:
    if (actual_mech_type)
	*actual_mech_type = GSS_SANON_X25519_MECHANISM;

    if (GSS_ERROR(major)) {
	_gss_sanon_delete_sec_context(&tmp, (gss_ctx_id_t *)&sc, GSS_C_NO_BUFFER);
	*context_handle = GSS_C_NO_CONTEXT;
    }
    _gss_secure_release_buffer(&tmp, &session_key);

    return major;
}
