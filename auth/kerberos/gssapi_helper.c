/*
   Unix SMB/CIFS implementation.
   GSSAPI helper functions

   Copyright (C) Stefan Metzmacher 2008,2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/gssapi.h"
#include "auth/kerberos/pac_utils.h"
#include "auth/kerberos/gssapi_helper.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

size_t gssapi_get_sig_size(gss_ctx_id_t gssapi_context,
			   const gss_OID mech,
			   uint32_t gss_want_flags,
			   size_t data_size)
{
	TALLOC_CTX *frame = talloc_stackframe();
	size_t sig_size = 0;

	if (gss_want_flags & GSS_C_CONF_FLAG) {
		OM_uint32 min_stat, maj_stat;
		bool want_sealing = true;
		int sealed = 0;
		gss_iov_buffer_desc iov[2];

		if (!(gss_want_flags & GSS_C_DCE_STYLE)) {
			TALLOC_FREE(frame);
			return 0;
		}

		/*
		 * gss_wrap_iov_length() only needs the type and length
		 */
		iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
		iov[0].buffer.value = NULL;
		iov[0].buffer.length = 0;
		iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
		iov[1].buffer.value = NULL;
		iov[1].buffer.length = data_size;

		maj_stat = gss_wrap_iov_length(&min_stat,
					       gssapi_context,
					       want_sealing,
					       GSS_C_QOP_DEFAULT,
					       &sealed,
					       iov, ARRAY_SIZE(iov));
		if (maj_stat) {
			DEBUG(0, ("gss_wrap_iov_length failed with [%s]\n",
				  gssapi_error_string(frame,
						      maj_stat,
						      min_stat,
						      mech)));
			TALLOC_FREE(frame);
			return 0;
		}

		sig_size = iov[0].buffer.length;
	} else if (gss_want_flags & GSS_C_INTEG_FLAG) {
		NTSTATUS status;
		uint32_t keytype;

		status = gssapi_get_session_key(frame,
						gssapi_context,
						NULL, &keytype);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return 0;
		}

		switch (keytype) {
		case ENCTYPE_DES_CBC_MD5:
		case ENCTYPE_DES_CBC_CRC:
		case ENCTYPE_ARCFOUR_HMAC:
		case ENCTYPE_ARCFOUR_HMAC_EXP:
			sig_size = 37;
			break;
		default:
			sig_size = 28;
			break;
		}
	}

	TALLOC_FREE(frame);
	return sig_size;
}

NTSTATUS gssapi_seal_packet(gss_ctx_id_t gssapi_context,
			    const gss_OID mech,
			    bool hdr_signing, size_t sig_size,
			    uint8_t *data, size_t length,
			    const uint8_t *whole_pdu, size_t pdu_length,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *sig)
{
	OM_uint32 maj_stat, min_stat;
	gss_iov_buffer_desc iov[4];
	int req_seal = 1;
	int sealed = 0;
	const uint8_t *pre_sign_ptr = NULL;
	size_t pre_sign_len = 0;
	const uint8_t *post_sign_ptr = NULL;
	size_t post_sign_len = 0;

	if (hdr_signing) {
		const uint8_t *de = data + length;
		const uint8_t *we = whole_pdu + pdu_length;

		if (data < whole_pdu) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (de > we) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		pre_sign_len = data - whole_pdu;
		if (pre_sign_len > 0) {
			pre_sign_ptr = whole_pdu;
		}
		post_sign_len = we - de;
		if (post_sign_len > 0) {
			post_sign_ptr = de;
		}
	}

	sig->length = sig_size;
	if (sig->length == 0) {
		return NT_STATUS_ACCESS_DENIED;
	}

	sig->data = talloc_zero_array(mem_ctx, uint8_t, sig->length);
	if (sig->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	iov[0].type          = GSS_IOV_BUFFER_TYPE_HEADER;
	iov[0].buffer.length = sig->length;
	iov[0].buffer.value  = sig->data;

	if (pre_sign_ptr != NULL) {
		iov[1].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
		iov[1].buffer.length = pre_sign_len;
		iov[1].buffer.value = discard_const(pre_sign_ptr);
	} else {
		iov[1].type = GSS_IOV_BUFFER_TYPE_EMPTY;
		iov[1].buffer.length = 0;
		iov[1].buffer.value = NULL;
	}

	/* data is encrypted in place, which is ok */
	iov[2].type          = GSS_IOV_BUFFER_TYPE_DATA;
	iov[2].buffer.length = length;
	iov[2].buffer.value  = data;

	if (post_sign_ptr != NULL) {
		iov[3].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
		iov[3].buffer.length = post_sign_len;
		iov[3].buffer.value = discard_const(post_sign_ptr);
	} else {
		iov[3].type = GSS_IOV_BUFFER_TYPE_EMPTY;
		iov[3].buffer.length = 0;
		iov[3].buffer.value = NULL;
	}

	maj_stat = gss_wrap_iov(&min_stat,
				gssapi_context,
				req_seal,
				GSS_C_QOP_DEFAULT,
				&sealed,
				iov, ARRAY_SIZE(iov));
	if (GSS_ERROR(maj_stat)) {
		char *error_string = gssapi_error_string(mem_ctx,
							 maj_stat,
							 min_stat,
							 mech);
		DEBUG(1, ("gss_wrap_iov failed: %s\n", error_string));
		talloc_free(error_string);
		data_blob_free(sig);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (req_seal == 1 && sealed == 0) {
		DEBUG(0, ("gss_wrap_iov says data was not sealed!\n"));
		data_blob_free(sig);
		return NT_STATUS_ACCESS_DENIED;
	}

	dump_data_pw("gssapi_seal_packet: sig\n", sig->data, sig->length);
	dump_data_pw("gssapi_seal_packet: sealed\n", data, length);

	DEBUG(10, ("Sealed %d bytes, and got %d bytes header/signature.\n",
		   (int)iov[2].buffer.length, (int)iov[0].buffer.length));

	return NT_STATUS_OK;
}

NTSTATUS gssapi_unseal_packet(gss_ctx_id_t gssapi_context,
			      const gss_OID mech,
			      bool hdr_signing,
			      uint8_t *data, size_t length,
			      const uint8_t *whole_pdu, size_t pdu_length,
			      const DATA_BLOB *sig)
{
	OM_uint32 maj_stat, min_stat;
	gss_iov_buffer_desc iov[4];
	gss_qop_t qop_state;
	int sealed = 0;
	const uint8_t *pre_sign_ptr = NULL;
	size_t pre_sign_len = 0;
	const uint8_t *post_sign_ptr = NULL;
	size_t post_sign_len = 0;

	if (hdr_signing) {
		const uint8_t *de = data + length;
		const uint8_t *we = whole_pdu + pdu_length;

		if (data < whole_pdu) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (de > we) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		pre_sign_len = data - whole_pdu;
		if (pre_sign_len > 0) {
			pre_sign_ptr = whole_pdu;
		}
		post_sign_len = we - de;
		if (post_sign_len > 0) {
			post_sign_ptr = de;
		}
	}

	dump_data_pw("gssapi_unseal_packet: sig\n", sig->data, sig->length);
	dump_data_pw("gssapi_unseal_packet: sealed\n", data, length);

	iov[0].type          = GSS_IOV_BUFFER_TYPE_HEADER;
	iov[0].buffer.length = sig->length;
	iov[0].buffer.value  = sig->data;

	if (pre_sign_ptr != NULL) {
		iov[1].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
		iov[1].buffer.length = pre_sign_len;
		iov[1].buffer.value = discard_const(pre_sign_ptr);
	} else {
		iov[1].type = GSS_IOV_BUFFER_TYPE_EMPTY;
		iov[1].buffer.length = 0;
		iov[1].buffer.value = NULL;
	}

	/* data is encrypted in place, which is ok */
	iov[2].type          = GSS_IOV_BUFFER_TYPE_DATA;
	iov[2].buffer.length = length;
	iov[2].buffer.value  = data;

	if (post_sign_ptr != NULL) {
		iov[3].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY;
		iov[3].buffer.length = post_sign_len;
		iov[3].buffer.value = discard_const(post_sign_ptr);
	} else {
		iov[3].type = GSS_IOV_BUFFER_TYPE_EMPTY;
		iov[3].buffer.length = 0;
		iov[3].buffer.value = NULL;
	}

	maj_stat = gss_unwrap_iov(&min_stat,
				  gssapi_context,
				  &sealed,
				  &qop_state,
				  iov, ARRAY_SIZE(iov));
	if (GSS_ERROR(maj_stat)) {
		char *error_string = gssapi_error_string(NULL,
							 maj_stat,
							 min_stat,
							 mech);
		DEBUG(1, ("gss_unwrap_iov failed: %s\n", error_string));
		talloc_free(error_string);

		return NT_STATUS_ACCESS_DENIED;
	}

	if (sealed == 0) {
		DEBUG(0, ("gss_unwrap_iov says data was not sealed!\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(10, ("Unsealed %d bytes, with %d bytes header/signature.\n",
		   (int)iov[2].buffer.length, (int)iov[0].buffer.length));

	return NT_STATUS_OK;
}

NTSTATUS gssapi_sign_packet(gss_ctx_id_t gssapi_context,
			    const gss_OID mech,
			    bool hdr_signing,
			    const uint8_t *data, size_t length,
			    const uint8_t *whole_pdu, size_t pdu_length,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *sig)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token;

	if (hdr_signing) {
		input_token.length = pdu_length;
		input_token.value = discard_const_p(uint8_t *, whole_pdu);
	} else {
		input_token.length = length;
		input_token.value = discard_const_p(uint8_t *, data);
	}

	maj_stat = gss_get_mic(&min_stat,
			       gssapi_context,
			       GSS_C_QOP_DEFAULT,
			       &input_token,
			       &output_token);
	if (GSS_ERROR(maj_stat)) {
		char *error_string = gssapi_error_string(mem_ctx,
							 maj_stat,
							 min_stat,
							 mech);
		DEBUG(1, ("GSS GetMic failed: %s\n", error_string));
		talloc_free(error_string);
		return NT_STATUS_ACCESS_DENIED;
	}

	*sig = data_blob_talloc(mem_ctx, (uint8_t *)output_token.value, output_token.length);
	gss_release_buffer(&min_stat, &output_token);
	if (sig->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	dump_data_pw("gssapi_sign_packet: sig\n", sig->data, sig->length);

	return NT_STATUS_OK;
}

NTSTATUS gssapi_check_packet(gss_ctx_id_t gssapi_context,
			     const gss_OID mech,
			     bool hdr_signing,
			     const uint8_t *data, size_t length,
			     const uint8_t *whole_pdu, size_t pdu_length,
			     const DATA_BLOB *sig)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token;
	gss_buffer_desc input_message;
	gss_qop_t qop_state;

	dump_data_pw("gssapi_check_packet: sig\n", sig->data, sig->length);

	if (hdr_signing) {
		input_message.length = pdu_length;
		input_message.value = discard_const(whole_pdu);
	} else {
		input_message.length = length;
		input_message.value = discard_const(data);
	}

	input_token.length = sig->length;
	input_token.value = sig->data;

	maj_stat = gss_verify_mic(&min_stat,
				  gssapi_context,
				  &input_message,
				  &input_token,
				  &qop_state);
	if (GSS_ERROR(maj_stat)) {
		char *error_string = gssapi_error_string(NULL,
							 maj_stat,
							 min_stat,
							 mech);
		DEBUG(1, ("GSS VerifyMic failed: %s\n", error_string));
		talloc_free(error_string);

		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}
