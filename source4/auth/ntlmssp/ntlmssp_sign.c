/*
 *  Unix SMB/CIFS implementation.
 *  Version 3.0
 *  NTLMSSP Signing routines
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2001
 *  Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003-2005
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "auth/ntlmssp/ntlmssp.h"
#include "auth/gensec/gensec.h"
#include "../libcli/auth/ntlmssp_private.h"

NTSTATUS gensec_ntlmssp_sign_packet(struct gensec_security *gensec_security,
				    TALLOC_CTX *sig_mem_ctx,
				    const uint8_t *data, size_t length,
				    const uint8_t *whole_pdu, size_t pdu_length,
				    DATA_BLOB *sig)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	NTSTATUS nt_status;

	nt_status = ntlmssp_sign_packet(gensec_ntlmssp->ntlmssp_state,
					sig_mem_ctx,
					data, length,
					whole_pdu, pdu_length,
					sig);

	return nt_status;
}

NTSTATUS gensec_ntlmssp_check_packet(struct gensec_security *gensec_security,
				     TALLOC_CTX *sig_mem_ctx,
				     const uint8_t *data, size_t length,
				     const uint8_t *whole_pdu, size_t pdu_length,
				     const DATA_BLOB *sig)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	NTSTATUS nt_status;

	nt_status = ntlmssp_check_packet(gensec_ntlmssp->ntlmssp_state,
					 data, length,
					 whole_pdu, pdu_length,
					 sig);

	return nt_status;
}

NTSTATUS gensec_ntlmssp_seal_packet(struct gensec_security *gensec_security,
				    TALLOC_CTX *sig_mem_ctx,
				    uint8_t *data, size_t length,
				    const uint8_t *whole_pdu, size_t pdu_length,
				    DATA_BLOB *sig)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	NTSTATUS nt_status;

	nt_status = ntlmssp_seal_packet(gensec_ntlmssp->ntlmssp_state,
					sig_mem_ctx,
					data, length,
					whole_pdu, pdu_length,
					sig);

	return nt_status;
}

/*
  wrappers for the ntlmssp_*() functions
*/
NTSTATUS gensec_ntlmssp_unseal_packet(struct gensec_security *gensec_security,
				      TALLOC_CTX *sig_mem_ctx,
				      uint8_t *data, size_t length,
				      const uint8_t *whole_pdu, size_t pdu_length,
				      const DATA_BLOB *sig)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	NTSTATUS nt_status;

	nt_status = ntlmssp_unseal_packet(gensec_ntlmssp->ntlmssp_state,
					  data, length,
					  whole_pdu, pdu_length,
					  sig);

	return nt_status;
}

size_t gensec_ntlmssp_sig_size(struct gensec_security *gensec_security, size_t data_size) 
{
	return NTLMSSP_SIG_SIZE;
}

NTSTATUS gensec_ntlmssp_wrap(struct gensec_security *gensec_security, 
			     TALLOC_CTX *sig_mem_ctx, 
			     const DATA_BLOB *in, 
			     DATA_BLOB *out)
{
	DATA_BLOB sig;
	NTSTATUS nt_status;

	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {

		*out = data_blob_talloc(sig_mem_ctx, NULL, in->length + NTLMSSP_SIG_SIZE);
		if (!out->data) {
			return NT_STATUS_NO_MEMORY;
		}
		memcpy(out->data + NTLMSSP_SIG_SIZE, in->data, in->length);
		
	        nt_status = gensec_ntlmssp_seal_packet(gensec_security, sig_mem_ctx, 
						       out->data + NTLMSSP_SIG_SIZE, 
						       out->length - NTLMSSP_SIG_SIZE, 
						       out->data + NTLMSSP_SIG_SIZE, 
						       out->length - NTLMSSP_SIG_SIZE, 
						       &sig);
		
		if (NT_STATUS_IS_OK(nt_status)) {
			memcpy(out->data, sig.data, NTLMSSP_SIG_SIZE);
		}
		return nt_status;

	} else if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {

		*out = data_blob_talloc(sig_mem_ctx, NULL, in->length + NTLMSSP_SIG_SIZE);
		if (!out->data) {
			return NT_STATUS_NO_MEMORY;
		}
		memcpy(out->data + NTLMSSP_SIG_SIZE, in->data, in->length);

	        nt_status = gensec_ntlmssp_sign_packet(gensec_security, sig_mem_ctx, 
						       out->data + NTLMSSP_SIG_SIZE, 
						       out->length - NTLMSSP_SIG_SIZE, 
						       out->data + NTLMSSP_SIG_SIZE, 
						       out->length - NTLMSSP_SIG_SIZE, 
						       &sig);

		if (NT_STATUS_IS_OK(nt_status)) {
			memcpy(out->data, sig.data, NTLMSSP_SIG_SIZE);
		}
		return nt_status;

	} else {
		*out = *in;
		return NT_STATUS_OK;
	}
}


NTSTATUS gensec_ntlmssp_unwrap(struct gensec_security *gensec_security, 
			       TALLOC_CTX *sig_mem_ctx, 
			       const DATA_BLOB *in, 
			       DATA_BLOB *out)
{
	struct gensec_ntlmssp_context *gensec_ntlmssp =
		talloc_get_type_abort(gensec_security->private_data,
				      struct gensec_ntlmssp_context);
	struct ntlmssp_state *ntlmssp_state = gensec_ntlmssp->ntlmssp_state;
	DATA_BLOB sig;

	if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SEAL)) {
		if (in->length < NTLMSSP_SIG_SIZE) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		sig.data = in->data;
		sig.length = NTLMSSP_SIG_SIZE;

		*out = data_blob_talloc(sig_mem_ctx, in->data + NTLMSSP_SIG_SIZE, in->length - NTLMSSP_SIG_SIZE);
		
	        return gensec_ntlmssp_unseal_packet(gensec_security, sig_mem_ctx, 
						    out->data, out->length, 
						    out->data, out->length, 
						    &sig);
						  
	} else if (gensec_have_feature(gensec_security, GENSEC_FEATURE_SIGN)) {
		NTSTATUS status;
		struct ntlmssp_crypt_direction save_direction;

		if (in->length < NTLMSSP_SIG_SIZE) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		sig.data = in->data;
		sig.length = NTLMSSP_SIG_SIZE;
		*out = data_blob_talloc(sig_mem_ctx, in->data + NTLMSSP_SIG_SIZE, in->length - NTLMSSP_SIG_SIZE);

		if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
			save_direction = ntlmssp_state->crypt->ntlm2.receiving;
		} else {
			save_direction = ntlmssp_state->crypt->ntlm;
		}

		status = gensec_ntlmssp_check_packet(gensec_security, sig_mem_ctx,
						     out->data, out->length,
						     out->data, out->length,
						     &sig);
		if (!NT_STATUS_IS_OK(status)) {
			NTSTATUS check_status = status;
			/*
			 * The Windows LDAP libraries seems to have a bug
			 * and always use sealing even if only signing was
			 * negotiated. So we need to fallback.
			 */

			if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
				ntlmssp_state->crypt->ntlm2.receiving = save_direction;
			} else {
				ntlmssp_state->crypt->ntlm = save_direction;
			}

			status = gensec_ntlmssp_unseal_packet(gensec_security,
							      sig_mem_ctx,
							      out->data,
							      out->length,
							      out->data,
							      out->length,
							      &sig);
			if (NT_STATUS_IS_OK(status)) {
				ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
			} else {
				status = check_status;
			}
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("NTLMSSP packet check for unwrap failed due to invalid signature\n"));
		}
		return status;
	} else {
		*out = *in;
		return NT_STATUS_OK;
	}
}

