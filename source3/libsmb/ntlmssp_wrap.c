/*
   NLTMSSP wrappers

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2003,2011

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
#include "auth/ntlmssp/ntlmssp.h"
#include "ntlmssp_wrap.h"
#include "auth/gensec/gensec.h"

NTSTATUS auth_ntlmssp_sign_packet(struct auth_ntlmssp_state *ans,
				  TALLOC_CTX *sig_mem_ctx,
				  const uint8_t *data,
				  size_t length,
				  const uint8_t *whole_pdu,
				  size_t pdu_length,
				  DATA_BLOB *sig)
{
	if (ans->gensec_security) {
		return gensec_sign_packet(ans->gensec_security,
					  sig_mem_ctx, data, length, whole_pdu, pdu_length, sig);
	}
	return ntlmssp_sign_packet(ans->ntlmssp_state,
				   sig_mem_ctx,
				   data, length,
				   whole_pdu, pdu_length,
				   sig);
}

NTSTATUS auth_ntlmssp_check_packet(struct auth_ntlmssp_state *ans,
				   const uint8_t *data,
				   size_t length,
				   const uint8_t *whole_pdu,
				   size_t pdu_length,
				   const DATA_BLOB *sig)
{
	if (ans->gensec_security) {
		return gensec_check_packet(ans->gensec_security,
					   data, length, whole_pdu, pdu_length, sig);
	}
	return ntlmssp_check_packet(ans->ntlmssp_state,
				    data, length,
				    whole_pdu, pdu_length,
				    sig);
}

NTSTATUS auth_ntlmssp_seal_packet(struct auth_ntlmssp_state *ans,
				  TALLOC_CTX *sig_mem_ctx,
				  uint8_t *data,
				  size_t length,
				  const uint8_t *whole_pdu,
				  size_t pdu_length,
				  DATA_BLOB *sig)
{
	if (ans->gensec_security) {
		return gensec_seal_packet(ans->gensec_security,
					  sig_mem_ctx, data, length, whole_pdu, pdu_length, sig);
	}
	return ntlmssp_seal_packet(ans->ntlmssp_state,
				   sig_mem_ctx,
				   data, length,
				   whole_pdu, pdu_length,
				   sig);
}

NTSTATUS auth_ntlmssp_unseal_packet(struct auth_ntlmssp_state *ans,
				    uint8_t *data,
				    size_t length,
				    const uint8_t *whole_pdu,
				    size_t pdu_length,
				    const DATA_BLOB *sig)
{
	if (ans->gensec_security) {
		return gensec_unseal_packet(ans->gensec_security,
					    data, length, whole_pdu, pdu_length, sig);
	}
	return ntlmssp_unseal_packet(ans->ntlmssp_state,
				     data, length,
				     whole_pdu, pdu_length,
				     sig);
}

bool auth_ntlmssp_negotiated_sign(struct auth_ntlmssp_state *ans)
{
	if (ans->gensec_security) {
		return gensec_have_feature(ans->gensec_security, GENSEC_FEATURE_SIGN);
	}
	return ans->ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SIGN;
}

bool auth_ntlmssp_negotiated_seal(struct auth_ntlmssp_state *ans)
{
	if (ans->gensec_security) {
		return gensec_have_feature(ans->gensec_security, GENSEC_FEATURE_SEAL);
	}
	return ans->ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SEAL;
}

NTSTATUS auth_ntlmssp_set_username(struct auth_ntlmssp_state *ans,
				   const char *user)
{
	return ntlmssp_set_username(ans->ntlmssp_state, user);
}

NTSTATUS auth_ntlmssp_set_domain(struct auth_ntlmssp_state *ans,
				 const char *domain)
{
	return ntlmssp_set_domain(ans->ntlmssp_state, domain);
}

NTSTATUS auth_ntlmssp_set_password(struct auth_ntlmssp_state *ans,
				   const char *password)
{
	return ntlmssp_set_password(ans->ntlmssp_state, password);
}

void auth_ntlmssp_want_feature(struct auth_ntlmssp_state *ans, uint32_t feature)
{
	if (ans->gensec_security) {
		if (feature & NTLMSSP_FEATURE_SESSION_KEY) {
			gensec_want_feature(ans->gensec_security, GENSEC_FEATURE_SESSION_KEY);
		}
		if (feature & NTLMSSP_FEATURE_SIGN) {
			gensec_want_feature(ans->gensec_security, GENSEC_FEATURE_SIGN);
		}
		if (feature & NTLMSSP_FEATURE_SEAL) {
			gensec_want_feature(ans->gensec_security, GENSEC_FEATURE_SEAL);
		}
	} else {
		ntlmssp_want_feature(ans->ntlmssp_state, feature);
	}
}

DATA_BLOB auth_ntlmssp_get_session_key(struct auth_ntlmssp_state *ans, TALLOC_CTX *mem_ctx)
{
	if (ans->gensec_security) {
		DATA_BLOB session_key;
		NTSTATUS status = gensec_session_key(ans->gensec_security, mem_ctx, &session_key);
		if (NT_STATUS_IS_OK(status)) {
			return session_key;
		} else {
			return data_blob_null;
		}
	}
	return data_blob_talloc(mem_ctx, ans->ntlmssp_state->session_key.data, ans->ntlmssp_state->session_key.length);
}

NTSTATUS auth_ntlmssp_update(struct auth_ntlmssp_state *ans,
			     TALLOC_CTX *mem_ctx,
			     const DATA_BLOB request, DATA_BLOB *reply)
{
	NTSTATUS status;
	if (ans->gensec_security) {
		return gensec_update(ans->gensec_security, mem_ctx, NULL, request, reply);
	}
	status = ntlmssp_update(ans->ntlmssp_state, request, reply);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return status;
	}
	talloc_steal(mem_ctx, reply->data);
	return status;
}

NTSTATUS auth_ntlmssp_client_prepare(TALLOC_CTX *mem_ctx,
				   struct auth_ntlmssp_state **_ans)
{
	struct auth_ntlmssp_state *ans;
	NTSTATUS status;

	ans = talloc_zero(mem_ctx, struct auth_ntlmssp_state);

	status = ntlmssp_client_start(ans,
				      lp_netbios_name(), lp_workgroup(),
				      lp_client_ntlmv2_auth(), &ans->ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_ans = ans;
	return NT_STATUS_OK;
}

NTSTATUS auth_ntlmssp_client_start(struct auth_ntlmssp_state *ans)
{
	NTSTATUS status;

	return NT_STATUS_OK;
}
