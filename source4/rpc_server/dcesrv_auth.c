/* 
   Unix SMB/CIFS implementation.

   server side dcerpc authentication code

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004

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
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/dcerpc_server_proto.h"
#include "rpc_server/common/proto.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/auth.h"
#include "param/param.h"
#include "librpc/rpc/rpc_common.h"

/*
  parse any auth information from a dcerpc bind request
  return false if we can't handle the auth request for some 
  reason (in which case we send a bind_nak)
*/
bool dcesrv_auth_bind(struct dcesrv_call_state *call)
{
	struct cli_credentials *server_credentials = NULL;
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	struct dcesrv_auth *auth = &dce_conn->auth_state;
	NTSTATUS status;
	uint32_t auth_length;

	if (pkt->auth_length == 0) {
		auth->auth_type = DCERPC_AUTH_TYPE_NONE;
		auth->auth_level = DCERPC_AUTH_LEVEL_NONE;
		auth->auth_context_id = 0;
		return true;
	}

	status = dcerpc_pull_auth_trailer(pkt, call, &pkt->u.bind.auth_info,
					  &call->in_auth_info,
					  &auth_length, false);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	switch (call->in_auth_info.auth_level) {
	case DCERPC_AUTH_LEVEL_CONNECT:
	case DCERPC_AUTH_LEVEL_CALL:
	case DCERPC_AUTH_LEVEL_PACKET:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PRIVACY:
		/*
		 * We evaluate auth_type only if auth_level was valid
		 */
		break;
	default:
		/*
		 * Setting DCERPC_AUTH_LEVEL_NONE,
		 * gives the caller a chance to decide what
		 * reject_reason to use
		 *
		 * Note: DCERPC_AUTH_LEVEL_NONE == 1
		 */
		auth->auth_type = DCERPC_AUTH_TYPE_NONE;
		auth->auth_level = DCERPC_AUTH_LEVEL_NONE;
		auth->auth_context_id = 0;
		return false;
	}

	auth->auth_type = call->in_auth_info.auth_type;
	auth->auth_level = call->in_auth_info.auth_level;
	auth->auth_context_id = call->in_auth_info.auth_context_id;

	server_credentials 
		= cli_credentials_init(call);
	if (!server_credentials) {
		DEBUG(1, ("Failed to init server credentials\n"));
		return false;
	}
	
	cli_credentials_set_conf(server_credentials, call->conn->dce_ctx->lp_ctx);
	status = cli_credentials_set_machine_account(server_credentials, call->conn->dce_ctx->lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to obtain server credentials: %s\n",
			  nt_errstr(status)));
		return false;
	}

	status = samba_server_gensec_start(dce_conn, call->event_ctx, 
					   call->msg_ctx,
					   call->conn->dce_ctx->lp_ctx,
					   server_credentials,
					   NULL,
					   &auth->gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to call samba_server_gensec_start %s\n",
			  nt_errstr(status)));
		return false;
	}

	if (call->conn->remote_address != NULL) {
		status = gensec_set_remote_address(auth->gensec_security,
						call->conn->remote_address);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to call gensec_set_remote_address() %s\n",
				  nt_errstr(status)));
			return false;
		}
	}

	status = gensec_start_mech_by_authtype(auth->gensec_security, auth->auth_type,
					       auth->auth_level);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("Failed to start GENSEC mechanism for DCERPC server: auth_type=%d, auth_level=%d: %s\n",
			  (int)auth->auth_type,
			  (int)auth->auth_level,
			  nt_errstr(status)));
		return false;
	}

	return true;
}

/*
  add any auth information needed in a bind ack, and process the authentication
  information found in the bind.
*/
NTSTATUS dcesrv_auth_bind_ack(struct dcesrv_call_state *call, struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;
	bool want_header_signing = false;

	dce_conn->allow_alter = true;
	dce_conn->allow_auth3 = true;

	if (call->pkt.auth_length == 0) {
		dce_conn->auth_state.auth_finished = true;
		dce_conn->allow_request = true;
		return NT_STATUS_OK;
	}

	/* We can't work without an existing gensec state */
	if (!call->conn->auth_state.gensec_security) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (call->pkt.pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN) {
		dce_conn->auth_state.client_hdr_signing = true;
		want_header_signing = true;
	}

	if (!lpcfg_parm_bool(call->conn->dce_ctx->lp_ctx, NULL, "dcesrv","header signing", true)) {
		want_header_signing = false;
	}

	call->_out_auth_info = (struct dcerpc_auth) {
		.auth_type = dce_conn->auth_state.auth_type,
		.auth_level = dce_conn->auth_state.auth_level,
		.auth_context_id = dce_conn->auth_state.auth_context_id,
	};
	call->out_auth_info = &call->_out_auth_info;

	status = gensec_update_ev(dce_conn->auth_state.gensec_security,
			       call, call->event_ctx,
			       call->in_auth_info.credentials,
			       &call->out_auth_info->credentials);
	
	if (NT_STATUS_IS_OK(status)) {
		status = gensec_session_info(dce_conn->auth_state.gensec_security,
					     dce_conn,
					     &dce_conn->auth_state.session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to establish session_info: %s\n", nt_errstr(status)));
			return status;
		}
		dce_conn->auth_state.auth_finished = true;
		dce_conn->allow_request = true;

		if (!gensec_have_feature(dce_conn->auth_state.gensec_security,
					 GENSEC_FEATURE_SIGN_PKT_HEADER))
		{
			want_header_signing = false;
		}

		if (want_header_signing) {
			gensec_want_feature(dce_conn->auth_state.gensec_security,
					    GENSEC_FEATURE_SIGN_PKT_HEADER);
			dce_conn->auth_state.hdr_signing = true;
			pkt->pfc_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
		}

		/* Now that we are authenticated, go back to the generic session key... */
		dce_conn->auth_state.session_key = dcesrv_generic_session_key;
		return NT_STATUS_OK;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		if (!gensec_have_feature(dce_conn->auth_state.gensec_security,
					 GENSEC_FEATURE_SIGN_PKT_HEADER))
		{
			want_header_signing = false;
		}

		if (want_header_signing) {
			gensec_want_feature(dce_conn->auth_state.gensec_security,
					    GENSEC_FEATURE_SIGN_PKT_HEADER);
			dce_conn->auth_state.hdr_signing = true;
			pkt->pfc_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
		}

		return NT_STATUS_OK;
	} else {
		DEBUG(4, ("GENSEC mech rejected the incoming authentication at bind_ack: %s\n",
			  nt_errstr(status)));
		return status;
	}
}


/*
  process the final stage of a auth request
*/
bool dcesrv_auth_auth3(struct dcesrv_call_state *call)
{
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;
	uint32_t auth_length;

	if (pkt->auth_length == 0) {
		return false;
	}

	if (dce_conn->auth_state.auth_finished) {
		return false;
	}

	/* We can't work without an existing gensec state */
	if (!dce_conn->auth_state.gensec_security) {
		return false;
	}

	status = dcerpc_pull_auth_trailer(pkt, call, &pkt->u.auth3.auth_info,
					  &call->in_auth_info, &auth_length, true);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (call->in_auth_info.auth_type != dce_conn->auth_state.auth_type) {
		return false;
	}

	if (call->in_auth_info.auth_level != dce_conn->auth_state.auth_level) {
		return false;
	}

	if (call->in_auth_info.auth_context_id != dce_conn->auth_state.auth_context_id) {
		return false;
	}

	call->_out_auth_info = (struct dcerpc_auth) {
		.auth_type = dce_conn->auth_state.auth_type,
		.auth_level = dce_conn->auth_state.auth_level,
		.auth_context_id = dce_conn->auth_state.auth_context_id,
	};
	call->out_auth_info = &call->_out_auth_info;

	/* Pass the extra data we got from the client down to gensec for processing */
	status = gensec_update_ev(dce_conn->auth_state.gensec_security,
			       call, call->event_ctx,
			       call->in_auth_info.credentials,
			       &call->out_auth_info->credentials);
	if (NT_STATUS_IS_OK(status)) {
		status = gensec_session_info(dce_conn->auth_state.gensec_security,
					     dce_conn,
					     &dce_conn->auth_state.session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to establish session_info: %s\n", nt_errstr(status)));
			return false;
		}
		dce_conn->auth_state.auth_finished = true;
		dce_conn->allow_request = true;

		/* Now that we are authenticated, go back to the generic session key... */
		dce_conn->auth_state.session_key = dcesrv_generic_session_key;

		if (call->out_auth_info->credentials.length != 0) {

			DEBUG(4, ("GENSEC produced output token (len=%u) at bind_auth3\n",
				  (unsigned)call->out_auth_info->credentials.length));
			return false;
		}
		return true;
	} else {
		DEBUG(4, ("GENSEC mech rejected the incoming authentication at bind_auth3: %s\n",
			  nt_errstr(status)));
		return false;
	}
}

/*
  parse any auth information from a dcerpc alter request
  return false if we can't handle the auth request for some 
  reason (in which case we send a bind_nak (is this true for here?))
*/
bool dcesrv_auth_alter(struct dcesrv_call_state *call)
{
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;
	uint32_t auth_length;

	/* on a pure interface change there is no auth blob */
	if (pkt->auth_length == 0) {
		if (!dce_conn->auth_state.auth_finished) {
			return false;
		}
		return true;
	}

	if (dce_conn->auth_state.auth_finished) {
		return false;
	}

	/* We can't work without an existing gensec state */
	if (!dce_conn->auth_state.gensec_security) {
		return false;
	}

	status = dcerpc_pull_auth_trailer(pkt, call, &pkt->u.alter.auth_info,
					  &call->in_auth_info, &auth_length, true);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (call->in_auth_info.auth_type != dce_conn->auth_state.auth_type) {
		return false;
	}

	if (call->in_auth_info.auth_level != dce_conn->auth_state.auth_level) {
		return false;
	}

	if (call->in_auth_info.auth_context_id != dce_conn->auth_state.auth_context_id) {
		return false;
	}

	return true;
}

/*
  add any auth information needed in a alter ack, and process the authentication
  information found in the alter.
*/
NTSTATUS dcesrv_auth_alter_ack(struct dcesrv_call_state *call, struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;

	/* on a pure interface change there is no auth_info structure
	   setup */
	if (call->pkt.auth_length == 0) {
		return NT_STATUS_OK;
	}

	if (!call->conn->auth_state.gensec_security) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	call->_out_auth_info = (struct dcerpc_auth) {
		.auth_type = dce_conn->auth_state.auth_type,
		.auth_level = dce_conn->auth_state.auth_level,
		.auth_context_id = dce_conn->auth_state.auth_context_id,
	};
	call->out_auth_info = &call->_out_auth_info;

	status = gensec_update_ev(dce_conn->auth_state.gensec_security,
			       call, call->event_ctx,
			       call->in_auth_info.credentials,
			       &call->out_auth_info->credentials);

	if (NT_STATUS_IS_OK(status)) {
		status = gensec_session_info(dce_conn->auth_state.gensec_security,
					     dce_conn,
					     &dce_conn->auth_state.session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to establish session_info: %s\n", nt_errstr(status)));
			return status;
		}
		dce_conn->auth_state.auth_finished = true;
		dce_conn->allow_request = true;

		/* Now that we are authenticated, got back to the generic session key... */
		dce_conn->auth_state.session_key = dcesrv_generic_session_key;
		return NT_STATUS_OK;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return NT_STATUS_OK;
	}

	DEBUG(4, ("GENSEC mech rejected the incoming authentication at auth alter_ack: %s\n",
		  nt_errstr(status)));
	return status;
}

/*
  check credentials on a request
*/
bool dcesrv_auth_request(struct dcesrv_call_state *call, DATA_BLOB *full_packet)
{
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;
	uint32_t auth_length;
	size_t hdr_size = DCERPC_REQUEST_LENGTH;

	if (!dce_conn->allow_request) {
		return false;
	}

	if (dce_conn->auth_state.auth_invalid) {
		return false;
	}

	if (pkt->pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		hdr_size += 16;
	}

	switch (dce_conn->auth_state.auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		if (pkt->auth_length != 0) {
			break;
		}
		return true;
	case DCERPC_AUTH_LEVEL_NONE:
		if (pkt->auth_length != 0) {
			return false;
		}
		return true;

	default:
		return false;
	}

	if (!dce_conn->auth_state.gensec_security) {
		return false;
	}

	status = dcerpc_pull_auth_trailer(pkt, call,
					  &pkt->u.request.stub_and_verifier,
					  &call->in_auth_info, &auth_length, false);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (call->in_auth_info.auth_type != dce_conn->auth_state.auth_type) {
		return false;
	}

	if (call->in_auth_info.auth_level != dce_conn->auth_state.auth_level) {
		return false;
	}

	if (call->in_auth_info.auth_context_id != dce_conn->auth_state.auth_context_id) {
		return false;
	}

	pkt->u.request.stub_and_verifier.length -= auth_length;

	/* check signature or unseal the packet */
	switch (dce_conn->auth_state.auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = gensec_unseal_packet(dce_conn->auth_state.gensec_security,
					      full_packet->data + hdr_size,
					      pkt->u.request.stub_and_verifier.length, 
					      full_packet->data,
					      full_packet->length-
					      call->in_auth_info.credentials.length,
					      &call->in_auth_info.credentials);
		memcpy(pkt->u.request.stub_and_verifier.data, 
		       full_packet->data + hdr_size,
		       pkt->u.request.stub_and_verifier.length);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		status = gensec_check_packet(dce_conn->auth_state.gensec_security,
					     pkt->u.request.stub_and_verifier.data, 
					     pkt->u.request.stub_and_verifier.length,
					     full_packet->data,
					     full_packet->length-
					     call->in_auth_info.credentials.length,
					     &call->in_auth_info.credentials);
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		/* for now we ignore possible signatures here */
		status = NT_STATUS_OK;
		break;

	default:
		status = NT_STATUS_INVALID_LEVEL;
		break;
	}

	/* remove the indicated amount of padding */
	if (pkt->u.request.stub_and_verifier.length < call->in_auth_info.auth_pad_length) {
		return false;
	}
	pkt->u.request.stub_and_verifier.length -= call->in_auth_info.auth_pad_length;

	return NT_STATUS_IS_OK(status);
}


/* 
   push a signed or sealed dcerpc request packet into a blob
*/
bool dcesrv_auth_response(struct dcesrv_call_state *call,
			  DATA_BLOB *blob, size_t sig_size,
			  struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	struct ndr_push *ndr;
	uint32_t payload_length;
	DATA_BLOB creds2;

	switch (dce_conn->auth_state.auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
		if (sig_size == 0) {
			return false;
		}

		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		/*
		 * TODO: let the gensec mech decide if it wants to generate a
		 *       signature that might be needed for schannel...
		 */
		status = ncacn_push_auth(blob, call, pkt, NULL);
		return NT_STATUS_IS_OK(status);

	case DCERPC_AUTH_LEVEL_NONE:
		status = ncacn_push_auth(blob, call, pkt, NULL);
		return NT_STATUS_IS_OK(status);

	default:
		return false;
	}

	if (!dce_conn->auth_state.gensec_security) {
		return false;
	}

	ndr = ndr_push_init_ctx(call);
	if (!ndr) {
		return false;
	}

	if (!(pkt->drep[0] & DCERPC_DREP_LE)) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	ndr_err = ndr_push_ncacn_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	call->_out_auth_info = (struct dcerpc_auth) {
		.auth_type = dce_conn->auth_state.auth_type,
		.auth_level = dce_conn->auth_state.auth_level,
		.auth_context_id = dce_conn->auth_state.auth_context_id,
	};
	call->out_auth_info = &call->_out_auth_info;

	/* pad to 16 byte multiple in the payload portion of the
	   packet. This matches what w2k3 does. Note that we can't use
	   ndr_push_align() as that is relative to the start of the
	   whole packet, whereas w2k8 wants it relative to the start
	   of the stub */
	call->out_auth_info->auth_pad_length =
		DCERPC_AUTH_PAD_LENGTH(pkt->u.response.stub_and_verifier.length);
	ndr_err = ndr_push_zero(ndr, call->out_auth_info->auth_pad_length);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	payload_length = pkt->u.response.stub_and_verifier.length +
		call->out_auth_info->auth_pad_length;

	/* add the auth verifier */
	ndr_err = ndr_push_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS,
				       call->out_auth_info);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	/* extract the whole packet as a blob */
	*blob = ndr_push_blob(ndr);

	/*
	 * Setup the frag and auth length in the packet buffer.
	 * This is needed if the GENSEC mech does AEAD signing
	 * of the packet headers. The signature itself will be
	 * appended later.
	 */
	dcerpc_set_frag_length(blob, blob->length + sig_size);
	dcerpc_set_auth_length(blob, sig_size);

	/* sign or seal the packet */
	switch (dce_conn->auth_state.auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = gensec_seal_packet(dce_conn->auth_state.gensec_security, 
					    call,
					    ndr->data + DCERPC_REQUEST_LENGTH, 
					    payload_length,
					    blob->data,
					    blob->length,
					    &creds2);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		status = gensec_sign_packet(dce_conn->auth_state.gensec_security, 
					    call,
					    ndr->data + DCERPC_REQUEST_LENGTH, 
					    payload_length,
					    blob->data,
					    blob->length,
					    &creds2);
		break;

	default:
		status = NT_STATUS_INVALID_LEVEL;
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}	

	if (creds2.length != sig_size) {
		DEBUG(3,("dcesrv_auth_response: creds2.length[%u] != sig_size[%u] pad[%u] stub[%u]\n",
			 (unsigned)creds2.length, (uint32_t)sig_size,
			 (unsigned)call->out_auth_info->auth_pad_length,
			 (unsigned)pkt->u.response.stub_and_verifier.length));
		dcerpc_set_frag_length(blob, blob->length + creds2.length);
		dcerpc_set_auth_length(blob, creds2.length);
	}

	if (!data_blob_append(call, blob, creds2.data, creds2.length)) {
		status = NT_STATUS_NO_MEMORY;
		return false;
	}
	data_blob_free(&creds2);

	return true;
}
