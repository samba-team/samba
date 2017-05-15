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
	bool want_header_signing = false;
	NTSTATUS status;

	if (pkt->auth_length == 0) {
		enum dcerpc_transport_t transport =
			dcerpc_binding_get_transport(call->conn->endpoint->ep_description);
		const char *auth_type = derpc_transport_string_by_transport(transport);
		const char *transport_protection = AUTHZ_TRANSPORT_PROTECTION_NONE;
		if (transport == NCACN_NP) {
			transport_protection = AUTHZ_TRANSPORT_PROTECTION_SMB;
		}
		auth->auth_type = DCERPC_AUTH_TYPE_NONE;
		auth->auth_level = DCERPC_AUTH_LEVEL_NONE;
		auth->auth_context_id = 0;

		/*
		 * Log the authorization to this RPC interface.  This
		 * covered ncacn_np pass-through auth, and anonymous
		 * DCE/RPC (eg epmapper, netlogon etc)
		 */
		log_successful_authz_event(call->conn->msg_ctx,
					   call->conn->dce_ctx->lp_ctx,
					   call->conn->remote_address,
					   call->conn->local_address,
					   "DCE/RPC",
					   auth_type,
					   transport_protection,
					   call->conn->auth_state.session_info);

		return true;
	}

	status = dcerpc_pull_auth_trailer(pkt, call, &pkt->u.bind.auth_info,
					  &call->in_auth_info,
					  NULL, true);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * Setting DCERPC_AUTH_LEVEL_NONE,
		 * gives the caller the reject_reason
		 * as auth_context_id.
		 *
		 * Note: DCERPC_AUTH_LEVEL_NONE == 1
		 */
		auth->auth_type = DCERPC_AUTH_TYPE_NONE;
		auth->auth_level = DCERPC_AUTH_LEVEL_NONE;
		auth->auth_context_id =
			DCERPC_BIND_NAK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED;
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
		 * gives the caller the reject_reason
		 * as auth_context_id.
		 *
		 * Note: DCERPC_AUTH_LEVEL_NONE == 1
		 */
		auth->auth_type = DCERPC_AUTH_TYPE_NONE;
		auth->auth_level = DCERPC_AUTH_LEVEL_NONE;
		auth->auth_context_id = DCERPC_BIND_NAK_REASON_NOT_SPECIFIED;
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

	/*
	 * We have to call this because we set the target_service for
	 * Kerberos to NULL above, and in any case we wish to log a
	 * more specific service target.
	 *
	 */
	status = gensec_set_target_service_description(auth->gensec_security,
						       "DCE/RPC");
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to call gensec_set_target_service_description %s\n",
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

	if (call->conn->local_address != NULL) {
		status = gensec_set_local_address(auth->gensec_security,
						  call->conn->local_address);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to call gensec_set_local_address() %s\n",
				  nt_errstr(status)));
			return false;
		}
	}

	status = gensec_start_mech_by_authtype(auth->gensec_security, auth->auth_type,
					       auth->auth_level);
	if (!NT_STATUS_IS_OK(status)) {
		const char *backend_name =
			gensec_get_name_by_authtype(auth->gensec_security,
						    auth->auth_type);

		DEBUG(3, ("Failed to start GENSEC mechanism for DCERPC server: "
			  "auth_type=%d (%s), auth_level=%d: %s\n",
			  (int)auth->auth_type, backend_name,
			  (int)auth->auth_level,
			  nt_errstr(status)));

		/*
		 * Setting DCERPC_AUTH_LEVEL_NONE,
		 * gives the caller the reject_reason
		 * as auth_context_id.
		 *
		 * Note: DCERPC_AUTH_LEVEL_NONE == 1
		 */
		auth->auth_type = DCERPC_AUTH_TYPE_NONE;
		auth->auth_level = DCERPC_AUTH_LEVEL_NONE;
		if (backend_name != NULL) {
			auth->auth_context_id =
				DCERPC_BIND_NAK_REASON_INVALID_CHECKSUM;
		} else {
			auth->auth_context_id =
				DCERPC_BIND_NAK_REASON_INVALID_AUTH_TYPE;
		}
		return false;
	}

	if (call->pkt.pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN) {
		auth->client_hdr_signing = true;
		want_header_signing = true;
	}

	if (want_header_signing) {
		want_header_signing = gensec_have_feature(auth->gensec_security,
						GENSEC_FEATURE_SIGN_PKT_HEADER);
	}

	if (want_header_signing) {
		want_header_signing = lpcfg_parm_bool(dce_conn->dce_ctx->lp_ctx,
						      NULL,
						      "dcesrv",
						      "header signing",
						      true);
	}

	if (want_header_signing) {
		gensec_want_feature(auth->gensec_security,
				    GENSEC_FEATURE_SIGN_PKT_HEADER);
		auth->hdr_signing = true;
	}

	return true;
}

NTSTATUS dcesrv_auth_complete(struct dcesrv_call_state *call, NTSTATUS status)
{
	struct dcesrv_connection *dce_conn = call->conn;
	const char *pdu = "<unknown>";

	switch (call->pkt.ptype) {
	case DCERPC_PKT_BIND:
		pdu = "BIND";
		break;
	case DCERPC_PKT_ALTER:
		pdu = "ALTER";
		break;
	case DCERPC_PKT_AUTH3:
		pdu = "AUTH3";
		if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			DEBUG(4, ("GENSEC not finished at at %s\n", pdu));
			return NT_STATUS_RPC_SEC_PKG_ERROR;
		}
		break;
	default:
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(4, ("GENSEC mech rejected the incoming authentication "
			  "at %s: %s\n", pdu, nt_errstr(status)));
		return status;
	}

	status = gensec_session_info(dce_conn->auth_state.gensec_security,
				     dce_conn,
				     &dce_conn->auth_state.session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to establish session_info: %s\n",
			  nt_errstr(status)));
		return status;
	}
	dce_conn->auth_state.auth_finished = true;
	dce_conn->allow_request = true;

	/* Now that we are authenticated, go back to the generic session key... */
	dce_conn->auth_state.session_key = dcesrv_generic_session_key;

	if (call->pkt.ptype != DCERPC_PKT_AUTH3) {
		return NT_STATUS_OK;
	}

	if (call->out_auth_info->credentials.length != 0) {
		DEBUG(4, ("GENSEC produced output token (len=%zu) at %s\n",
			  call->out_auth_info->credentials.length, pdu));
		return NT_STATUS_RPC_SEC_PKG_ERROR;
	}

	return NT_STATUS_OK;
}

/*
  add any auth information needed in a bind ack, and process the authentication
  information found in the bind.
*/
NTSTATUS dcesrv_auth_prepare_bind_ack(struct dcesrv_call_state *call, struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;

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

	if (dce_conn->auth_state.hdr_signing) {
		pkt->pfc_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
	}

	call->_out_auth_info = (struct dcerpc_auth) {
		.auth_type = dce_conn->auth_state.auth_type,
		.auth_level = dce_conn->auth_state.auth_level,
		.auth_context_id = dce_conn->auth_state.auth_context_id,
	};
	call->out_auth_info = &call->_out_auth_info;

	return NT_STATUS_OK;
}

/*
  process the final stage of a auth request
*/
bool dcesrv_auth_prepare_auth3(struct dcesrv_call_state *call)
{
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;

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
					  &call->in_auth_info, NULL, true);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * Windows returns DCERPC_NCA_S_FAULT_REMOTE_NO_MEMORY
		 * instead of DCERPC_NCA_S_PROTO_ERROR.
		 */
		call->fault_code = DCERPC_NCA_S_FAULT_REMOTE_NO_MEMORY;
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

	return true;
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

	/* on a pure interface change there is no auth blob */
	if (pkt->auth_length == 0) {
		if (!dce_conn->auth_state.auth_finished) {
			return false;
		}
		return true;
	}

	if (dce_conn->auth_state.auth_finished) {
		call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
		return false;
	}

	/* We can't work without an existing gensec state */
	if (!dce_conn->auth_state.gensec_security) {
		return false;
	}

	status = dcerpc_pull_auth_trailer(pkt, call, &pkt->u.alter.auth_info,
					  &call->in_auth_info, NULL, true);
	if (!NT_STATUS_IS_OK(status)) {
		call->fault_code = DCERPC_NCA_S_PROTO_ERROR;
		return false;
	}

	if (call->in_auth_info.auth_type == DCERPC_AUTH_TYPE_NONE) {
		call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
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
NTSTATUS dcesrv_auth_prepare_alter_ack(struct dcesrv_call_state *call, struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;

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

	return NT_STATUS_OK;
}

/*
  check credentials on a packet
*/
bool dcesrv_auth_pkt_pull(struct dcesrv_call_state *call,
			  DATA_BLOB *full_packet,
			  uint8_t required_flags,
			  uint8_t optional_flags,
			  uint8_t payload_offset,
			  DATA_BLOB *payload_and_verifier)
{
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	const struct dcerpc_auth tmp_auth = {
		.auth_type = dce_conn->auth_state.auth_type,
		.auth_level = dce_conn->auth_state.auth_level,
		.auth_context_id = dce_conn->auth_state.auth_context_id,
	};
	NTSTATUS status;

	if (!dce_conn->allow_request) {
		call->fault_code = DCERPC_NCA_S_PROTO_ERROR;
		return false;
	}

	if (dce_conn->auth_state.auth_invalid) {
		return false;
	}

	status = dcerpc_ncacn_pull_pkt_auth(&tmp_auth,
					    dce_conn->auth_state.gensec_security,
					    call,
					    pkt->ptype,
					    required_flags,
					    optional_flags,
					    payload_offset,
					    payload_and_verifier,
					    full_packet,
					    pkt);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTOCOL_ERROR)) {
		call->fault_code = DCERPC_NCA_S_PROTO_ERROR;
		return false;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_UNSUPPORTED_AUTHN_LEVEL)) {
		call->fault_code = DCERPC_NCA_S_UNSUPPORTED_AUTHN_LEVEL;
		return false;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR)) {
		call->fault_code = DCERPC_FAULT_SEC_PKG_ERROR;
		return false;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
		return false;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return true;
}

/* 
   push a signed or sealed dcerpc request packet into a blob
*/
bool dcesrv_auth_pkt_push(struct dcesrv_call_state *call,
			  DATA_BLOB *blob, size_t sig_size,
			  uint8_t payload_offset,
			  const DATA_BLOB *payload,
			  const struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;
	const struct dcerpc_auth tmp_auth = {
		.auth_type = dce_conn->auth_state.auth_type,
		.auth_level = dce_conn->auth_state.auth_level,
		.auth_context_id = dce_conn->auth_state.auth_context_id,
	};
	NTSTATUS status;

	status = dcerpc_ncacn_push_pkt_auth(&tmp_auth,
					    dce_conn->auth_state.gensec_security,
					    call, blob, sig_size,
					    payload_offset,
					    payload,
					    pkt);
	return NT_STATUS_IS_OK(status);
}
