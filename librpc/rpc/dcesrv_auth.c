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
#include "librpc/rpc/dcesrv_core.h"
#include "librpc/rpc/dcesrv_core_proto.h"
#include "librpc/rpc/dcerpc_util.h"
#include "librpc/rpc/dcerpc_pkt_auth.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/auth.h"
#include "param/param.h"

static NTSTATUS dcesrv_auth_negotiate_hdr_signing(struct dcesrv_call_state *call,
						  struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;
	struct dcesrv_auth *a = NULL;

	if (!(call->pkt.pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN)) {
		return NT_STATUS_OK;
	}

	if (dce_conn->client_hdr_signing) {
		if (dce_conn->negotiated_hdr_signing && pkt != NULL) {
			pkt->pfc_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
		}
		return NT_STATUS_OK;
	}

	dce_conn->client_hdr_signing = true;
	dce_conn->negotiated_hdr_signing = dce_conn->support_hdr_signing;

	if (!dce_conn->negotiated_hdr_signing) {
		return NT_STATUS_OK;
	}

	if (pkt != NULL) {
		pkt->pfc_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
	}

	a = call->conn->default_auth_state;
	if (a->gensec_security != NULL) {
		gensec_want_feature(a->gensec_security,
				    GENSEC_FEATURE_SIGN_PKT_HEADER);
	}

	for (a = call->conn->auth_states; a != NULL; a = a->next) {
		if (a->gensec_security == NULL) {
			continue;
		}

		gensec_want_feature(a->gensec_security,
				    GENSEC_FEATURE_SIGN_PKT_HEADER);
	}

	return NT_STATUS_OK;
}

static bool dcesrv_auth_prepare_gensec(struct dcesrv_call_state *call)
{
	struct dcesrv_connection *dce_conn = call->conn;
	struct dcesrv_auth *auth = call->auth_state;
	NTSTATUS status;

	if (auth->auth_started) {
		return false;
	}

	auth->auth_started = true;

	if (auth->auth_invalid) {
		return false;
	}

	if (auth->auth_finished) {
		return false;
	}

	if (auth->gensec_security != NULL) {
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

	status = call->conn->dce_ctx->callbacks.auth.gensec_prepare(auth,
						call,
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

	if (dce_conn->negotiated_hdr_signing) {
		gensec_want_feature(auth->gensec_security,
				    GENSEC_FEATURE_SIGN_PKT_HEADER);
	}

	return true;
}

static void dcesrv_default_auth_state_finish_bind(struct dcesrv_call_state *call)
{
	SMB_ASSERT(call->pkt.ptype == DCERPC_PKT_BIND);

	if (call->auth_state == call->conn->default_auth_state) {
		return;
	}

	if (call->conn->default_auth_state->auth_started) {
		return;
	}

	if (call->conn->default_auth_state->auth_invalid) {
		return;
	}

	call->conn->default_auth_state->auth_type = DCERPC_AUTH_TYPE_NONE;
	call->conn->default_auth_state->auth_level = DCERPC_AUTH_LEVEL_NONE;
	call->conn->default_auth_state->auth_context_id = 0;
	call->conn->default_auth_state->auth_started = true;
	call->conn->default_auth_state->auth_finished = true;

	/*
	 *
	 * We defer log_successful_dcesrv_authz_event()
	 * to dcesrv_default_auth_state_prepare_request()
	 *
	 * As we don't want to trigger authz_events
	 * just for alter_context requests without authentication
	 */
}

void dcesrv_default_auth_state_prepare_request(struct dcesrv_call_state *call)
{
	struct dcesrv_connection *dce_conn = call->conn;
	struct dcesrv_auth *auth = call->auth_state;

	if (auth->auth_audited) {
		return;
	}

	if (call->pkt.ptype != DCERPC_PKT_REQUEST) {
		return;
	}

	if (auth != dce_conn->default_auth_state) {
		return;
	}

	if (auth->auth_invalid) {
		return;
	}

	if (!auth->auth_finished) {
		return;
	}

	if (!call->conn->dce_ctx->callbacks.log.successful_authz) {
		return;
	}

	call->conn->dce_ctx->callbacks.log.successful_authz(call);
}

/*
  parse any auth information from a dcerpc bind request
  return false if we can't handle the auth request for some
  reason (in which case we send a bind_nak)
*/
bool dcesrv_auth_bind(struct dcesrv_call_state *call)
{
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_auth *auth = call->auth_state;
	NTSTATUS status;

	if (pkt->auth_length == 0) {
		auth->auth_type = DCERPC_AUTH_TYPE_NONE;
		auth->auth_level = DCERPC_AUTH_LEVEL_NONE;
		auth->auth_context_id = 0;
		auth->auth_started = true;

		if (call->conn->dce_ctx->callbacks.log.successful_authz) {
			call->conn->dce_ctx->callbacks.log.successful_authz(call);
		}

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

	return dcesrv_auth_prepare_gensec(call);
}

NTSTATUS dcesrv_auth_complete(struct dcesrv_call_state *call, NTSTATUS status)
{
	struct dcesrv_auth *auth = call->auth_state;
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

	status = gensec_session_info(auth->gensec_security,
				     auth,
				     &auth->session_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to establish session_info: %s\n",
			  nt_errstr(status)));
		return status;
	}
	auth->auth_finished = true;

	if (auth->auth_level == DCERPC_AUTH_LEVEL_CONNECT &&
	    !call->conn->got_explicit_auth_level_connect)
	{
		call->conn->default_auth_level_connect = auth;
	}

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
	struct dcesrv_auth *auth = call->auth_state;
	NTSTATUS status;

	status = dcesrv_auth_negotiate_hdr_signing(call, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dce_conn->allow_alter = true;
	dcesrv_default_auth_state_finish_bind(call);

	if (call->pkt.auth_length == 0) {
		auth->auth_finished = true;
		return NT_STATUS_OK;
	}

	/* We can't work without an existing gensec state */
	if (auth->gensec_security == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	call->_out_auth_info = (struct dcerpc_auth) {
		.auth_type = auth->auth_type,
		.auth_level = auth->auth_level,
		.auth_context_id = auth->auth_context_id,
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
	struct dcesrv_auth *auth = call->auth_state;
	NTSTATUS status;

	if (pkt->auth_length == 0) {
		return false;
	}

	if (auth->auth_finished) {
		return false;
	}

	if (auth->auth_invalid) {
		return false;
	}

	/* We can't work without an existing gensec state */
	if (auth->gensec_security == NULL) {
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

	if (call->in_auth_info.auth_type != auth->auth_type) {
		return false;
	}

	if (call->in_auth_info.auth_level != auth->auth_level) {
		return false;
	}

	if (call->in_auth_info.auth_context_id != auth->auth_context_id) {
		return false;
	}

	call->_out_auth_info = (struct dcerpc_auth) {
		.auth_type = auth->auth_type,
		.auth_level = auth->auth_level,
		.auth_context_id = auth->auth_context_id,
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
	struct dcesrv_auth *auth = call->auth_state;
	NTSTATUS status;

	/* on a pure interface change there is no auth blob */
	if (pkt->auth_length == 0) {
		if (!auth->auth_finished) {
			return false;
		}
		return true;
	}

	if (auth->auth_finished) {
		call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
		return false;
	}

	status = dcerpc_pull_auth_trailer(pkt, call, &pkt->u.alter.auth_info,
					  &call->in_auth_info, NULL, true);
	if (!NT_STATUS_IS_OK(status)) {
		call->fault_code = DCERPC_NCA_S_PROTO_ERROR;
		return false;
	}

	if (!auth->auth_started) {
		bool ok;

		ok = dcesrv_auth_prepare_gensec(call);
		if (!ok) {
			call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
			return false;
		}

		return true;
	}

	if (call->in_auth_info.auth_type == DCERPC_AUTH_TYPE_NONE) {
		call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
		return false;
	}

	if (auth->auth_invalid) {
		return false;
	}

	if (call->in_auth_info.auth_type != auth->auth_type) {
		return false;
	}

	if (call->in_auth_info.auth_level != auth->auth_level) {
		return false;
	}

	if (call->in_auth_info.auth_context_id != auth->auth_context_id) {
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
	struct dcesrv_auth *auth = call->auth_state;
	NTSTATUS status;

	status = dcesrv_auth_negotiate_hdr_signing(call, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* on a pure interface change there is no auth_info structure
	   setup */
	if (call->pkt.auth_length == 0) {
		return NT_STATUS_OK;
	}

	if (auth->gensec_security == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	call->_out_auth_info = (struct dcerpc_auth) {
		.auth_type = auth->auth_type,
		.auth_level = auth->auth_level,
		.auth_context_id = auth->auth_context_id,
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
	struct dcesrv_auth *auth = call->auth_state;
	const struct dcerpc_auth tmp_auth = {
		.auth_type = auth->auth_type,
		.auth_level = auth->auth_level,
		.auth_context_id = auth->auth_context_id,
	};
	bool check_pkt_auth_fields;
	NTSTATUS status;

	if (!auth->auth_started) {
		return false;
	}

	if (!auth->auth_finished) {
		call->fault_code = DCERPC_NCA_S_PROTO_ERROR;
		return false;
	}

	if (auth->auth_invalid) {
		return false;
	}

	if (call->pkt.pfc_flags & DCERPC_PFC_FLAG_FIRST) {
		/*
		 * The caller most likely checked this
		 * already, but we better double check.
		 */
		check_pkt_auth_fields = true;
	} else {
		/*
		 * The caller already found first fragment
		 * and is passing the auth_state of it.
		 * A server is supposed to use the
		 * setting of the first fragment and
		 * completely ignore the values
		 * on the remaining fragments
		 */
		check_pkt_auth_fields = false;
	}

	status = dcerpc_ncacn_pull_pkt_auth(&tmp_auth,
					    auth->gensec_security,
					    check_pkt_auth_fields,
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
	struct dcesrv_auth *auth = call->auth_state;
	const struct dcerpc_auth tmp_auth = {
		.auth_type = auth->auth_type,
		.auth_level = auth->auth_level,
		.auth_context_id = auth->auth_context_id,
	};
	NTSTATUS status;

	status = dcerpc_ncacn_push_pkt_auth(&tmp_auth,
					    auth->gensec_security,
					    call, blob, sig_size,
					    payload_offset,
					    payload,
					    pkt);
	return NT_STATUS_IS_OK(status);
}
