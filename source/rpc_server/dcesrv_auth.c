/* 
   Unix SMB/CIFS implementation.

   server side dcerpc authentication code

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "auth/gensec/gensec.h"

/*
  parse any auth information from a dcerpc bind request
  return False if we can't handle the auth request for some 
  reason (in which case we send a bind_nak)
*/
BOOL dcesrv_auth_bind(struct dcesrv_call_state *call)
{
	struct cli_credentials *server_credentials;
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	struct dcesrv_auth *auth = &dce_conn->auth_state;
	NTSTATUS status;

	if (pkt->u.bind.auth_info.length == 0) {
		dce_conn->auth_state.auth_info = NULL;
		return True;
	}

	dce_conn->auth_state.auth_info = talloc(dce_conn, struct dcerpc_auth);
	if (!dce_conn->auth_state.auth_info) {
		return False;
	}

	status = ndr_pull_struct_blob(&pkt->u.bind.auth_info,
				      call,
				      dce_conn->auth_state.auth_info,
				      (ndr_pull_flags_fn_t)ndr_pull_dcerpc_auth);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	status = gensec_server_start(dce_conn, call->event_ctx, call->msg_ctx, &auth->gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC for DCERPC server: %s\n", nt_errstr(status)));
		return False;
	}

	server_credentials 
		= cli_credentials_init(call);
	if (!server_credentials) {
		DEBUG(1, ("Failed to init server credentials\n"));
		return False;
	}
	
	cli_credentials_set_conf(server_credentials);
	status = cli_credentials_set_machine_account(server_credentials);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Failed to obtain server credentials, perhaps a standalone server?: %s\n", nt_errstr(status)));
		talloc_free(server_credentials);
		server_credentials = NULL;
	}

	gensec_set_credentials(auth->gensec_security, server_credentials);

	status = gensec_start_mech_by_authtype(auth->gensec_security, auth->auth_info->auth_type, 
					       auth->auth_info->auth_level);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC mechanism for DCERPC server: auth_type=%d, auth_level=%d: %s\n", 
			  (int)auth->auth_info->auth_type,
			  (int)auth->auth_info->auth_level,
			  nt_errstr(status)));
		return False;
	}

	return True;
}

/*
  add any auth information needed in a bind ack, and process the authentication
  information found in the bind.
*/
BOOL dcesrv_auth_bind_ack(struct dcesrv_call_state *call, struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;

	if (!call->conn->auth_state.gensec_security) {
		return True;
	}

	status = gensec_update(dce_conn->auth_state.gensec_security,
			       call,
			       dce_conn->auth_state.auth_info->credentials, 
			       &dce_conn->auth_state.auth_info->credentials);
	
	if (NT_STATUS_IS_OK(status)) {
		status = gensec_session_info(dce_conn->auth_state.gensec_security,
					     &dce_conn->auth_state.session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to establish session_info: %s\n", nt_errstr(status)));
			return False;
		}

		/* Now that we are authenticated, go back to the generic session key... */
		dce_conn->auth_state.session_key = dcesrv_generic_session_key;
		return True;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		dce_conn->auth_state.auth_info->auth_pad_length = 0;
		dce_conn->auth_state.auth_info->auth_reserved = 0;
		return True;
	} else {
		DEBUG(2, ("Failed to start dcesrv auth negotiate: %s\n", nt_errstr(status)));
		return False;
	}
}


/*
  process the final stage of a auth request
*/
BOOL dcesrv_auth_auth3(struct dcesrv_call_state *call)
{
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;

	/* We can't work without an existing gensec state, and an new blob to feed it */
	if (!dce_conn->auth_state.auth_info ||
	    !dce_conn->auth_state.gensec_security ||
	    pkt->u.auth3.auth_info.length == 0) {
		return False;
	}

	status = ndr_pull_struct_blob(&pkt->u.auth3.auth_info,
				      call,
				      dce_conn->auth_state.auth_info,
				      (ndr_pull_flags_fn_t)ndr_pull_dcerpc_auth);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* Pass the extra data we got from the client down to gensec for processing */
	status = gensec_update(dce_conn->auth_state.gensec_security,
			       call,
			       dce_conn->auth_state.auth_info->credentials, 
			       &dce_conn->auth_state.auth_info->credentials);
	if (NT_STATUS_IS_OK(status)) {
		status = gensec_session_info(dce_conn->auth_state.gensec_security,
					     &dce_conn->auth_state.session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to establish session_info: %s\n", nt_errstr(status)));
			return False;
		}
		/* Now that we are authenticated, go back to the generic session key... */
		dce_conn->auth_state.session_key = dcesrv_generic_session_key;
		return True;
	} else {
		DEBUG(4, ("dcesrv_auth_auth3: failed to authenticate: %s\n", 
			  nt_errstr(status)));
		return False;
	}

	return True;
}

/*
  parse any auth information from a dcerpc alter request
  return False if we can't handle the auth request for some 
  reason (in which case we send a bind_nak (is this true for here?))
*/
BOOL dcesrv_auth_alter(struct dcesrv_call_state *call)
{
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;

	/* on a pure interface change there is no auth blob */
	if (pkt->u.alter.auth_info.length == 0) {
		return True;
	}

	/* We can't work without an existing gensec state */
	if (!dce_conn->auth_state.gensec_security) {
		return False;
	}

	dce_conn->auth_state.auth_info = talloc(dce_conn, struct dcerpc_auth);
	if (!dce_conn->auth_state.auth_info) {
		return False;
	}

	status = ndr_pull_struct_blob(&pkt->u.alter.auth_info,
				      call,
				      dce_conn->auth_state.auth_info,
				      (ndr_pull_flags_fn_t)ndr_pull_dcerpc_auth);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	return True;
}

/*
  add any auth information needed in a alter ack, and process the authentication
  information found in the alter.
*/
BOOL dcesrv_auth_alter_ack(struct dcesrv_call_state *call, struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;

	/* on a pure interface change there is no auth_info structure
	   setup */
	if (!call->conn->auth_state.auth_info ||
	    dce_conn->auth_state.auth_info->credentials.length == 0) {
		return True;
	}

	if (!call->conn->auth_state.gensec_security) {
		return False;
	}

	status = gensec_update(dce_conn->auth_state.gensec_security,
			       call,
			       dce_conn->auth_state.auth_info->credentials, 
			       &dce_conn->auth_state.auth_info->credentials);

	if (NT_STATUS_IS_OK(status)) {
		status = gensec_session_info(dce_conn->auth_state.gensec_security,
					     &dce_conn->auth_state.session_info);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to establish session_info: %s\n", nt_errstr(status)));
			return False;
		}

		/* Now that we are authenticated, got back to the generic session key... */
		dce_conn->auth_state.session_key = dcesrv_generic_session_key;
		return True;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		dce_conn->auth_state.auth_info->auth_pad_length = 0;
		dce_conn->auth_state.auth_info->auth_reserved = 0;
		return True;
	}

	DEBUG(2, ("Failed to finish dcesrv auth alter_ack: %s\n", nt_errstr(status)));
	return False;
}

/*
  generate a CONNECT level verifier
*/
static NTSTATUS dcesrv_connect_verifier(TALLOC_CTX *mem_ctx, DATA_BLOB *blob)
{
	*blob = data_blob_talloc(mem_ctx, NULL, 16);
	if (blob->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	SIVAL(blob->data, 0, 1);
	memset(blob->data+4, 0, 12);
	return NT_STATUS_OK;
}

/*
  generate a CONNECT level verifier
*/
static NTSTATUS dcesrv_check_connect_verifier(DATA_BLOB *blob)
{
	if (blob->length != 16 ||
	    IVAL(blob->data, 0) != 1) {
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}


/*
  check credentials on a request
*/
BOOL dcesrv_auth_request(struct dcesrv_call_state *call, DATA_BLOB *full_packet)
{
	struct ncacn_packet *pkt = &call->pkt;
	struct dcesrv_connection *dce_conn = call->conn;
	DATA_BLOB auth_blob;
	struct dcerpc_auth auth;
	struct ndr_pull *ndr;
	NTSTATUS status;

	if (!dce_conn->auth_state.auth_info ||
	    !dce_conn->auth_state.gensec_security) {
		return True;
	}

	auth_blob.length = 8 + pkt->auth_length;

	/* check for a valid length */
	if (pkt->u.request.stub_and_verifier.length < auth_blob.length) {
		return False;
	}

	auth_blob.data = 
		pkt->u.request.stub_and_verifier.data + 
		pkt->u.request.stub_and_verifier.length - auth_blob.length;
	pkt->u.request.stub_and_verifier.length -= auth_blob.length;

	/* pull the auth structure */
	ndr = ndr_pull_init_blob(&auth_blob, call);
	if (!ndr) {
		return False;
	}

	if (!(pkt->drep[0] & DCERPC_DREP_LE)) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	status = ndr_pull_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(ndr);
		return False;
	}

	/* check signature or unseal the packet */
	switch (dce_conn->auth_state.auth_info->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = gensec_unseal_packet(dce_conn->auth_state.gensec_security,
					      call,
					      full_packet->data + DCERPC_REQUEST_LENGTH,
					      pkt->u.request.stub_and_verifier.length, 
					      full_packet->data,
					      full_packet->length-auth.credentials.length,
					      &auth.credentials);
		memcpy(pkt->u.request.stub_and_verifier.data, 
		       full_packet->data + DCERPC_REQUEST_LENGTH,
		       pkt->u.request.stub_and_verifier.length);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		status = gensec_check_packet(dce_conn->auth_state.gensec_security,
					     call,
					     pkt->u.request.stub_and_verifier.data, 
					     pkt->u.request.stub_and_verifier.length,
					     full_packet->data,
					     full_packet->length-auth.credentials.length,
					     &auth.credentials);
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		status = dcesrv_check_connect_verifier(&auth.credentials);
		break;

	default:
		status = NT_STATUS_INVALID_LEVEL;
		break;
	}

	/* remove the indicated amount of padding */
	if (pkt->u.request.stub_and_verifier.length < auth.auth_pad_length) {
		talloc_free(ndr);
		return False;
	}
	pkt->u.request.stub_and_verifier.length -= auth.auth_pad_length;
	talloc_free(ndr);

	return NT_STATUS_IS_OK(status);
}


/* 
   push a signed or sealed dcerpc request packet into a blob
*/
BOOL dcesrv_auth_response(struct dcesrv_call_state *call,
			  DATA_BLOB *blob, struct ncacn_packet *pkt)
{
	struct dcesrv_connection *dce_conn = call->conn;
	NTSTATUS status;
	struct ndr_push *ndr;
	uint32_t payload_length;
	DATA_BLOB creds2;

	/* non-signed packets are simple */
	if (!dce_conn->auth_state.auth_info || !dce_conn->auth_state.gensec_security) {
		status = ncacn_push_auth(blob, call, pkt, NULL);
		return NT_STATUS_IS_OK(status);
	}

	ndr = ndr_push_init_ctx(call);
	if (!ndr) {
		return False;
	}

	if (!(pkt->drep[0] & DCERPC_DREP_LE)) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	status = ndr_push_ncacn_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* pad to 16 byte multiple, match win2k3 */
	dce_conn->auth_state.auth_info->auth_pad_length = NDR_ALIGN(ndr, 16);
	ndr_push_zero(ndr, dce_conn->auth_state.auth_info->auth_pad_length);

	payload_length = ndr->offset - DCERPC_REQUEST_LENGTH;

	if (dce_conn->auth_state.auth_info->auth_level == DCERPC_AUTH_LEVEL_CONNECT) {
		status = dcesrv_connect_verifier(call,
						 &dce_conn->auth_state.auth_info->credentials);
		if (!NT_STATUS_IS_OK(status)) {
			return False;
		}
	} else {

		/* We hope this length is accruate.  If must be if the
		 * GENSEC mech does AEAD signing of the packet
		 * headers */
		dce_conn->auth_state.auth_info->credentials
			= data_blob_talloc(call, NULL, 
					   gensec_sig_size(dce_conn->auth_state.gensec_security, 
							   payload_length));
		data_blob_clear(&dce_conn->auth_state.auth_info->credentials);
	}

	/* add the auth verifier */
	status = ndr_push_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, 
				      dce_conn->auth_state.auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	/* extract the whole packet as a blob */
	*blob = ndr_push_blob(ndr);

	/* fill in the fragment length and auth_length, we can't fill
	   in these earlier as we don't know the signature length (it
	   could be variable length) */
	dcerpc_set_frag_length(blob, blob->length);

	/* We hope this value is accruate.  If must be if the GENSEC
	 * mech does AEAD signing of the packet headers */
	dcerpc_set_auth_length(blob, dce_conn->auth_state.auth_info->credentials.length);

	/* sign or seal the packet */
	switch (dce_conn->auth_state.auth_info->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = gensec_seal_packet(dce_conn->auth_state.gensec_security, 
					    call,
					    ndr->data + DCERPC_REQUEST_LENGTH, 
					    payload_length,
					    blob->data,
					    blob->length - dce_conn->auth_state.auth_info->credentials.length,
					    &creds2);

		if (NT_STATUS_IS_OK(status)) {
			status = data_blob_realloc(call, blob,
						   blob->length - dce_conn->auth_state.auth_info->credentials.length + 
						   creds2.length);
		}

		if (NT_STATUS_IS_OK(status)) {
			memcpy(blob->data + blob->length - dce_conn->auth_state.auth_info->credentials.length,
			       creds2.data, creds2.length);
		}

		/* If we did AEAD signing of the packet headers, then we hope
		 * this value didn't change... */
		dcerpc_set_auth_length(blob, creds2.length);
		data_blob_free(&creds2);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		status = gensec_sign_packet(dce_conn->auth_state.gensec_security, 
					    call,
					    ndr->data + DCERPC_REQUEST_LENGTH, 
					    payload_length,
					    blob->data,
					    blob->length - dce_conn->auth_state.auth_info->credentials.length,
					    &creds2);
		if (NT_STATUS_IS_OK(status)) {
			status = data_blob_realloc(call, blob,
						   blob->length - dce_conn->auth_state.auth_info->credentials.length + 
						   creds2.length);
		}

		if (NT_STATUS_IS_OK(status)) {
			memcpy(blob->data + blob->length - dce_conn->auth_state.auth_info->credentials.length,
			       creds2.data, creds2.length);
		}

		/* If we did AEAD signing of the packet headers, then we hope
		 * this value didn't change... */
		dcerpc_set_auth_length(blob, creds2.length);

		data_blob_free(&creds2);
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		break;

	default:
		status = NT_STATUS_INVALID_LEVEL;
		break;
	}

	data_blob_free(&dce_conn->auth_state.auth_info->credentials);

	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}	

	return True;
}
