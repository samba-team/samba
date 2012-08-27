/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2010

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../auth/gensec/gensec.h"
#include "auth.h"
#include "../lib/tsocket/tsocket.h"
#include "../libcli/security/security.h"
#include "../lib/util/tevent_ntstatus.h"

static struct tevent_req *smbd_smb2_session_setup_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req,
					uint64_t in_session_id,
					uint8_t in_flags,
					uint8_t in_security_mode,
					uint64_t in_previous_session_id,
					DATA_BLOB in_security_buffer);
static NTSTATUS smbd_smb2_session_setup_recv(struct tevent_req *req,
					uint16_t *out_session_flags,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id);

static void smbd_smb2_request_sesssetup_done(struct tevent_req *subreq);

NTSTATUS smbd_smb2_request_process_sesssetup(struct smbd_smb2_request *smb2req)
{
	const uint8_t *inhdr;
	const uint8_t *inbody;
	uint64_t in_session_id;
	uint8_t in_flags;
	uint8_t in_security_mode;
	uint64_t in_previous_session_id;
	uint16_t in_security_offset;
	uint16_t in_security_length;
	DATA_BLOB in_security_buffer;
	NTSTATUS status;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(smb2req, 0x19);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(smb2req, status);
	}
	inhdr = SMBD_SMB2_IN_HDR_PTR(smb2req);
	inbody = SMBD_SMB2_IN_BODY_PTR(smb2req);

	in_session_id = BVAL(inhdr, SMB2_HDR_SESSION_ID);

	in_flags = CVAL(inbody, 0x02);
	in_security_mode = CVAL(inbody, 0x03);
	/* Capabilities = IVAL(inbody, 0x04) */
	/* Channel = IVAL(inbody, 0x08) */
	in_security_offset = SVAL(inbody, 0x0C);
	in_security_length = SVAL(inbody, 0x0E);
	in_previous_session_id = BVAL(inbody, 0x10);

	if (in_security_offset != (SMB2_HDR_BODY + SMBD_SMB2_IN_BODY_LEN(smb2req))) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_security_length > SMBD_SMB2_IN_DYN_LEN(smb2req)) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_INVALID_PARAMETER);
	}

	in_security_buffer.data = SMBD_SMB2_IN_DYN_PTR(smb2req);
	in_security_buffer.length = in_security_length;

	subreq = smbd_smb2_session_setup_send(smb2req,
					      smb2req->sconn->ev_ctx,
					      smb2req,
					      in_session_id,
					      in_flags,
					      in_security_mode,
					      in_previous_session_id,
					      in_security_buffer);
	if (subreq == NULL) {
		return smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_sesssetup_done, smb2req);

	return smbd_smb2_request_pending_queue(smb2req, subreq, 500);
}

static void smbd_smb2_request_sesssetup_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *smb2req =
		tevent_req_callback_data(subreq,
		struct smbd_smb2_request);
	uint8_t *outhdr;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	uint16_t out_session_flags;
	uint64_t out_session_id;
	uint16_t out_security_offset;
	DATA_BLOB out_security_buffer = data_blob_null;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_session_setup_recv(subreq,
					      &out_session_flags,
					      smb2req,
					      &out_security_buffer,
					      &out_session_id);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = nt_status_squash(status);
		error = smbd_smb2_request_error(smb2req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->sconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	out_security_offset = SMB2_HDR_BODY + 0x08;

	outhdr = SMBD_SMB2_OUT_HDR_PTR(smb2req);

	outbody = data_blob_talloc(smb2req->out.vector, NULL, 0x08);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(smb2req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(smb2req->sconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SBVAL(outhdr, SMB2_HDR_SESSION_ID, out_session_id);

	SSVAL(outbody.data, 0x00, 0x08 + 1);	/* struct size */
	SSVAL(outbody.data, 0x02,
	      out_session_flags);		/* session flags */
	SSVAL(outbody.data, 0x04,
	      out_security_offset);		/* security buffer offset */
	SSVAL(outbody.data, 0x06,
	      out_security_buffer.length);	/* security buffer length */

	outdyn = out_security_buffer;

	error = smbd_smb2_request_done_ex(smb2req, status, outbody, &outdyn,
					   __location__);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(smb2req->sconn,
						 nt_errstr(error));
		return;
	}
}

static NTSTATUS smbd_smb2_auth_generic_return(struct smbXsrv_session *session,
					struct smbd_smb2_request *smb2req,
					uint8_t in_security_mode,
					struct auth_session_info *session_info,
					uint16_t *out_session_flags,
					uint64_t *out_session_id)
{
	NTSTATUS status;
	bool guest = false;
	uint8_t session_key[16];
	struct smbXsrv_session *x = session;
	struct smbXsrv_connection *conn = session->connection;

	if ((in_security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) ||
	    lp_server_signing() == SMB_SIGNING_REQUIRED) {
		x->global->signing_required = true;
	}

	if (lp_smb_encrypt(-1) == SMB_SIGNING_REQUIRED) {
		x->global->encryption_required = true;
	}

	if (security_session_user_level(session_info, NULL) < SECURITY_USER) {
		/* we map anonymous to guest internally */
		*out_session_flags |= SMB2_SESSION_FLAG_IS_GUEST;
		*out_session_flags |= SMB2_SESSION_FLAG_IS_NULL;
		/* force no signing */
		x->global->signing_required = false;
		guest = true;
	}

	if (guest && x->global->encryption_required) {
		DEBUG(1,("reject guest session as encryption is required\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!(conn->smb2.server.capabilities & SMB2_CAP_ENCRYPTION)) {
		if (x->global->encryption_required) {
			DEBUG(1,("reject session with dialect[0x%04X] "
				 "as encryption is required\n",
				 conn->smb2.server.dialect));
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (x->global->encryption_required) {
		*out_session_flags |= SMB2_SESSION_FLAG_ENCRYPT_DATA;
	}

	ZERO_STRUCT(session_key);
	memcpy(session_key, session_info->session_key.data,
	       MIN(session_info->session_key.length, sizeof(session_key)));

	x->global->signing_key = data_blob_talloc(x->global,
						  session_key,
						  sizeof(session_key));
	if (x->global->signing_key.data == NULL) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}

	if (conn->protocol >= PROTOCOL_SMB2_24) {
		const DATA_BLOB label = data_blob_string_const_null("SMB2AESCMAC");
		const DATA_BLOB context = data_blob_string_const_null("SmbSign");

		smb2_key_derivation(session_key, sizeof(session_key),
				    label.data, label.length,
				    context.data, context.length,
				    x->global->signing_key.data);
	}

	if (conn->protocol >= PROTOCOL_SMB2_24) {
		const DATA_BLOB label = data_blob_string_const_null("SMB2AESCCM");
		const DATA_BLOB context = data_blob_string_const_null("ServerIn ");

		x->global->decryption_key = data_blob_talloc(x->global,
							     session_key,
							     sizeof(session_key));
		if (x->global->decryption_key.data == NULL) {
			ZERO_STRUCT(session_key);
			return NT_STATUS_NO_MEMORY;
		}

		smb2_key_derivation(session_key, sizeof(session_key),
				    label.data, label.length,
				    context.data, context.length,
				    x->global->decryption_key.data);
	}

	if (conn->protocol >= PROTOCOL_SMB2_24) {
		const DATA_BLOB label = data_blob_string_const_null("SMB2AESCCM");
		const DATA_BLOB context = data_blob_string_const_null("ServerOut");

		x->global->encryption_key = data_blob_talloc(x->global,
							     session_key,
							     sizeof(session_key));
		if (x->global->encryption_key.data == NULL) {
			ZERO_STRUCT(session_key);
			return NT_STATUS_NO_MEMORY;
		}

		smb2_key_derivation(session_key, sizeof(session_key),
				    label.data, label.length,
				    context.data, context.length,
				    x->global->encryption_key.data);

		generate_random_buffer((uint8_t *)&x->nonce_high, sizeof(x->nonce_high));
		x->nonce_low = 1;
	}

	x->global->application_key = data_blob_dup_talloc(x->global,
						x->global->signing_key);
	if (x->global->application_key.data == NULL) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}

	if (conn->protocol >= PROTOCOL_SMB2_24) {
		const DATA_BLOB label = data_blob_string_const_null("SMB2APP");
		const DATA_BLOB context = data_blob_string_const_null("SmbRpc");

		smb2_key_derivation(session_key, sizeof(session_key),
				    label.data, label.length,
				    context.data, context.length,
				    x->global->application_key.data);
	}
	ZERO_STRUCT(session_key);

	x->global->channels[0].signing_key = data_blob_dup_talloc(x->global->channels,
						x->global->signing_key);
	if (x->global->channels[0].signing_key.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	data_blob_clear_free(&session_info->session_key);
	session_info->session_key = data_blob_dup_talloc(session_info,
						x->global->application_key);
	if (session_info->session_key.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	session->compat = talloc_zero(session, struct user_struct);
	if (session->compat == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	session->compat->session = session;
	session->compat->homes_snum = -1;
	session->compat->session_info = session_info;
	session->compat->session_keystr = NULL;
	session->compat->vuid = session->global->session_wire_id;
	DLIST_ADD(smb2req->sconn->users, session->compat);
	smb2req->sconn->num_users++;

	if (security_session_user_level(session_info, NULL) >= SECURITY_USER) {
		session->compat->homes_snum =
			register_homes_share(session_info->unix_info->unix_name);
	}

	set_current_user_info(session_info->unix_info->sanitized_username,
			      session_info->unix_info->unix_name,
			      session_info->info->domain_name);

	reload_services(smb2req->sconn, conn_snum_used, true);

	session->status = NT_STATUS_OK;
	session->global->auth_session_info = session_info;
	session->global->auth_session_info_seqnum += 1;
	session->global->channels[0].auth_session_info_seqnum =
		session->global->auth_session_info_seqnum;
	session->global->expiration_time = gensec_expire_time(session->gensec);

	if (!session_claim(session)) {
		DEBUG(1, ("smb2: Failed to claim session "
			"for vuid=%llu\n",
			(unsigned long long)session->compat->vuid));
		return NT_STATUS_LOGON_FAILURE;
	}

	status = smbXsrv_session_update(session);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smb2: Failed to update session for vuid=%llu - %s\n",
			  (unsigned long long)session->compat->vuid,
			  nt_errstr(status)));
		return NT_STATUS_LOGON_FAILURE;
	}

	/*
	 * we attach the session to the request
	 * so that the response can be signed
	 */
	smb2req->session = session;
	if (!guest) {
		smb2req->do_signing = true;
	}

	global_client_caps |= (CAP_LEVEL_II_OPLOCKS|CAP_STATUS32);

	*out_session_id = session->global->session_wire_id;

	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_reauth_generic_return(struct smbXsrv_session *session,
					struct smbd_smb2_request *smb2req,
					struct auth_session_info *session_info,
					uint16_t *out_session_flags,
					uint64_t *out_session_id)
{
	NTSTATUS status;
	struct smbXsrv_session *x = session;
	struct smbXsrv_connection *conn = session->connection;

	data_blob_clear_free(&session_info->session_key);
	session_info->session_key = data_blob_dup_talloc(session_info,
						x->global->application_key);
	if (session_info->session_key.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	session->compat->session_info = session_info;
	session->compat->vuid = session->global->session_wire_id;

	session->compat->homes_snum =
			register_homes_share(session_info->unix_info->unix_name);

	set_current_user_info(session_info->unix_info->sanitized_username,
			      session_info->unix_info->unix_name,
			      session_info->info->domain_name);

	reload_services(smb2req->sconn, conn_snum_used, true);

	session->status = NT_STATUS_OK;
	TALLOC_FREE(session->global->auth_session_info);
	session->global->auth_session_info = session_info;
	session->global->auth_session_info_seqnum += 1;
	session->global->channels[0].auth_session_info_seqnum =
		session->global->auth_session_info_seqnum;
	session->global->expiration_time = gensec_expire_time(session->gensec);

	status = smbXsrv_session_update(session);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smb2: Failed to update session for vuid=%llu - %s\n",
			  (unsigned long long)session->compat->vuid,
			  nt_errstr(status)));
		return NT_STATUS_LOGON_FAILURE;
	}

	conn_clear_vuid_caches(conn->sconn, session->compat->vuid);

	*out_session_id = session->global->session_wire_id;

	return NT_STATUS_OK;
}

struct smbd_smb2_session_setup_state {
	struct tevent_context *ev;
	struct smbd_smb2_request *smb2req;
	uint64_t in_session_id;
	uint8_t in_flags;
	uint8_t in_security_mode;
	uint64_t in_previous_session_id;
	DATA_BLOB in_security_buffer;
	struct smbXsrv_session *session;
	struct auth_session_info *session_info;
	uint16_t out_session_flags;
	DATA_BLOB out_security_buffer;
	uint64_t out_session_id;
	/* The following pointer is owned by state->session. */
	struct smbd_smb2_session_setup_state **pp_self_ref;
};

static int pp_self_ref_destructor(struct smbd_smb2_session_setup_state **pp_state)
{
	(*pp_state)->session = NULL;
	/*
	 * To make things clearer, ensure the pp_self_ref
	 * pointer is nulled out. We're never going to
	 * access this again.
	 */
	(*pp_state)->pp_self_ref = NULL;
	return 0;
}

static int smbd_smb2_session_setup_state_destructor(struct smbd_smb2_session_setup_state *state)
{
	/*
	 * if state->session is not NULL,
	 * we remove the session on failure
	 */
	TALLOC_FREE(state->session);
	return 0;
}

static void smbd_smb2_session_setup_gensec_done(struct tevent_req *subreq);
static void smbd_smb2_session_setup_previous_done(struct tevent_req *subreq);

/************************************************************************
 We have to tag the state->session pointer with memory talloc'ed
 on it to ensure it gets NULL'ed out if the underlying struct smbXsrv_session
 is deleted by shutdown whilst this request is in flight.
************************************************************************/

static NTSTATUS tag_state_session_ptr(struct smbd_smb2_session_setup_state *state)
{
	state->pp_self_ref = talloc_zero(state->session,
			struct smbd_smb2_session_setup_state *);
	if (state->pp_self_ref == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	*state->pp_self_ref = state;
	talloc_set_destructor(state->pp_self_ref, pp_self_ref_destructor);
	return NT_STATUS_OK;
}

static struct tevent_req *smbd_smb2_session_setup_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_smb2_request *smb2req,
					uint64_t in_session_id,
					uint8_t in_flags,
					uint8_t in_security_mode,
					uint64_t in_previous_session_id,
					DATA_BLOB in_security_buffer)
{
	struct tevent_req *req;
	struct smbd_smb2_session_setup_state *state;
	NTSTATUS status;
	NTTIME now = timeval_to_nttime(&smb2req->request_time);
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_session_setup_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->smb2req = smb2req;
	state->in_session_id = in_session_id;
	state->in_flags = in_flags;
	state->in_security_mode = in_security_mode;
	state->in_previous_session_id = in_previous_session_id;
	state->in_security_buffer = in_security_buffer;

	if (in_flags & SMB2_SESSION_FLAG_BINDING) {
		if (smb2req->sconn->conn->protocol < PROTOCOL_SMB2_22) {
			tevent_req_nterror(req, NT_STATUS_REQUEST_NOT_ACCEPTED);
			return tevent_req_post(req, ev);
		}

		/*
		 * We do not support multi channel.
		 */
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
	}

	talloc_set_destructor(state, smbd_smb2_session_setup_state_destructor);

	if (state->in_session_id == 0) {
		/* create a new session */
		status = smbXsrv_session_create(state->smb2req->sconn->conn,
					        now, &state->session);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	} else {
		status = smb2srv_session_lookup(state->smb2req->sconn->conn,
						state->in_session_id, now,
						&state->session);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
			status = NT_STATUS_OK;
		}
		if (NT_STATUS_IS_OK(status)) {
			state->session->status = NT_STATUS_MORE_PROCESSING_REQUIRED;
			status = NT_STATUS_MORE_PROCESSING_REQUIRED;
			TALLOC_FREE(state->session->gensec);
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
	}

	status = tag_state_session_ptr(state);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (state->session->gensec == NULL) {
		status = auth_generic_prepare(state->session,
					      state->session->connection->remote_address,
					      &state->session->gensec);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		gensec_want_feature(state->session->gensec, GENSEC_FEATURE_SESSION_KEY);
		gensec_want_feature(state->session->gensec, GENSEC_FEATURE_UNIX_TOKEN);

		status = gensec_start_mech_by_oid(state->session->gensec,
						  GENSEC_OID_SPNEGO);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	become_root();
	subreq = gensec_update_send(state, state->ev,
				    state->session->gensec,
				    state->in_security_buffer);
	unbecome_root();
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbd_smb2_session_setup_gensec_done, req);

	return req;
}

static void smbd_smb2_session_setup_gensec_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbd_smb2_session_setup_state *state =
		tevent_req_data(req,
		struct smbd_smb2_session_setup_state);
	NTSTATUS status;

	become_root();
	status = gensec_update_recv(subreq, state,
				    &state->out_security_buffer);
	unbecome_root();
	TALLOC_FREE(subreq);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) &&
	    !NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		state->out_session_id = state->session->global->session_wire_id;
		/* we want to keep the session */
		TALLOC_FREE(state->pp_self_ref);
		tevent_req_nterror(req, status);
		return;
	}

	status = gensec_session_info(state->session->gensec,
				     state->session->global,
				     &state->session_info);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if ((state->in_previous_session_id != 0) &&
	     (state->session->global->session_wire_id !=
	      state->in_previous_session_id))
	{
		subreq = smb2srv_session_close_previous_send(state, state->ev,
						state->session->connection,
						state->session_info,
						state->in_previous_session_id,
						state->session->global->session_wire_id);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					smbd_smb2_session_setup_previous_done,
					req);
		return;
	}

	if (state->session->global->auth_session_info != NULL) {
		status = smbd_smb2_reauth_generic_return(state->session,
							 state->smb2req,
							 state->session_info,
							 &state->out_session_flags,
							 &state->out_session_id);
		if (tevent_req_nterror(req, status)) {
			return;
		}
		/* we want to keep the session */
		TALLOC_FREE(state->pp_self_ref);
		tevent_req_done(req);
		return;
	}

	status = smbd_smb2_auth_generic_return(state->session,
					       state->smb2req,
					       state->in_security_mode,
					       state->session_info,
					       &state->out_session_flags,
					       &state->out_session_id);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/* we want to keep the session */
	TALLOC_FREE(state->pp_self_ref);
	tevent_req_done(req);
	return;
}

static void smbd_smb2_session_setup_previous_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbd_smb2_session_setup_state *state =
		tevent_req_data(req,
		struct smbd_smb2_session_setup_state);
	NTSTATUS status;

	status = smb2srv_session_close_previous_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->session->global->auth_session_info != NULL) {
		status = smbd_smb2_reauth_generic_return(state->session,
							 state->smb2req,
							 state->session_info,
							 &state->out_session_flags,
							 &state->out_session_id);
		if (tevent_req_nterror(req, status)) {
			return;
		}
		/* we want to keep the session */
		TALLOC_FREE(state->pp_self_ref);
		tevent_req_done(req);
		return;
	}

	status = smbd_smb2_auth_generic_return(state->session,
					       state->smb2req,
					       state->in_security_mode,
					       state->session_info,
					       &state->out_session_flags,
					       &state->out_session_id);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/* we want to keep the session */
	TALLOC_FREE(state->pp_self_ref);
	tevent_req_done(req);
	return;
}

static NTSTATUS smbd_smb2_session_setup_recv(struct tevent_req *req,
					uint16_t *out_session_flags,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *out_security_buffer,
					uint64_t *out_session_id)
{
	struct smbd_smb2_session_setup_state *state =
		tevent_req_data(req,
		struct smbd_smb2_session_setup_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			tevent_req_received(req);
			return nt_status_squash(status);
		}
	} else {
		status = NT_STATUS_OK;
	}

	*out_session_flags = state->out_session_flags;
	*out_security_buffer = state->out_security_buffer;
	*out_session_id = state->out_session_id;

	talloc_steal(mem_ctx, out_security_buffer->data);
	tevent_req_received(req);
	return status;
}

NTSTATUS smbd_smb2_request_process_logoff(struct smbd_smb2_request *req)
{
	NTSTATUS status;
	DATA_BLOB outbody;

	status = smbd_smb2_request_verify_sizes(req, 0x04);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	/*
	 * TODO: cancel all outstanding requests on the session
	 */
	status = smbXsrv_session_logoff(req->session);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smbd_smb2_request_process_logoff: "
			  "smbXsrv_session_logoff() failed: %s\n",
			  nt_errstr(status)));
		/*
		 * If we hit this case, there is something completely
		 * wrong, so we better disconnect the transport connection.
		 */
		return status;
	}

	/*
	 * we may need to sign the response, so we need to keep
	 * the session until the response is sent to the wire.
	 */
	talloc_steal(req, req->session);

	outbody = data_blob_talloc(req->out.vector, NULL, 0x04);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	SSVAL(outbody.data, 0x00, 0x04);	/* struct size */
	SSVAL(outbody.data, 0x02, 0);		/* reserved */

	return smbd_smb2_request_done(req, outbody, NULL);
}
