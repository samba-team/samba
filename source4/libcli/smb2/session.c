/* 
   Unix SMB/CIFS implementation.

   SMB2 client session handling

   Copyright (C) Andrew Tridgell 2005
   
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
#include "system/network.h"
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "../libcli/smb/smbXcli_base.h"

/**
  initialise a smb2_session structure
 */
struct smb2_session *smb2_session_init(struct smb2_transport *transport,
				       struct gensec_settings *settings,
				       TALLOC_CTX *parent_ctx)
{
	struct smb2_session *session;
	NTSTATUS status;

	session = talloc_zero(parent_ctx, struct smb2_session);
	if (!session) {
		return NULL;
	}
	session->transport = talloc_steal(session, transport);

	session->smbXcli = smbXcli_session_create(session, transport->conn);
	if (session->smbXcli == NULL) {
		talloc_free(session);
		return NULL;
	}

	/* prepare a gensec context for later use */
	status = gensec_client_start(session, &session->gensec,
				     settings);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(session);
		return NULL;
	}

	gensec_want_feature(session->gensec, GENSEC_FEATURE_SESSION_KEY);

	return session;
}

/*
 * Note: that the caller needs to keep 'transport' around as
 *       long as the returned session is active!
 */
struct smb2_session *smb2_session_channel(struct smb2_transport *transport,
					  struct gensec_settings *settings,
					  TALLOC_CTX *parent_ctx,
					  struct smb2_session *base_session)
{
	struct smb2_session *session;
	NTSTATUS status;

	session = talloc_zero(parent_ctx, struct smb2_session);
	if (!session) {
		return NULL;
	}
	session->transport = transport;

	status = smb2cli_session_create_channel(session,
						base_session->smbXcli,
						transport->conn,
						&session->smbXcli);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(session);
		return NULL;
	}

	session->needs_bind = true;

	/* prepare a gensec context for later use */
	status = gensec_client_start(session, &session->gensec,
				     settings);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(session);
		return NULL;
	}

	gensec_want_feature(session->gensec, GENSEC_FEATURE_SESSION_KEY);

	return session;
}

struct smb2_session_setup_spnego_state {
	struct tevent_context *ev;
	struct smb2_session *session;
	struct cli_credentials *credentials;
	uint64_t previous_session_id;
	bool session_bind;
	bool reauth;
	NTSTATUS gensec_status;
	DATA_BLOB in_secblob;
	DATA_BLOB out_secblob;
};

static void smb2_session_setup_spnego_done(struct tevent_req *subreq);

/*
  a composite function that does a full SPNEGO session setup
 */
struct tevent_req *smb2_session_setup_spnego_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct smb2_session *session,
				struct cli_credentials *credentials,
				uint64_t previous_session_id)
{
	struct tevent_req *req;
	struct smb2_session_setup_spnego_state *state;
	uint64_t current_session_id;
	const char *chosen_oid;
	struct tevent_req *subreq;
	NTSTATUS status;
	const DATA_BLOB *server_gss_blob;
	DATA_BLOB negprot_secblob = data_blob_null;
	uint32_t timeout_msec;
	uint8_t in_flags = 0;

	timeout_msec = session->transport->options.request_timeout * 1000;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2_session_setup_spnego_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->session = session;
	state->credentials = credentials;
	state->previous_session_id = previous_session_id;

	current_session_id = smb2cli_session_current_id(state->session->smbXcli);
	if (state->session->needs_bind) {
		state->session_bind = true;
	} else if (current_session_id != 0) {
		state->reauth = true;
	}
	server_gss_blob = smbXcli_conn_server_gss_blob(session->transport->conn);
	if (server_gss_blob) {
		negprot_secblob = *server_gss_blob;
	}

	status = gensec_set_credentials(session->gensec, credentials);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = gensec_set_target_hostname(session->gensec,
					    smbXcli_conn_remote_name(session->transport->conn));
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = gensec_set_target_service(session->gensec, "cifs");
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (negprot_secblob.length > 0) {
		chosen_oid = GENSEC_OID_SPNEGO;
	} else {
		chosen_oid = GENSEC_OID_NTLMSSP;
	}

	status = gensec_start_mech_by_oid(session->gensec, chosen_oid);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = gensec_update_ev(session->gensec, state,
			       state->ev,
			       negprot_secblob,
			       &state->in_secblob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}
	state->gensec_status = status;

	if (state->session_bind) {
		in_flags |= SMB2_SESSION_FLAG_BINDING;
	}

	subreq = smb2cli_session_setup_send(state, state->ev,
					    session->transport->conn,
					    timeout_msec,
					    session->smbXcli,
					    in_flags,
					    0, /* in_capabilities */
					    0, /* in_channel */
					    state->previous_session_id,
					    &state->in_secblob);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2_session_setup_spnego_done, req);

	return req;
}

/*
  handle continuations of the spnego session setup
*/
static void smb2_session_setup_spnego_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2_session_setup_spnego_state *state =
		tevent_req_data(req,
		struct smb2_session_setup_spnego_state);
	struct smb2_session *session = state->session;
	NTSTATUS peer_status;
	NTSTATUS status;
	struct iovec *recv_iov;
	uint32_t timeout_msec;
	uint8_t in_flags = 0;

	timeout_msec = session->transport->options.request_timeout * 1000;

	status = smb2cli_session_setup_recv(subreq, state,
					    &recv_iov,
					    &state->out_secblob);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return;
	}
	peer_status = status;

	if (NT_STATUS_EQUAL(state->gensec_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		status = gensec_update_ev(session->gensec, state,
				       state->ev,
				       state->out_secblob,
				       &state->in_secblob);
		state->gensec_status = status;
	}

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_IS_OK(peer_status) && NT_STATUS_IS_OK(state->gensec_status)) {
		DATA_BLOB session_key;

		if (state->reauth) {
			tevent_req_done(req);
			return;
		}

		if (cli_credentials_is_anonymous(state->credentials)) {
			/*
			 * Windows server does not set the
			 * SMB2_SESSION_FLAG_IS_GUEST nor
			 * SMB2_SESSION_FLAG_IS_NULL flag.
			 *
			 * This fix makes sure we do not try
			 * to verify a signature on the final
			 * session setup response.
			 */
			tevent_req_done(req);
			return;
		}

		status = gensec_session_key(session->gensec, state,
					    &session_key);
		if (tevent_req_nterror(req, status)) {
			return;
		}

		if (state->session_bind) {
			status = smb2cli_session_set_channel_key(session->smbXcli,
								 session_key,
								 recv_iov);
			if (tevent_req_nterror(req, status)) {
				return;
			}
			session->needs_bind = false;
		} else {
			status = smb2cli_session_set_session_key(session->smbXcli,
								 session_key,
								 recv_iov);
			if (tevent_req_nterror(req, status)) {
				return;
			}
		}
		tevent_req_done(req);
		return;
	}

	if (state->session_bind) {
		in_flags |= SMB2_SESSION_FLAG_BINDING;
	}

	subreq = smb2cli_session_setup_send(state, state->ev,
					    session->transport->conn,
					    timeout_msec,
					    session->smbXcli,
					    in_flags,
					    0, /* in_capabilities */
					    0, /* in_channel */
					    state->previous_session_id,
					    &state->in_secblob);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smb2_session_setup_spnego_done, req);
}

/*
  receive a composite session setup reply
*/
NTSTATUS smb2_session_setup_spnego_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/*
  sync version of smb2_session_setup_spnego
*/
NTSTATUS smb2_session_setup_spnego(struct smb2_session *session, 
				   struct cli_credentials *credentials,
				   uint64_t previous_session_id)
{
	struct tevent_req *subreq;
	NTSTATUS status;
	bool ok;
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = session->transport->ev;

	if (frame == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	subreq = smb2_session_setup_spnego_send(frame, ev,
						session, credentials,
						previous_session_id);
	if (subreq == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		status = map_nt_error_from_unix_common(errno);
		TALLOC_FREE(frame);
		return status;
	}

	status = smb2_session_setup_spnego_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
