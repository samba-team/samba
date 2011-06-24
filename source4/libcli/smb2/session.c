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
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "auth/gensec/gensec.h"

#include <unistd.h>

/**
  initialise a smb2_session structure
 */
struct smb2_session *smb2_session_init(struct smb2_transport *transport,
				       struct gensec_settings *settings,
				       TALLOC_CTX *parent_ctx, bool primary)
{
	struct smb2_session *session;
	NTSTATUS status;

	session = talloc_zero(parent_ctx, struct smb2_session);
	if (!session) {
		return NULL;
	}
	if (primary) {
		session->transport = talloc_steal(session, transport);
	} else {
		session->transport = talloc_reference(session, transport);
	}

	session->pid = getpid();

	/* prepare a gensec context for later use */
	status = gensec_client_start(session, &session->gensec, 
				     session->transport->socket->event.ctx, 
				     settings);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(session);
		return NULL;
	}

	gensec_want_feature(session->gensec, GENSEC_FEATURE_SESSION_KEY);

	return session;
}

/**
  send a session setup request
*/
struct smb2_request *smb2_session_setup_send(struct smb2_session *session, 
					     struct smb2_session_setup *io)
{
	struct smb2_request *req;
	NTSTATUS status;
	
	req = smb2_request_init(session->transport, SMB2_OP_SESSSETUP, 
				0x18, true, io->in.secblob.length);
	if (req == NULL) return NULL;

	SBVAL(req->out.hdr,  SMB2_HDR_SESSION_ID, session->uid);
	SCVAL(req->out.body, 0x02, io->in.vc_number);
	SCVAL(req->out.body, 0x03, io->in.security_mode);
	SIVAL(req->out.body, 0x04, io->in.capabilities);
	SIVAL(req->out.body, 0x08, io->in.channel);
	SBVAL(req->out.body, 0x10, io->in.previous_sessionid);

	req->session = session;

	status = smb2_push_o16s16_blob(&req->out, 0x0C, io->in.secblob);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	smb2_transport_send(req);

	return req;
}


/**
  recv a session setup reply
*/
NTSTATUS smb2_session_setup_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx, 
				 struct smb2_session_setup *io)
{
	NTSTATUS status;

	if (!smb2_request_receive(req) || 
	    (smb2_request_is_error(req) && 
	     !NT_STATUS_EQUAL(req->status, NT_STATUS_MORE_PROCESSING_REQUIRED))) {
		return smb2_request_destroy(req);
	}

	SMB2_CHECK_PACKET_RECV(req, 0x08, true);

	io->out.session_flags = SVAL(req->in.body, 0x02);
	io->out.uid           = BVAL(req->in.hdr,  SMB2_HDR_SESSION_ID);
	
	status = smb2_pull_o16s16_blob(&req->in, mem_ctx, req->in.body+0x04, &io->out.secblob);
	if (!NT_STATUS_IS_OK(status)) {
		smb2_request_destroy(req);
		return status;
	}

	return smb2_request_destroy(req);
}

/*
  sync session setup request
*/
NTSTATUS smb2_session_setup(struct smb2_session *session, 
			    TALLOC_CTX *mem_ctx, struct smb2_session_setup *io)
{
	struct smb2_request *req = smb2_session_setup_send(session, io);
	return smb2_session_setup_recv(req, mem_ctx, io);
}

struct smb2_session_setup_spnego_state {
	struct smb2_session_setup io;
	struct smb2_request *req;
	NTSTATUS gensec_status;
};

static void smb2_session_setup_spnego_handler(struct smb2_request *req);

/*
  a composite function that does a full SPNEGO session setup
 */
struct tevent_req *smb2_session_setup_spnego_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct smb2_session *session,
						  struct cli_credentials *credentials)
{
	struct tevent_req *req;
	struct smb2_session_setup_spnego_state *state;
	const char *chosen_oid;
	struct smb2_request *subreq;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2_session_setup_spnego_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->io);
	state->io.in.vc_number          = 0;
	if (session->transport->signing_required) {
		state->io.in.security_mode =
			SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED;
	}
	state->io.in.capabilities       = 0;
	state->io.in.channel            = 0;
	state->io.in.previous_sessionid = 0;

	status = gensec_set_credentials(session->gensec, credentials);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = gensec_set_target_hostname(session->gensec,
					    session->transport->socket->hostname);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = gensec_set_target_service(session->gensec, "cifs");
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (session->transport->negotiate.secblob.length > 0) {
		chosen_oid = GENSEC_OID_SPNEGO;
	} else {
		chosen_oid = GENSEC_OID_NTLMSSP;
	}

	status = gensec_start_mech_by_oid(session->gensec, chosen_oid);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = gensec_update(session->gensec, state,
			       session->transport->negotiate.secblob,
			       &state->io.in.secblob);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}
	state->gensec_status = status;

	subreq = smb2_session_setup_send(session, &state->io);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	subreq->async.fn = smb2_session_setup_spnego_handler;
	subreq->async.private_data = req;

	return req;
}

/*
  handle continuations of the spnego session setup
*/
static void smb2_session_setup_spnego_handler(struct smb2_request *subreq)
{
	struct tevent_req *req =
		talloc_get_type_abort(subreq->async.private_data,
		struct tevent_req);
	struct smb2_session_setup_spnego_state *state =
		tevent_req_data(req,
		struct smb2_session_setup_spnego_state);
	struct smb2_session *session = subreq->session;
	NTSTATUS session_key_err;
	DATA_BLOB session_key;
	NTSTATUS peer_status;
	NTSTATUS status;

	status = smb2_session_setup_recv(subreq, state, &state->io);
	peer_status = status;
	if (NT_STATUS_EQUAL(peer_status, NT_STATUS_MORE_PROCESSING_REQUIRED) ||
	    (NT_STATUS_IS_OK(peer_status) &&
	     NT_STATUS_EQUAL(state->gensec_status, NT_STATUS_MORE_PROCESSING_REQUIRED))) {
		status = gensec_update(session->gensec, state,
				       state->io.out.secblob,
				       &state->io.in.secblob);
		state->gensec_status = status;
		session->uid = state->io.out.uid;
	}

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_EQUAL(peer_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		subreq = smb2_session_setup_send(session, &state->io);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}

		subreq->async.fn = smb2_session_setup_spnego_handler;
		subreq->async.private_data = req;
		return;
	}

	session_key_err = gensec_session_key(session->gensec, &session_key);
	if (NT_STATUS_IS_OK(session_key_err)) {
		session->session_key = session_key;
	}

	if (session->transport->signing_required) {
		if (session->session_key.length == 0) {
			DEBUG(0,("Wrong session key length %u for SMB2 signing\n",
				 (unsigned)session->session_key.length));
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
		session->signing_active = true;
	}

	tevent_req_done(req);
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
				   struct cli_credentials *credentials)
{
	struct tevent_req *subreq;
	NTSTATUS status;
	bool ok;
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = session->transport->socket->event.ctx;

	if (frame == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	subreq = smb2_session_setup_spnego_send(frame, ev,
						session, credentials);
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
