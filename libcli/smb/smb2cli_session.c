/*
   Unix SMB/CIFS implementation.
   smb2 lib
   Copyright (C) Volker Lendecke 2011

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
#include "../lib/util/tevent_ntstatus.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/smb/smbXcli_base.h"

struct smb2cli_session_setup_state {
	struct smbXcli_session *session;
	uint8_t fixed[24];
	uint8_t dyn_pad[1];
	struct iovec *recv_iov;
	DATA_BLOB out_security_buffer;
	NTSTATUS status;
};

static void smb2cli_session_setup_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_session_setup_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct smbXcli_conn *conn,
				uint32_t timeout_msec,
				struct smbXcli_session *session,
				uint8_t in_flags,
				uint32_t in_capabilities,
				uint32_t in_channel,
				uint64_t in_previous_session_id,
				const DATA_BLOB *in_security_buffer)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_session_setup_state *state;
	uint8_t *buf;
	uint8_t *dyn;
	size_t dyn_len;
	uint8_t security_mode;
	uint16_t security_buffer_offset = 0;
	uint16_t security_buffer_length = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_session_setup_state);
	if (req == NULL) {
		return NULL;
	}

	if (session == NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}
	state->session = session;
	security_mode = smb2cli_session_security_mode(session);

	if (in_security_buffer) {
		if (in_security_buffer->length > UINT16_MAX) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
			return tevent_req_post(req, ev);
		}
		security_buffer_offset = SMB2_HDR_BODY + 24;
		security_buffer_length = in_security_buffer->length;
	}

	buf = state->fixed;

	SSVAL(buf,  0, 25);
	SCVAL(buf,  2, in_flags);
	SCVAL(buf,  3, security_mode);
	SIVAL(buf,  4, in_capabilities);
	SIVAL(buf,  8, in_channel);
	SSVAL(buf, 12, security_buffer_offset);
	SSVAL(buf, 14, security_buffer_length);
	SBVAL(buf, 16, in_previous_session_id);

	if (security_buffer_length > 0) {
		dyn = in_security_buffer->data;
		dyn_len = in_security_buffer->length;
	} else {
		dyn = state->dyn_pad;;
		dyn_len = sizeof(state->dyn_pad);
	}

	subreq = smb2cli_req_send(state, ev,
				  conn, SMB2_OP_SESSSETUP,
				  0, 0, /* flags */
				  timeout_msec,
				  NULL, /* tcon */
				  session,
				  state->fixed, sizeof(state->fixed),
				  dyn, dyn_len,
				  UINT16_MAX); /* max_dyn_len */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_session_setup_done, req);
	return req;
}

static void smb2cli_session_setup_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_session_setup_state *state =
		tevent_req_data(req,
		struct smb2cli_session_setup_state);
	NTSTATUS status;
	uint64_t current_session_id;
	uint64_t session_id;
	uint16_t session_flags;
	uint16_t expected_offset = 0;
	uint16_t security_buffer_offset;
	uint16_t security_buffer_length;
	uint8_t *security_buffer_data = NULL;
	const uint8_t *hdr;
	const uint8_t *body;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_MORE_PROCESSING_REQUIRED,
		.body_size = 0x09
	},
	{
		.status = NT_STATUS_OK,
		.body_size = 0x09
	}
	};

	status = smb2cli_req_recv(subreq, state, &state->recv_iov,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		tevent_req_nterror(req, status);
		return;
	}

	hdr = (const uint8_t *)state->recv_iov[0].iov_base;
	body = (const uint8_t *)state->recv_iov[1].iov_base;

	session_id = BVAL(hdr, SMB2_HDR_SESSION_ID);
	session_flags = SVAL(body, 2);

	security_buffer_offset = SVAL(body, 4);
	security_buffer_length = SVAL(body, 6);

	if (security_buffer_length > 0) {
		expected_offset = SMB2_HDR_BODY + 8;
	}
	if (security_buffer_offset != 0) {
		security_buffer_data = (uint8_t *)state->recv_iov[2].iov_base;
		expected_offset = SMB2_HDR_BODY + 8;
	}

	if (security_buffer_offset != expected_offset) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
	if (security_buffer_length > state->recv_iov[2].iov_len) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	state->out_security_buffer.data = security_buffer_data;
	state->out_security_buffer.length = security_buffer_length;

	current_session_id = smb2cli_session_current_id(state->session);
	if (current_session_id == 0) {
		/* A new session was requested */
		current_session_id = session_id;
	}

	if (current_session_id != session_id) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	smb2cli_session_set_id_and_flags(state->session,
					 session_id, session_flags);

	state->status = status;
	tevent_req_done(req);
}

NTSTATUS smb2cli_session_setup_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    struct iovec **recv_iov,
				    DATA_BLOB *out_security_buffer)
{
	struct smb2cli_session_setup_state *state =
		tevent_req_data(req,
		struct smb2cli_session_setup_state);
	NTSTATUS status;
	struct iovec *_tmp;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	if (recv_iov == NULL) {
		recv_iov = &_tmp;
	}

	*recv_iov = talloc_move(mem_ctx, &state->recv_iov);

	*out_security_buffer = state->out_security_buffer;

	/*
	 * Return the status from the server:
	 * NT_STATUS_MORE_PROCESSING_REQUIRED or
	 * NT_STATUS_OK.
	 */
	status = state->status;
	tevent_req_received(req);
	return status;
}

struct smb2cli_logoff_state {
	uint8_t fixed[4];
};

static void smb2cli_logoff_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_logoff_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct smbXcli_conn *conn,
				       uint32_t timeout_msec,
				       struct smbXcli_session *session)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_logoff_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_logoff_state);
	if (req == NULL) {
		return NULL;
	}
	SSVAL(state->fixed, 0, 4);

	subreq = smb2cli_req_send(state, ev,
				  conn, SMB2_OP_LOGOFF,
				  0, 0, /* flags */
				  timeout_msec,
				  NULL, /* tcon */
				  session,
				  state->fixed, sizeof(state->fixed),
				  NULL, 0, /* dyn* */
				  0); /* max_dyn_len */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_logoff_done, req);
	return req;
}

static void smb2cli_logoff_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_logoff_state *state =
		tevent_req_data(req,
		struct smb2cli_logoff_state);
	NTSTATUS status;
	struct iovec *iov;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x04
	}
	};

	status = smb2cli_req_recv(subreq, state, &iov,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS smb2cli_logoff_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb2cli_logoff(struct smbXcli_conn *conn,
			uint32_t timeout_msec,
			struct smbXcli_session *session)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_logoff_send(frame, ev, conn, timeout_msec, session);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_logoff_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}
