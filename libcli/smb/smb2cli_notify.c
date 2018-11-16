/*
   Unix SMB/CIFS implementation.
   smb2 lib
   Copyright (C) Volker Lendecke 2017

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
#include "lib/util/tevent_ntstatus.h"
#include "smb_common.h"
#include "smbXcli_base.h"
#include "librpc/gen_ndr/ndr_notify.h"

struct smb2cli_notify_state {
	uint8_t fixed[32];

	struct iovec *recv_iov;
	uint8_t *data;
	uint32_t data_length;

	struct tevent_req *subreq;
	struct tevent_req *timeout_subreq;
};

static void smb2cli_notify_done(struct tevent_req *subreq);
static void smb2cli_notify_timedout(struct tevent_req *subreq);
static bool smb2cli_notify_cancel(struct tevent_req *req);

struct tevent_req *smb2cli_notify_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct smbXcli_conn *conn,
				       uint32_t timeout_msec,
				       struct smbXcli_session *session,
				       struct smbXcli_tcon *tcon,
				       uint32_t output_buffer_length,
				       uint64_t fid_persistent,
				       uint64_t fid_volatile,
				       uint32_t completion_filter,
				       bool recursive)
{
	struct tevent_req *req;
	struct smb2cli_notify_state *state;
	uint8_t *fixed;
	uint16_t watch_tree;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_notify_state);
	if (req == NULL) {
		return NULL;
	}

	watch_tree = recursive ? SMB2_WATCH_TREE : 0;
	fixed = state->fixed;
	SSVAL(fixed, 0, 32);
	SSVAL(fixed, 2, watch_tree);
	SIVAL(fixed, 4, output_buffer_length);
	SBVAL(fixed, 8, fid_persistent);
	SBVAL(fixed, 16, fid_volatile);
	SIVAL(fixed, 24, completion_filter);
	SIVAL(fixed, 28, 0); 	/* reserved */

	state->subreq = smb2cli_req_send(state, ev, conn, SMB2_OP_NOTIFY,
					 0, 0, /* flags */
					 0,	/* timeout_msec */
					 tcon,
					 session,
					 state->fixed, sizeof(state->fixed),
					 NULL, 0, /* dyn* */
					 0); /* max_dyn_len */
	if (tevent_req_nomem(state->subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->subreq, smb2cli_notify_done, req);

	if (timeout_msec != 0) {
		state->timeout_subreq = tevent_wakeup_send(
			state, ev, timeval_current_ofs_msec(timeout_msec));
		if (tevent_req_nomem(state->timeout_subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			state->timeout_subreq, smb2cli_notify_timedout, req);
	}

	tevent_req_set_cancel_fn(req, smb2cli_notify_cancel);

	return req;
}

static bool smb2cli_notify_cancel(struct tevent_req *req)
{
	struct smb2cli_notify_state *state = tevent_req_data(
		req, struct smb2cli_notify_state);
	bool ok;

	TALLOC_FREE(state->timeout_subreq);

	ok = tevent_req_cancel(state->subreq);
	return ok;
}

static void smb2cli_notify_timedout(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb2cli_notify_state *state = tevent_req_data(
		req, struct smb2cli_notify_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	ok = tevent_req_cancel(state->subreq);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
}

static void smb2cli_notify_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb2cli_notify_state *state = tevent_req_data(
		req, struct smb2cli_notify_state);
	NTSTATUS status;
	struct iovec *iov;
	uint16_t data_offset;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x09
	}
	};

	status = smb2cli_req_recv(subreq, state, &iov,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_CANCELLED)) {
		status = NT_STATUS_IO_TIMEOUT;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	data_offset = SVAL(iov[1].iov_base, 2);
	state->data_length = IVAL(iov[1].iov_base, 4);

	if ((data_offset != SMB2_HDR_BODY + 8) ||
	    (state->data_length > iov[2].iov_len)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	state->recv_iov = iov;
	state->data = (uint8_t *)iov[2].iov_base;
	tevent_req_done(req);
}

NTSTATUS smb2cli_notify_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			     uint8_t **data, uint32_t *data_length)
{
	struct smb2cli_notify_state *state = tevent_req_data(
		req, struct smb2cli_notify_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	talloc_steal(mem_ctx, state->recv_iov);
	*data_length = state->data_length;
	*data = state->data;
	return NT_STATUS_OK;
}

NTSTATUS smb2cli_notify(struct smbXcli_conn *conn,
			uint32_t timeout_msec,
			struct smbXcli_session *session,
			struct smbXcli_tcon *tcon,
			uint32_t output_buffer_length,
			uint64_t fid_persistent,
			uint64_t fid_volatile,
			uint32_t completion_filter,
			bool recursive,
			TALLOC_CTX *mem_ctx,
			uint8_t **data,
			uint32_t *data_length)
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
	req = smb2cli_notify_send(frame, ev, conn, timeout_msec,
				  session, tcon, output_buffer_length,
				  fid_persistent, fid_volatile,
				  completion_filter, recursive);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_notify_recv(req, mem_ctx, data, data_length);
 fail:
	TALLOC_FREE(frame);
	return status;
}
