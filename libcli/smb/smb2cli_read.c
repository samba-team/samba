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
#include "lib/util/tevent_ntstatus.h"
#include "smb_common.h"
#include "smbXcli_base.h"

struct smb2cli_read_state {
	uint8_t fixed[48];
	uint8_t dyn_pad[1];
	struct iovec *recv_iov;
	uint8_t *data;
	uint32_t data_length;
	bool out_valid;
};

static void smb2cli_read_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_read_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct smbXcli_conn *conn,
				     uint32_t timeout_msec,
				     struct smbXcli_session *session,
				     struct smbXcli_tcon *tcon,
				     uint32_t length,
				     uint64_t offset,
				     uint64_t fid_persistent,
				     uint64_t fid_volatile,
				     uint64_t minimum_count,
				     uint64_t remaining_bytes)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_read_state *state;
	uint8_t *fixed;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_read_state);
	if (req == NULL) {
		return NULL;
	}

	fixed = state->fixed;

	SSVAL(fixed, 0, 49);
	SIVAL(fixed, 4, length);
	SBVAL(fixed, 8, offset);
	SBVAL(fixed, 16, fid_persistent);
	SBVAL(fixed, 24, fid_volatile);
	SBVAL(fixed, 32, minimum_count);
	SBVAL(fixed, 40, remaining_bytes);

	subreq = smb2cli_req_send(state, ev, conn, SMB2_OP_READ,
				  0, 0, /* flags */
				  timeout_msec,
				  tcon,
				  session,
				  state->fixed, sizeof(state->fixed),
				  state->dyn_pad, sizeof(state->dyn_pad),
				  length); /* max_dyn_len */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_read_done, req);
	return req;
}

static void smb2cli_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb2cli_read_state *state =
		tevent_req_data(req,
		struct smb2cli_read_state);
	NTSTATUS status;
	NTSTATUS error;
	struct iovec *iov;
	const uint8_t dyn_ofs = SMB2_HDR_BODY + 0x10;
	DATA_BLOB dyn_buffer = data_blob_null;
	uint8_t data_offset;
	DATA_BLOB data_buffer = data_blob_null;
	uint32_t next_offset = 0; /* this variable is completely ignored */
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = STATUS_BUFFER_OVERFLOW,
		.body_size = 0x11
	},
	{
		.status = NT_STATUS_OK,
		.body_size = 0x11
	}
	};

	status = smb2cli_req_recv(subreq, state, &iov,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		/* no error */
	} else {
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	data_offset = CVAL(iov[1].iov_base, 2);
	state->data_length = IVAL(iov[1].iov_base, 4);

	dyn_buffer = data_blob_const((uint8_t *)iov[2].iov_base,
				     iov[2].iov_len);

	error = smb2cli_parse_dyn_buffer(dyn_ofs,
					 dyn_buffer,
					 dyn_ofs, /* min_offset */
					 data_offset,
					 state->data_length,
					 dyn_buffer.length, /* max_length */
					 &next_offset,
					 &data_buffer);
	if (tevent_req_nterror(req, error)) {
		return;
	}

	state->recv_iov = iov;
	state->data = data_buffer.data;

	state->out_valid = true;

	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS smb2cli_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   uint8_t **data, uint32_t *data_length)
{
	struct smb2cli_read_state *state =
		tevent_req_data(req,
		struct smb2cli_read_state);
	NTSTATUS status = NT_STATUS_OK;

	if (tevent_req_is_nterror(req, &status) && !state->out_valid) {
		*data_length = 0;
		*data = NULL;
		tevent_req_received(req);
		return status;
	}
	talloc_steal(mem_ctx, state->recv_iov);
	*data_length = state->data_length;
	*data = state->data;
	tevent_req_received(req);
	return status;
}

NTSTATUS smb2cli_read(struct smbXcli_conn *conn,
		      uint32_t timeout_msec,
		      struct smbXcli_session *session,
		      struct smbXcli_tcon *tcon,
		      uint32_t length,
		      uint64_t offset,
		      uint64_t fid_persistent,
		      uint64_t fid_volatile,
		      uint64_t minimum_count,
		      uint64_t remaining_bytes,
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
	req = smb2cli_read_send(frame, ev,
				conn, timeout_msec, session, tcon,
				length, offset,
				fid_persistent, fid_volatile,
				minimum_count, remaining_bytes);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_read_recv(req, mem_ctx, data, data_length);
 fail:
	TALLOC_FREE(frame);
	return status;
}
