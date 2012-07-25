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

struct smb2cli_query_directory_state {
	uint8_t fixed[32];
	uint8_t dyn_pad[1];
	struct iovec *recv_iov;
	uint8_t *data;
	uint32_t data_length;
};

static void smb2cli_query_directory_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_query_directory_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct smbXcli_conn *conn,
						uint32_t timeout_msec,
						struct smbXcli_session *session,
						struct smbXcli_tcon *tcon,
						uint8_t level,
						uint8_t flags,
						uint32_t file_index,
						uint64_t fid_persistent,
						uint64_t fid_volatile,
						const char *mask,
						uint32_t outbuf_len)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_query_directory_state *state;
	uint8_t *fixed;
	uint8_t *dyn;
	size_t dyn_len;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_query_directory_state);
	if (req == NULL) {
		return NULL;
	}

	if (!convert_string_talloc(state, CH_UNIX, CH_UTF16,
				   mask, strlen(mask),
				   &dyn, &dyn_len)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	if (strlen(mask) == 0) {
		TALLOC_FREE(dyn);
		dyn_len = 0;
	}

	fixed = state->fixed;
	SSVAL(fixed, 0, 33);
	SCVAL(fixed, 2, level);
	SCVAL(fixed, 3, flags);
	SIVAL(fixed, 4, file_index);
	SBVAL(fixed, 8, fid_persistent);
	SBVAL(fixed, 16, fid_volatile);
	SSVAL(fixed, 24, SMB2_HDR_BODY + 32);
	SSVAL(fixed, 26, dyn_len);
	SSVAL(fixed, 28, outbuf_len);

	if (dyn_len == 0) {
		dyn = state->dyn_pad;
		dyn_len = sizeof(state->dyn_pad);
	}

	subreq = smb2cli_req_send(state, ev, conn, SMB2_OP_FIND,
				  0, 0, /* flags */
				  timeout_msec,
				  tcon,
				  session,
				  state->fixed, sizeof(state->fixed),
				  dyn, dyn_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_query_directory_done, req);
	return req;
}

static void smb2cli_query_directory_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_query_directory_state *state =
		tevent_req_data(req,
		struct smb2cli_query_directory_state);
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

NTSTATUS smb2cli_query_directory_recv(struct tevent_req *req,
				       TALLOC_CTX *mem_ctx,
				       uint8_t **data,
				       uint32_t *data_length)
{
	struct smb2cli_query_directory_state *state =
		tevent_req_data(req,
		struct smb2cli_query_directory_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	talloc_steal(mem_ctx, state->recv_iov);
	*data_length = state->data_length;
	*data = state->data;
	return NT_STATUS_OK;
}

NTSTATUS smb2cli_query_directory(struct smbXcli_conn *conn,
				 uint32_t timeout_msec,
				 struct smbXcli_session *session,
				 struct smbXcli_tcon *tcon,
				 uint8_t level,
				 uint8_t flags,
				 uint32_t file_index,
				 uint64_t fid_persistent,
				 uint64_t fid_volatile,
				 const char *mask,
				 uint32_t outbuf_len,
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
	ev = tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_query_directory_send(frame, ev, conn, timeout_msec,
					   session, tcon,
					   level, flags,
					   file_index, fid_persistent,
					   fid_volatile, mask, outbuf_len);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_query_directory_recv(req, mem_ctx,
					      data, data_length);
 fail:
	TALLOC_FREE(frame);
	return status;
}
