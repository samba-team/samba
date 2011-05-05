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
#include "client.h"
#include "async_smb.h"
#include "smb2cli_base.h"
#include "smb2cli.h"
#include "libsmb/proto.h"
#include "lib/util/tevent_ntstatus.h"

struct smb2cli_read_state {
	uint8_t fixed[48];
	uint8_t *inbuf;
	uint8_t *data;
	uint32_t data_length;
};

static void smb2cli_read_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_read_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli,
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

	subreq = smb2cli_req_send(state, ev, cli, SMB2_OP_READ, 0,
				  state->fixed, sizeof(state->fixed),
				  NULL, 0);
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
	struct iovec *iov;
	uint8_t data_offset;

	status = smb2cli_req_recv(subreq, talloc_tos(), &iov, 17);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	data_offset = CVAL(iov[1].iov_base, 2);
	state->data_length = IVAL(iov[1].iov_base, 4);

	if ((data_offset != SMB2_HDR_BODY + 16) ||
	    (state->data_length > iov[2].iov_len)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
	state->inbuf = smb2cli_req_inbuf(subreq);
	state->data = (uint8_t *)iov[2].iov_base;
	tevent_req_done(req);
}

NTSTATUS smb2cli_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   uint8_t **data, uint32_t *data_length)
{
	struct smb2cli_read_state *state =
		tevent_req_data(req,
		struct smb2cli_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	talloc_steal(mem_ctx, state->inbuf);
	*data_length = state->data_length;
	*data = state->data;
	return NT_STATUS_OK;
}

NTSTATUS smb2cli_read(struct cli_state *cli,
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
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = event_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_read_send(frame, ev, cli, length, offset,
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
