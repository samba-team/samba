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

struct smb2cli_write_state {
	uint8_t fixed[48];
};

static void smb2cli_write_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_write_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli,
				      uint32_t length,
				      uint64_t offset,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile,
				      uint32_t remaining_bytes,
				      uint32_t flags,
				      const uint8_t *data)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_write_state *state;
	uint8_t *fixed;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_write_state);
	if (req == NULL) {
		return NULL;
	}

	fixed = state->fixed;

	SSVAL(fixed, 0, 49);
	SSVAL(fixed, 2, SMB2_HDR_BODY + 48);
	SIVAL(fixed, 4, length);
	SBVAL(fixed, 8, offset);
	SBVAL(fixed, 16, fid_persistent);
	SBVAL(fixed, 24, fid_volatile);
	SIVAL(fixed, 36, remaining_bytes);
	SIVAL(fixed, 44, flags);

	subreq = smb2cli_req_send(state, ev, cli, SMB2_OP_WRITE, 0,
				  state->fixed, sizeof(state->fixed),
				  data, length);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_write_done, req);
	return req;
}

static void smb2cli_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	NTSTATUS status;
	struct iovec *iov;

	status = smb2cli_req_recv(subreq, talloc_tos(), &iov, 17);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS smb2cli_write_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb2cli_write(struct cli_state *cli,
		       uint32_t length,
		       uint64_t offset,
		       uint64_t fid_persistent,
		       uint64_t fid_volatile,
		       uint32_t remaining_bytes,
		       uint32_t flags,
		       const uint8_t *data)
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
	req = smb2cli_write_send(frame, ev, cli, length, offset,
				 fid_persistent, fid_volatile,
				 remaining_bytes, flags, data);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_write_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}
