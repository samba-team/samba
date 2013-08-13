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

struct smb2cli_close_state {
	uint8_t fixed[24];
};

static void smb2cli_close_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_close_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      struct smbXcli_session *session,
				      struct smbXcli_tcon *tcon,
				      uint16_t flags,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_close_state *state;
	uint8_t *fixed;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_close_state);
	if (req == NULL) {
		return NULL;
	}
	fixed = state->fixed;
	SSVAL(fixed, 0, 24);
	SSVAL(fixed, 2, flags);
	SBVAL(fixed, 8, fid_persistent);
	SBVAL(fixed, 16, fid_volatile);

	subreq = smb2cli_req_send(state, ev, conn, SMB2_OP_CLOSE,
				  0, 0, /* flags */
				  timeout_msec,
				  tcon,
				  session,
				  state->fixed, sizeof(state->fixed),
				  NULL, 0, /* dyn* */
				  0); /* max_dyn_len */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_close_done, req);
	return req;
}

static void smb2cli_close_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	NTSTATUS status;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x3C
	}
	};

	status = smb2cli_req_recv(subreq, NULL, NULL,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS smb2cli_close_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb2cli_close(struct smbXcli_conn *conn,
		       uint32_t timeout_msec,
		       struct smbXcli_session *session,
		       struct smbXcli_tcon *tcon,
		       uint16_t flags,
		       uint64_t fid_persistent,
		       uint64_t fid_volatile)
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
	req = smb2cli_close_send(frame, ev, conn, timeout_msec,
				 session, tcon, flags,
				 fid_persistent, fid_volatile);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_close_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}
