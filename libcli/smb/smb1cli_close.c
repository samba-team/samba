/*
   Unix SMB/CIFS implementation.

   Copyright (C) Gregor Beck 2013
   Copyright (C) Stefan Metzmacher 2013

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

struct smb1cli_close_state {
	uint16_t vwv[3];
};

static void smb1cli_close_done(struct tevent_req *subreq);

/**
 * Send an asynchronous SMB_COM_CLOSE request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee442151.aspx">MS-CIFS 2.2.4.5.1</a>
 * @see smb1cli_close_recv(), smb1cli_close()
 *
 * @param[in] mem_ctx  The memory context for the result.
 * @param[in] ev The event context to work on.
 * @param[in] conn The smb connection.
 * @param[in] timeout_msec If positiv a timeout for the request.
 * @param[in] pid The process identifier.
 * @param[in] tcon The smb tree connect.
 * @param[in] session The smb session.
 * @param[in] fnum The file id of the file to be closed.
 * @param[in] last_modified If not 0 or 0xFFFFFFFF request to set modification time to this number of seconds since January 1, 1970.
 *
 * @return a tevent_req or NULL.
 */
struct tevent_req *smb1cli_close_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      uint32_t pid,
				      struct smbXcli_tcon *tcon,
				      struct smbXcli_session *session,
				      uint16_t fnum,
				      uint32_t last_modified)
{
	struct tevent_req *req, *subreq;
	struct smb1cli_close_state *state;

	req = tevent_req_create(mem_ctx, &state, struct smb1cli_close_state);
	if (req == NULL) {
		return NULL;
	}

	SSVAL(state->vwv+0, 0, fnum);
	SIVALS(state->vwv+1, 0, last_modified);

	subreq = smb1cli_req_send(state, ev, conn, SMBclose,
				  0, 0, /* *_flags */
				  0, 0, /* *_flags2 */
				  timeout_msec, pid, tcon, session,
				  ARRAY_SIZE(state->vwv), state->vwv,
				  0, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb1cli_close_done, req);
	return req;
}

static void smb1cli_close_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb1cli_close_state *state = tevent_req_data(
		req, struct smb1cli_close_state);
	NTSTATUS status;
	static const struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct = 0x00
	},
	};

	status = smb1cli_req_recv(subreq, state,
				  NULL, /* recv_iov */
				  NULL, /* phdr */
				  NULL, /* wct */
				  NULL, /* vwv */
				  NULL, /* pvwv_offset */
				  NULL, /* num_bytes */
				  NULL, /* bytes */
				  NULL, /* pbytes_offset */
				  NULL, /* inbuf */
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

/**
 * Receive the response to an asynchronous SMB_COM_CLOSE request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee441667.aspx">MS-CIFS 2.2.4.5.2</a>
 *
 * @param req A tevent_req created with smb1cli_close_send()
 *
 * @return NT_STATUS_OK on success
 */
NTSTATUS smb1cli_close_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/**
 * Send an synchronous SMB_COM_CLOSE request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee441493.aspx">MS-CIFS 2.2.4.5</a>
 * @see smb1cli_close_send(), smb1cli_close_recv()
 *
 * @param[in] conn The smb connection.
 * @param[in] timeout_msec If positiv a timeout for the request.
 * @param[in] pid The process identifier.
 * @param[in] tcon The smb tree connect.
 * @param[in] session The smb session.
 * @param[in] fnum The file id of the file to be closed.
 * @param[in] last_modified If not 0 or 0xFFFFFFFF request to set modification time to this number of seconds since J
 *
 * @return NT_STATUS_OK on success.
 */
NTSTATUS smb1cli_close(struct smbXcli_conn *conn,
		       uint32_t timeout_msec,
		       uint32_t pid,
		       struct smbXcli_tcon *tcon,
		       struct smbXcli_session *session,
		       uint16_t fnum,
		       uint32_t last_modified)
{
	NTSTATUS status = NT_STATUS_OK;
	struct tevent_req *req;
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	req = smb1cli_close_send(frame, ev, conn,
				 timeout_msec, pid, tcon, session,
				 fnum, last_modified);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto done;
	}

	status = smb1cli_close_recv(req);
done:
	talloc_free(frame);
	return status;
}
