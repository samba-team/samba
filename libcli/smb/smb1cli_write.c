/*
   Unix SMB/CIFS implementation.

   Copyright (C) Gregor Beck 2013

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

struct smb1cli_writex_state {
	uint32_t size;
	uint16_t vwv[14];
	uint32_t written;
	uint16_t available;
	uint8_t pad;
	struct iovec iov[2];
};

static void smb1cli_writex_done(struct tevent_req *subreq);

/**
 * Send an asynchrounus SMB_COM_WRITE_ANDX request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee441954.aspx">MS-CIFS 2.2.4.43.1</a>
 * @see smb1cli_writex_recv(), smb1cli_writex()
 *
 * @param[in] mem_ctx The memory context for the result.
 * @param[in] ev The event context to work on.
 * @param[in] conn The smb connection.
 * @param[in] timeout_msec If positiv a timeout for the request.
 * @param[in] pid The process identifier
 * @param[in] tcon The smb tree connect.
 * @param[in] session The smb session.
 * @param[in] fnum The file id of the file the data should be written to.
 * @param[in] mode A bitfield containing the write mode.
 * @param[in] buf The data to be written to the file.
 * @param[in] offset The offset in bytes from the begin of file where to write.
 * @param[in] size The number of bytes to write.
 *
 * @return a tevent_req or NULL
 */
struct tevent_req *smb1cli_writex_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct smbXcli_conn *conn,
				       uint32_t timeout_msec,
				       uint32_t pid,
				       struct smbXcli_tcon *tcon,
				       struct smbXcli_session *session,
				       uint16_t fnum,
				       uint16_t mode,
				       const uint8_t *buf,
				       uint64_t offset,
				       uint32_t size)
{
	struct tevent_req *req, *subreq;
	struct smb1cli_writex_state *state;
	bool bigoffset = ((smb1cli_conn_capabilities(conn) & CAP_LARGE_FILES) != 0);
	uint8_t wct = bigoffset ? 14 : 12;
	uint16_t *vwv;
	uint16_t data_offset =
		smb1cli_req_wct_ofs(NULL, 0) /* reqs_before */
		+ 1			     /* the wct field */
		+ wct * 2		     /* vwv */
		+ 2			     /* num_bytes field */
		+ 1;			     /* pad */
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct smb1cli_writex_state);
	if (req == NULL) {
		return NULL;
	}

	state->size = size;

	vwv = state->vwv;

	SCVAL(vwv+0, 0, 0xFF);
	SCVAL(vwv+0, 1, 0);
	SSVAL(vwv+1, 0, 0);
	SSVAL(vwv+2, 0, fnum);
	SIVAL(vwv+3, 0, offset);
	SIVAL(vwv+5, 0, 0);
	SSVAL(vwv+7, 0, mode);
	SSVAL(vwv+8, 0, 0);
	SSVAL(vwv+9, 0, (state->size>>16));
	SSVAL(vwv+10, 0, state->size);
	SSVAL(vwv+11, 0, data_offset);

	if (bigoffset) {
		SIVAL(vwv+12, 0, (((uint64_t)offset)>>32) & 0xffffffff);
	}

	state->pad = 0;
	state->iov[0].iov_base = (void *)&state->pad;
	state->iov[0].iov_len = 1;
	state->iov[1].iov_base = discard_const_p(void, buf);
	state->iov[1].iov_len = state->size;

	subreq = smb1cli_req_create(state, ev, conn, SMBwriteX,
				    0, 0, /* *_flags */
				    0, 0, /* *_flags2 */
				    timeout_msec, pid, tcon, session,
				    wct, vwv,
				    ARRAY_SIZE(state->iov), state->iov);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb1cli_writex_done, req);

	status = smb1cli_req_chain_submit(&subreq, 1);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void smb1cli_writex_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb1cli_writex_state *state = tevent_req_data(
		req, struct smb1cli_writex_state);
	struct iovec *recv_iov = NULL;
	uint8_t wct;
	uint16_t *vwv;
	NTSTATUS status;
	static const struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct = 0x06
	},
	};

	status = smb1cli_req_recv(subreq, state,
				  &recv_iov,
				  NULL, /* phdr */
				  &wct,
				  &vwv,
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

	state->written = SVAL(vwv+2, 0);
	if (state->size > UINT16_MAX) {
		/*
		 * It is important that we only set the
		 * high bits only if we asked for a large write.
		 *
		 * OS/2 print shares get this wrong and may send
		 * invalid values.
		 *
		 * See bug #5326.
		 */
		state->written |= SVAL(vwv+4, 0)<<16;
	}
	state->available = SVAL(vwv+3, 0);

	tevent_req_done(req);
}

/**
 * Receive the response to an asynchronous SMB_COM_WRITE_ANDX request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee441673.aspx">MS-CIFS:2.2.4.43.2</a>
 *
 *
 * @param[in] req req A tevent request created with smb1cli_writex_send()
 * @param[out] pwritten The number of bytes written to the file.
 * @param[out] pavailable Valid if writing to a named pipe or IO device.
 *
 * @return NT_STATUS_OK on succsess.
 */
NTSTATUS smb1cli_writex_recv(struct tevent_req *req, uint32_t *pwritten, uint16_t *pavailable)
{
	struct smb1cli_writex_state *state = tevent_req_data(
		req, struct smb1cli_writex_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (pwritten != NULL) {
		*pwritten = state->written;
	}
	if (pavailable != NULL) {
		*pavailable = state->available;
	}
	return NT_STATUS_OK;
}

/**
 * Send an synchrounus SMB_COM_WRITE_ANDX request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee441848.aspx">MS-CIFS 2.2.4.43</a>
 * @see smb1cli_writex_send(), smb1cli_writex_recv()
 *
 * @param[in] conn The smb connection.
 * @param[in] timeout_msec If positiv a timeout for the request.
 * @param[in] pid The process identifier
 * @param[in] tcon The smb tree connect.
 * @param[in] session The smb session.
 * @param[in] fnum The file id of the file the data should be written to.
 * @param[in] mode A bitfield containing the write mode.
 * @param[in] buf The data to be written to the file.
 * @param[in] offset The offset in bytes from the begin of file where to write.
 * @param[in] size The number of bytes to write.
 * @param[out] pwritten The number of bytes written to the file.
 * @param[out] pavailable Valid if writing to a named pipe or IO device.
 *
 * @return NT_STATUS_OK on succsess.
 */
NTSTATUS smb1cli_writex(struct smbXcli_conn *conn,
			uint32_t timeout_msec,
			uint32_t pid,
			struct smbXcli_tcon *tcon,
			struct smbXcli_session *session,
			uint16_t fnum,
			uint16_t mode,
			const uint8_t *buf,
			uint64_t offset,
			uint32_t size,
			uint32_t *pwritten,
			uint16_t *pavailable)
{
	TALLOC_CTX *frame = NULL;
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	frame = talloc_stackframe();

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

	req = smb1cli_writex_send(frame, ev, conn,
				  timeout_msec,
				  pid, tcon, session,
				  fnum, mode, buf, offset, size);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto done;
	}

	status = smb1cli_writex_recv(req, pwritten, pavailable);
done:
	TALLOC_FREE(frame);
	return status;
}
