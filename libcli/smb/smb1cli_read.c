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

struct smb1cli_readx_state {
	uint32_t size;
	uint16_t vwv[12];
	NTSTATUS status;
	uint32_t received;
	uint8_t *buf;
};

static void smb1cli_readx_done(struct tevent_req *subreq);

/**
 * Send an asynchrounus SMB_COM_READ_ANDX request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee441839.aspx">MS-CIFS 2.2.4.42.1</a>,
 * <a href="http://msdn.microsoft.com/en-us/library/ff470250.aspx">MS-SMB 2.2.4.2.1</a>
 * @see smb1cli_readx_recv()
 * @todo fix API (min/max size, timeout)
 *
 * @param[in] mem_ctx The memory context for the result.
 * @param[in] ev The event context to work on.
 * @param[in] conn The smb connection.
 * @param[in] timeout_msec If positiv a timeout for the request.
 * @param[in] pid The process identifier
 * @param[in] tcon The smb tree connect.
 * @param[in] session The smb session.
 * @param[in] fnum The file id of the file the data should be read from.
 * @param[in] offset The offset in bytes from the begin of file where to start reading.
 * @param[in] size The number of bytes to read.
 *
 * @return a tevent_req or NULL
 */
struct tevent_req *smb1cli_readx_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      uint32_t pid,
				      struct smbXcli_tcon *tcon,
				      struct smbXcli_session *session,
				      uint16_t fnum,
				      uint64_t offset,
				      uint32_t size)
{
	NTSTATUS status;
	struct tevent_req *req, *subreq;
	struct smb1cli_readx_state *state;
	uint8_t wct = 10;

	req = tevent_req_create(mem_ctx, &state, struct smb1cli_readx_state);
	if (req == NULL) {
		return NULL;
	}
	state->size = size;

	SCVAL(state->vwv + 0, 0, 0xFF);
	SCVAL(state->vwv + 0, 1, 0);
	SSVAL(state->vwv + 1, 0, 0);
	SSVAL(state->vwv + 2, 0, fnum);
	SIVAL(state->vwv + 3, 0, offset);
	SSVAL(state->vwv + 5, 0, size);
	SSVAL(state->vwv + 6, 0, size);
	SSVAL(state->vwv + 7, 0, (size >> 16));
	SSVAL(state->vwv + 8, 0, 0);
	SSVAL(state->vwv + 9, 0, 0);

	if (smb1cli_conn_capabilities(conn) & CAP_LARGE_FILES) {
		SIVAL(state->vwv + 10, 0,
		      (((uint64_t)offset)>>32) & 0xffffffff);
		wct = 12;
	} else {
		if ((((uint64_t)offset) & 0xffffffff00000000LL) != 0) {
			DEBUG(10, ("smb1cli_readx_send got large offset where "
				   "the server does not support it\n"));
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
			return tevent_req_post(req, ev);
		}
	}

	subreq = smb1cli_req_create(state, ev, conn, SMBreadX,
				    0, 0, /* *_flags */
				    0, 0, /* *_flags2 */
				    timeout_msec, pid, tcon, session,
				    wct, state->vwv,
				    0, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb1cli_readx_done, req);

	status = smb1cli_req_chain_submit(&subreq, 1);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void smb1cli_readx_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb1cli_readx_state *state = tevent_req_data(
		req, struct smb1cli_readx_state);
	struct iovec *recv_iov = NULL;
	uint8_t wct;
	uint16_t *vwv;
	uint32_t num_bytes;
	uint8_t *bytes;
	uint16_t data_offset;
	uint32_t bytes_offset;
	static const struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct = 0x0C
	},
	};

	state->status = smb1cli_req_recv(subreq, state,
					 &recv_iov,
					 NULL, /* phdr */
					 &wct,
					 &vwv,
					 NULL, /* pvwv_offset */
					 &num_bytes,
					 &bytes,
					 &bytes_offset,
					 NULL, /* inbuf */
					 expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, state->status)) {
		return;
	}

	/* size is the number of bytes the server returned.
	 * Might be zero. */
	state->received = SVAL(vwv + 5, 0);
	state->received |= (((unsigned int)SVAL(vwv + 7, 0)) << 16);

	if (state->received > state->size) {
		DEBUG(5,("server returned more than we wanted!\n"));
		tevent_req_nterror(req, NT_STATUS_UNEXPECTED_IO_ERROR);
		return;
	}

	/*
	 * bcc field must be valid for small reads, for large reads the 16-bit
	 * bcc field can't be correct.
	 */
	if ((state->received < 0xffff) && (state->received > num_bytes)) {
		DEBUG(5, ("server announced more bytes than sent\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	data_offset = SVAL(vwv+6, 0);
	if (data_offset < bytes_offset) {
		DEBUG(5, ("server returned invalid read&x data offset\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
	if (smb_buffer_oob(num_bytes, data_offset - bytes_offset, state->received)) {
		DEBUG(5, ("server returned invalid read&x data offset\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	state->buf = bytes + (data_offset - bytes_offset);

	tevent_req_done(req);
}

/**
 * Receive the response to an asynchronous SMB_COM_READ_ANDX request.
 * <a href="http://msdn.microsoft.com/en-us/library/ee441872.aspx">MS-CIFS 2.2.4.42.2</a>,
 * <a href="http://msdn.microsoft.com/en-us/library/ff470017.aspx">MS-SMB 2.2.4.2.2</a>
 *
 * @warning rcvbuf is talloced from the request, so better make sure that you
 * copy it away before  you talloc_free(req). rcvbuf is NOT a talloc_ctx of its
 * own, so do not talloc_move it!
 *
 * @param[in] req A tevent request created with smb1cli_readx_send()
 * @param[out] received The number of bytes received.
 * @param[out] rcvbuf Pointer to the bytes received.
 *
 * @return NT_STATUS_OK on succsess.
 */
NTSTATUS smb1cli_readx_recv(struct tevent_req *req,
			    uint32_t *received,
			    uint8_t **rcvbuf)
{
	struct smb1cli_readx_state *state = tevent_req_data(
		req, struct smb1cli_readx_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*received = state->received;
	*rcvbuf = state->buf;
	return NT_STATUS_OK;
}
