/*
   Unix SMB/CIFS implementation.
   client file read/write routines
   Copyright (C) Andrew Tridgell 1994-1998

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
#include "libsmb/libsmb.h"
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "trans2.h"
#include "../libcli/smb/smbXcli_base.h"

/****************************************************************************
  Calculate the recommended read buffer size
****************************************************************************/
static size_t cli_read_max_bufsize(struct cli_state *cli)
{
	uint8_t wct = 12;
	uint32_t min_space;
	uint32_t data_offset;
	uint32_t useable_space = 0;

	data_offset = HDR_VWV;
	data_offset += wct * sizeof(uint16_t);
	data_offset += sizeof(uint16_t); /* byte count */
	data_offset += 1; /* pad */

	min_space = cli_state_available_size(cli, data_offset);

	if (cli->server_posix_capabilities & CIFS_UNIX_LARGE_READ_CAP) {
		useable_space = 0xFFFFFF - data_offset;

		if (smb1cli_conn_signing_is_active(cli->conn)) {
			return min_space;
		}

		if (smb1cli_conn_encryption_on(cli->conn)) {
			return min_space;
		}

		return useable_space;
	} else if (smb1cli_conn_capabilities(cli->conn) & CAP_LARGE_READX) {
		/*
		 * Note: CAP_LARGE_READX also works with signing
		 */
		useable_space = 0x1FFFF - data_offset;

		useable_space = MIN(useable_space, UINT16_MAX);

		return useable_space;
	}

	return min_space;
}

/****************************************************************************
  Calculate the recommended write buffer size
****************************************************************************/
static size_t cli_write_max_bufsize(struct cli_state *cli,
				    uint16_t write_mode,
				    uint8_t wct)
{
	uint32_t min_space;
	uint32_t data_offset;
	uint32_t useable_space = 0;

	data_offset = HDR_VWV;
	data_offset += wct * sizeof(uint16_t);
	data_offset += sizeof(uint16_t); /* byte count */
	data_offset += 1; /* pad */

	min_space = cli_state_available_size(cli, data_offset);

	if (cli->server_posix_capabilities & CIFS_UNIX_LARGE_WRITE_CAP) {
		useable_space = 0xFFFFFF - data_offset;
	} else if (smb1cli_conn_capabilities(cli->conn) & CAP_LARGE_WRITEX) {
		useable_space = 0x1FFFF - data_offset;
	} else {
		return min_space;
	}

	if (write_mode != 0) {
		return min_space;
	}

	if (smb1cli_conn_signing_is_active(cli->conn)) {
		return min_space;
	}

	if (smb1cli_conn_encryption_on(cli->conn)) {
		return min_space;
	}

	if (strequal(cli->dev, "LPT1:")) {
		return min_space;
	}

	return useable_space;
}

struct cli_read_andx_state {
	size_t size;
	uint16_t vwv[12];
	NTSTATUS status;
	size_t received;
	uint8_t *buf;
};

static void cli_read_andx_done(struct tevent_req *subreq);

struct tevent_req *cli_read_andx_create(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli, uint16_t fnum,
					off_t offset, size_t size,
					struct tevent_req **psmbreq)
{
	struct tevent_req *req, *subreq;
	struct cli_read_andx_state *state;
	uint8_t wct = 10;

	req = tevent_req_create(mem_ctx, &state, struct cli_read_andx_state);
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

	if (smb1cli_conn_capabilities(cli->conn) & CAP_LARGE_FILES) {
		SIVAL(state->vwv + 10, 0,
		      (((uint64_t)offset)>>32) & 0xffffffff);
		wct = 12;
	} else {
		if ((((uint64_t)offset) & 0xffffffff00000000LL) != 0) {
			DEBUG(10, ("cli_read_andx_send got large offset where "
				   "the server does not support it\n"));
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
	}

	subreq = cli_smb_req_create(state, ev, cli, SMBreadX, 0, 0, wct,
				    state->vwv, 0, NULL);
	if (subreq == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}
	tevent_req_set_callback(subreq, cli_read_andx_done, req);
	*psmbreq = subreq;
	return req;
}

struct tevent_req *cli_read_andx_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli, uint16_t fnum,
				      off_t offset, size_t size)
{
	struct tevent_req *req, *subreq;
	NTSTATUS status;

	req = cli_read_andx_create(mem_ctx, ev, cli, fnum, offset, size,
				   &subreq);
	if (req == NULL) {
		return NULL;
	}

	status = smb1cli_req_chain_submit(&subreq, 1);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void cli_read_andx_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_read_andx_state *state = tevent_req_data(
		req, struct cli_read_andx_state);
	uint8_t *inbuf;
	uint8_t wct;
	uint16_t *vwv;
	uint32_t num_bytes;
	uint8_t *bytes;

	state->status = cli_smb_recv(subreq, state, &inbuf, 12, &wct, &vwv,
				     &num_bytes, &bytes);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_ERR(state->status)) {
		tevent_req_nterror(req, state->status);
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

	state->buf = discard_const_p(uint8_t, smb_base(inbuf)) + SVAL(vwv+6, 0);

	if (trans_oob(smb_len_tcp(inbuf), SVAL(vwv+6, 0), state->received)
	    || ((state->received != 0) && (state->buf < bytes))) {
		DEBUG(5, ("server returned invalid read&x data offset\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
	tevent_req_done(req);
}

/*
 * Pull the data out of a finished async read_and_x request. rcvbuf is
 * talloced from the request, so better make sure that you copy it away before
 * you talloc_free(req). "rcvbuf" is NOT a talloc_ctx of its own, so do not
 * talloc_move it!
 */

NTSTATUS cli_read_andx_recv(struct tevent_req *req, ssize_t *received,
			    uint8_t **rcvbuf)
{
	struct cli_read_andx_state *state = tevent_req_data(
		req, struct cli_read_andx_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*received = state->received;
	*rcvbuf = state->buf;
	return NT_STATUS_OK;
}

struct cli_pull_chunk;

struct cli_pull_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t fnum;
	off_t start_offset;
	off_t size;

	NTSTATUS (*sink)(char *buf, size_t n, void *priv);
	void *priv;

	size_t chunk_size;
	off_t next_offset;
	off_t remaining;

	/*
	 * How many bytes did we push into "sink"?
	 */
	off_t pushed;

	/*
	 * Outstanding requests
	 *
	 * The maximum is 256:
	 * - which would be a window of 256 MByte
	 *   for SMB2 with multi-credit
	 *   or smb1 unix extensions.
	 */
	uint16_t max_chunks;
	uint16_t num_chunks;
	uint16_t num_waiting;
	struct cli_pull_chunk *chunks;
};

struct cli_pull_chunk {
	struct cli_pull_chunk *prev, *next;
	struct tevent_req *req;/* This is the main request! Not the subreq */
	struct tevent_req *subreq;
	off_t ofs;
	uint8_t *buf;
	size_t total_size;
	size_t tmp_size;
	bool done;
};

static void cli_pull_setup_chunks(struct tevent_req *req);
static void cli_pull_chunk_ship(struct cli_pull_chunk *chunk);
static void cli_pull_chunk_done(struct tevent_req *subreq);

/*
 * Parallel read support.
 *
 * cli_pull sends as many read&x requests as the server would allow via
 * max_mux at a time. When replies flow back in, the data is written into
 * the callback function "sink" in the right order.
 */

struct tevent_req *cli_pull_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct cli_state *cli,
				 uint16_t fnum, off_t start_offset,
				 off_t size, size_t window_size,
				 NTSTATUS (*sink)(char *buf, size_t n,
						  void *priv),
				 void *priv)
{
	struct tevent_req *req;
	struct cli_pull_state *state;
	size_t page_size = 1024;
	uint64_t tmp64;

	req = tevent_req_create(mem_ctx, &state, struct cli_pull_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->ev = ev;
	state->fnum = fnum;
	state->start_offset = start_offset;
	state->size = size;
	state->sink = sink;
	state->priv = priv;
	state->next_offset = start_offset;
	state->remaining = size;

	if (size == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		state->chunk_size = smb2cli_conn_max_read_size(cli->conn);
	} else {
		state->chunk_size = cli_read_max_bufsize(cli);
	}
	if (state->chunk_size > page_size) {
		state->chunk_size &= ~(page_size - 1);
	}

	if (window_size == 0) {
		/*
		 * We use 16 MByte as default window size.
		 */
		window_size = 16 * 1024 * 1024;
	}

	tmp64 = window_size/state->chunk_size;
	if ((window_size % state->chunk_size) > 0) {
		tmp64 += 1;
	}
	tmp64 = MAX(tmp64, 1);
	tmp64 = MIN(tmp64, 256);
	state->max_chunks = tmp64;

	/*
	 * We defer the callback because of the complex
	 * substate/subfunction logic
	 */
	tevent_req_defer_callback(req, ev);

	cli_pull_setup_chunks(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void cli_pull_setup_chunks(struct tevent_req *req)
{
	struct cli_pull_state *state =
		tevent_req_data(req,
		struct cli_pull_state);
	struct cli_pull_chunk *chunk, *next = NULL;
	size_t i;

	for (chunk = state->chunks; chunk; chunk = next) {
		/*
		 * Note that chunk might be removed from this call.
		 */
		next = chunk->next;
		cli_pull_chunk_ship(chunk);
		if (!tevent_req_is_in_progress(req)) {
			return;
		}
	}

	for (i = state->num_chunks; i < state->max_chunks; i++) {

		if (state->num_waiting > 0) {
			return;
		}

		if (state->remaining == 0) {
			break;
		}

		chunk = talloc_zero(state, struct cli_pull_chunk);
		if (tevent_req_nomem(chunk, req)) {
			return;
		}
		chunk->req = req;
		chunk->ofs = state->next_offset;
		chunk->total_size = MIN(state->remaining, state->chunk_size);
		state->next_offset += chunk->total_size;
		state->remaining -= chunk->total_size;

		DLIST_ADD_END(state->chunks, chunk);
		state->num_chunks++;
		state->num_waiting++;

		cli_pull_chunk_ship(chunk);
		if (!tevent_req_is_in_progress(req)) {
			return;
		}
	}

	if (state->remaining > 0) {
		return;
	}

	if (state->num_chunks > 0) {
		return;
	}

	tevent_req_done(req);
}

static void cli_pull_chunk_ship(struct cli_pull_chunk *chunk)
{
	struct tevent_req *req = chunk->req;
	struct cli_pull_state *state =
		tevent_req_data(req,
		struct cli_pull_state);
	bool ok;
	off_t ofs;
	size_t size;

	if (chunk->done) {
		NTSTATUS status;

		if (chunk != state->chunks) {
			/*
			 * this chunk is not the
			 * first one in the list.
			 *
			 * which means we should not
			 * push it into the sink yet.
			 */
			return;
		}

		if (chunk->tmp_size == 0) {
			/*
			 * we got a short read, we're done
			 */
			tevent_req_done(req);
			return;
		}

		status = state->sink((char *)chunk->buf,
				     chunk->tmp_size,
				     state->priv);
		if (tevent_req_nterror(req, status)) {
			return;
		}
		state->pushed += chunk->tmp_size;

		if (chunk->tmp_size < chunk->total_size) {
			/*
			 * we got a short read, we're done
			 */
			tevent_req_done(req);
			return;
		}

		DLIST_REMOVE(state->chunks, chunk);
		SMB_ASSERT(state->num_chunks > 0);
		state->num_chunks--;
		TALLOC_FREE(chunk);

		return;
	}

	if (chunk->subreq != NULL) {
		return;
	}

	SMB_ASSERT(state->num_waiting > 0);

	ofs = chunk->ofs + chunk->tmp_size;
	size = chunk->total_size - chunk->tmp_size;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		uint32_t max_size;

		ok = smb2cli_conn_req_possible(state->cli->conn, &max_size);
		if (!ok) {
			return;
		}

		/*
		 * downgrade depending on the available credits
		 */
		size = MIN(max_size, size);

		chunk->subreq = cli_smb2_read_send(chunk,
						   state->ev,
						   state->cli,
						   state->fnum,
						   ofs,
						   size);
		if (tevent_req_nomem(chunk->subreq, req)) {
			return;
		}
	} else {
		ok = smb1cli_conn_req_possible(state->cli->conn);
		if (!ok) {
			return;
		}

		chunk->subreq = cli_read_andx_send(chunk,
						   state->ev,
						   state->cli,
						   state->fnum,
						   ofs,
						   size);
		if (tevent_req_nomem(chunk->subreq, req)) {
			return;
		}
	}
	tevent_req_set_callback(chunk->subreq,
				cli_pull_chunk_done,
				chunk);

	state->num_waiting--;
	return;
}

static void cli_pull_chunk_done(struct tevent_req *subreq)
{
	struct cli_pull_chunk *chunk =
		tevent_req_callback_data(subreq,
		struct cli_pull_chunk);
	struct tevent_req *req = chunk->req;
	struct cli_pull_state *state =
		tevent_req_data(req,
		struct cli_pull_state);
	NTSTATUS status;
	size_t expected = chunk->total_size - chunk->tmp_size;
	ssize_t received = 0;
	uint8_t *buf = NULL;

	chunk->subreq = NULL;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		status = cli_smb2_read_recv(subreq, &received, &buf);
	} else {
		status = cli_read_andx_recv(subreq, &received, &buf);
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)) {
		received = 0;
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (received > expected) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (received == 0) {
		/*
		 * We got EOF we're done
		 */
		chunk->done = true;
		cli_pull_setup_chunks(req);
		return;
	}

	if (received == chunk->total_size) {
		/*
		 * We got it in the first run.
		 *
		 * We don't call TALLOC_FREE(subreq)
		 * here and keep the returned buffer.
		 */
		chunk->buf = buf;
	} else if (chunk->buf == NULL) {
		chunk->buf = talloc_array(chunk, uint8_t, chunk->total_size);
		if (tevent_req_nomem(chunk->buf, req)) {
			return;
		}
	}

	if (received != chunk->total_size) {
		uint8_t *p = chunk->buf + chunk->tmp_size;
		memcpy(p, buf, received);
		TALLOC_FREE(subreq);
	}

	chunk->tmp_size += received;

	if (chunk->tmp_size == chunk->total_size) {
		chunk->done = true;
	} else {
		state->num_waiting++;
	}

	cli_pull_setup_chunks(req);
}

NTSTATUS cli_pull_recv(struct tevent_req *req, off_t *received)
{
	struct cli_pull_state *state = tevent_req_data(
		req, struct cli_pull_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	*received = state->pushed;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS cli_pull(struct cli_state *cli, uint16_t fnum,
		  off_t start_offset, off_t size, size_t window_size,
		  NTSTATUS (*sink)(char *buf, size_t n, void *priv),
		  void *priv, off_t *received)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_pull_send(frame, ev, cli, fnum, start_offset, size,
			    window_size, sink, priv);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = cli_pull_recv(req, received);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_read_state {
	struct cli_state *cli;
	char *buf;
	size_t buflen;
	size_t received;
};

static void cli_read_done(struct tevent_req *subreq);

struct tevent_req *cli_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	char *buf,
	off_t offset,
	size_t size)
{
	struct tevent_req *req, *subreq;
	struct cli_read_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->buf = buf;
	state->buflen = size;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		uint32_t max_size;
		bool ok;

		ok = smb2cli_conn_req_possible(state->cli->conn, &max_size);
		if (!ok) {
			tevent_req_nterror(
				req,
				NT_STATUS_INSUFFICIENT_RESOURCES);
			return tevent_req_post(req, ev);
		}

		/*
		 * downgrade depending on the available credits
		 */
		size = MIN(max_size, size);

		subreq = cli_smb2_read_send(
			state, ev, cli, fnum, offset, size);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
	} else {
		bool ok;
		ok = smb1cli_conn_req_possible(state->cli->conn);
		if (!ok) {
			tevent_req_nterror(
				req,
				NT_STATUS_INSUFFICIENT_RESOURCES);
			return tevent_req_post(req, ev);
		}

		subreq = cli_read_andx_send(
			state, ev, cli, fnum, offset, size);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
	}

	tevent_req_set_callback(subreq, cli_read_done, req);

	return req;
}

static void cli_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_read_state *state = tevent_req_data(
		req, struct cli_read_state);
	NTSTATUS status;
	ssize_t received;
	uint8_t *buf = NULL;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		status = cli_smb2_read_recv(subreq, &received, &buf);
	} else {
		status = cli_read_andx_recv(subreq, &received, &buf);
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)) {
		received = 0;
		status = NT_STATUS_OK;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if ((buf == NULL) || (received < 0) || (received > state->buflen)) {
		state->received = 0;
		tevent_req_nterror(req, NT_STATUS_UNEXPECTED_IO_ERROR);
		return;
	}

	memcpy(state->buf, buf, received);
	state->received = received;
	tevent_req_done(req);
}

NTSTATUS cli_read_recv(struct tevent_req *req, size_t *received)
{
	struct cli_read_state *state = tevent_req_data(
		req, struct cli_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (received != NULL) {
		*received = state->received;
	}
	return NT_STATUS_OK;
}

/*
 * Helper function for cli_pull(). This takes a chunk of data (buf) read from
 * a remote file and copies it into the return buffer (priv).
 */
NTSTATUS cli_read_sink(char *buf, size_t n, void *priv)
{
	char **pbuf = (char **)priv;
	memcpy(*pbuf, buf, n);
	*pbuf += n;
	return NT_STATUS_OK;
}

NTSTATUS cli_read(struct cli_state *cli, uint16_t fnum,
		 char *buf, off_t offset, size_t size,
		 size_t *nread)
{
	NTSTATUS status;
	off_t ret = 0;

	status = cli_pull(cli, fnum, offset, size, size,
			  cli_read_sink, &buf, &ret);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (nread) {
		*nread = ret;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
  write to a file using a SMBwrite and not bypassing 0 byte writes
****************************************************************************/

NTSTATUS cli_smbwrite(struct cli_state *cli, uint16_t fnum, char *buf,
		      off_t offset, size_t size1, size_t *ptotal)
{
	uint8_t *bytes;
	ssize_t total = 0;

	/*
	 * 3 bytes prefix
	 */

	bytes = talloc_array(talloc_tos(), uint8_t, 3);
	if (bytes == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	bytes[0] = 1;

	do {
		uint32_t usable_space = cli_state_available_size(cli, 48);
		size_t size = MIN(size1, usable_space);
		struct tevent_req *req;
		uint16_t vwv[5];
		uint16_t *ret_vwv;
		NTSTATUS status;

		SSVAL(vwv+0, 0, fnum);
		SSVAL(vwv+1, 0, size);
		SIVAL(vwv+2, 0, offset);
		SSVAL(vwv+4, 0, 0);

		bytes = talloc_realloc(talloc_tos(), bytes, uint8_t,
					     size+3);
		if (bytes == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		SSVAL(bytes, 1, size);
		memcpy(bytes + 3, buf + total, size);

		status = cli_smb(talloc_tos(), cli, SMBwrite, 0, 5, vwv,
				 size+3, bytes, &req, 1, NULL, &ret_vwv,
				 NULL, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(bytes);
			return status;
		}

		size = SVAL(ret_vwv+0, 0);
		TALLOC_FREE(req);
		if (size == 0) {
			break;
		}
		size1 -= size;
		total += size;
		offset += size;

	} while (size1);

	TALLOC_FREE(bytes);

	if (ptotal != NULL) {
		*ptotal = total;
	}
	return NT_STATUS_OK;
}

/*
 * Send a write&x request
 */

struct cli_write_andx_state {
	size_t size;
	uint16_t vwv[14];
	size_t written;
	uint8_t pad;
	struct iovec iov[2];
};

static void cli_write_andx_done(struct tevent_req *subreq);

struct tevent_req *cli_write_andx_create(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct cli_state *cli, uint16_t fnum,
					 uint16_t mode, const uint8_t *buf,
					 off_t offset, size_t size,
					 struct tevent_req **reqs_before,
					 int num_reqs_before,
					 struct tevent_req **psmbreq)
{
	struct tevent_req *req, *subreq;
	struct cli_write_andx_state *state;
	bool bigoffset = ((smb1cli_conn_capabilities(cli->conn) & CAP_LARGE_FILES) != 0);
	uint8_t wct = bigoffset ? 14 : 12;
	size_t max_write = cli_write_max_bufsize(cli, mode, wct);
	uint16_t *vwv;

	req = tevent_req_create(mem_ctx, &state, struct cli_write_andx_state);
	if (req == NULL) {
		return NULL;
	}

	state->size = MIN(size, max_write);

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

	SSVAL(vwv+11, 0,
	      smb1cli_req_wct_ofs(reqs_before, num_reqs_before)
	      + 1		/* the wct field */
	      + wct * 2		/* vwv */
	      + 2		/* num_bytes field */
	      + 1		/* pad */);

	if (bigoffset) {
		SIVAL(vwv+12, 0, (((uint64_t)offset)>>32) & 0xffffffff);
	}

	state->pad = 0;
	state->iov[0].iov_base = (void *)&state->pad;
	state->iov[0].iov_len = 1;
	state->iov[1].iov_base = discard_const_p(void, buf);
	state->iov[1].iov_len = state->size;

	subreq = cli_smb_req_create(state, ev, cli, SMBwriteX, 0, 0, wct, vwv,
				    2, state->iov);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_write_andx_done, req);
	*psmbreq = subreq;
	return req;
}

struct tevent_req *cli_write_andx_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct cli_state *cli, uint16_t fnum,
				       uint16_t mode, const uint8_t *buf,
				       off_t offset, size_t size)
{
	struct tevent_req *req, *subreq;
	NTSTATUS status;

	req = cli_write_andx_create(mem_ctx, ev, cli, fnum, mode, buf, offset,
				    size, NULL, 0, &subreq);
	if (req == NULL) {
		return NULL;
	}

	status = smb1cli_req_chain_submit(&subreq, 1);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void cli_write_andx_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_write_andx_state *state = tevent_req_data(
		req, struct cli_write_andx_state);
	uint8_t wct;
	uint16_t *vwv;
	NTSTATUS status;

	status = cli_smb_recv(subreq, state, NULL, 6, &wct, &vwv,
			      NULL, NULL);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_ERR(status)) {
		tevent_req_nterror(req, status);
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
	tevent_req_done(req);
}

NTSTATUS cli_write_andx_recv(struct tevent_req *req, size_t *pwritten)
{
	struct cli_write_andx_state *state = tevent_req_data(
		req, struct cli_write_andx_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (pwritten != 0) {
		*pwritten = state->written;
	}
	return NT_STATUS_OK;
}

struct cli_write_state {
	struct cli_state *cli;
	size_t written;
};

static void cli_write_done(struct tevent_req *subreq);

/*
 * Used to write to a file remotely.
 * This is similar in functionality to cli_push_send(), except this is a more
 * finer-grain API. For example, if the data we want to write exceeds the max
 * write size of the underlying connection, then it's the caller's
 * responsibility to handle this.
 * For writing a small amount of data to file, this is a simpler API to use.
 */
struct tevent_req *cli_write_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct cli_state *cli, uint16_t fnum,
				  uint16_t mode, const uint8_t *buf,
				  off_t offset, size_t size)
{
	struct tevent_req *req = NULL;
	struct cli_write_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_write_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		uint32_t max_size;
		bool ok;

		ok = smb2cli_conn_req_possible(state->cli->conn, &max_size);
		if (!ok) {
			tevent_req_nterror(
				req,
				NT_STATUS_INSUFFICIENT_RESOURCES);
			return tevent_req_post(req, ev);
		}

		/*
		 * downgrade depending on the available credits
		 */
		size = MIN(max_size, size);

		subreq = cli_smb2_write_send(state,
					     ev,
					     cli,
					     fnum,
					     mode,
					     buf,
					     offset,
					     size);
	} else {
		bool ok;

		ok = smb1cli_conn_req_possible(state->cli->conn);
		if (!ok) {
			tevent_req_nterror(
				req,
				NT_STATUS_INSUFFICIENT_RESOURCES);
			return tevent_req_post(req, ev);
		}

		subreq = cli_write_andx_send(state,
					     ev,
					     cli,
					     fnum,
					     mode,
					     buf,
					     offset,
					     size);
	}
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_write_done, req);

	return req;
}

static void cli_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct cli_write_state *state =
		tevent_req_data(req,
		struct cli_write_state);
	NTSTATUS status;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		status = cli_smb2_write_recv(subreq, &state->written);
	} else {
		status = cli_write_andx_recv(subreq, &state->written);
	}
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_write_recv(struct tevent_req *req, size_t *pwritten)
{
	struct cli_write_state *state =
		tevent_req_data(req,
		struct cli_write_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	if (pwritten != NULL) {
		*pwritten = state->written;
	}
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct cli_smb1_writeall_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t fnum;
	uint16_t mode;
	const uint8_t *buf;
	off_t offset;
	size_t size;
	size_t written;
};

static void cli_smb1_writeall_written(struct tevent_req *req);

static struct tevent_req *cli_smb1_writeall_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct cli_state *cli,
						 uint16_t fnum,
						 uint16_t mode,
						 const uint8_t *buf,
						 off_t offset, size_t size)
{
	struct tevent_req *req, *subreq;
	struct cli_smb1_writeall_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb1_writeall_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->fnum = fnum;
	state->mode = mode;
	state->buf = buf;
	state->offset = offset;
	state->size = size;
	state->written = 0;

	subreq = cli_write_andx_send(state, state->ev, state->cli, state->fnum,
				     state->mode, state->buf, state->offset,
				     state->size);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb1_writeall_written, req);
	return req;
}

static void cli_smb1_writeall_written(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb1_writeall_state *state = tevent_req_data(
		req, struct cli_smb1_writeall_state);
	NTSTATUS status;
	size_t written = 0, to_write;

	status = cli_write_andx_recv(subreq, &written);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->written += written;

	if (state->written > state->size) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	to_write = state->size - state->written;

	if (to_write == 0) {
		tevent_req_done(req);
		return;
	}

	subreq = cli_write_andx_send(state, state->ev, state->cli, state->fnum,
				     state->mode,
				     state->buf + state->written,
				     state->offset + state->written, to_write);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb1_writeall_written, req);
}

static NTSTATUS cli_smb1_writeall_recv(struct tevent_req *req,
				       size_t *pwritten)
{
	struct cli_smb1_writeall_state *state = tevent_req_data(
		req, struct cli_smb1_writeall_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (pwritten != NULL) {
		*pwritten = state->written;
	}
	return NT_STATUS_OK;
}

struct cli_writeall_state {
	struct cli_state *cli;
	size_t written;
};

static void cli_writeall_done(struct tevent_req *subreq);

struct tevent_req *cli_writeall_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint16_t mode,
	const uint8_t *buf,
	off_t offset,
	size_t size)
{
	struct tevent_req *req, *subreq;
	struct cli_writeall_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_writeall_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		subreq = cli_smb2_writeall_send(
			state,
			ev,
			cli,
			fnum,
			mode,
			buf,
			offset,
			size);
	} else {
		subreq = cli_smb1_writeall_send(
			state,
			ev,
			cli,
			fnum,
			mode,
			buf,
			offset,
			size);
	}

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_writeall_done, req);

	return req;
}

static void cli_writeall_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_writeall_state *state = tevent_req_data(
		req, struct cli_writeall_state);
	NTSTATUS status;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		status = cli_smb2_writeall_recv(subreq, &state->written);
	} else {
		status = cli_smb1_writeall_recv(subreq, &state->written);
	}
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_writeall_recv(struct tevent_req *req, size_t *pwritten)
{
	struct cli_writeall_state *state = tevent_req_data(
		req, struct cli_writeall_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (pwritten != NULL) {
		*pwritten = state->written;
	}
	return NT_STATUS_OK;
}


NTSTATUS cli_writeall(struct cli_state *cli, uint16_t fnum, uint16_t mode,
		      const uint8_t *buf, off_t offset, size_t size,
		      size_t *pwritten)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
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
	req = cli_writeall_send(frame, ev, cli, fnum, mode, buf, offset, size);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_writeall_recv(req, pwritten);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_push_chunk;

struct cli_push_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t fnum;
	uint16_t mode;
	off_t start_offset;

	size_t (*source)(uint8_t *buf, size_t n, void *priv);
	void *priv;

	bool eof;

	size_t chunk_size;
	off_t next_offset;

	/*
	 * Outstanding requests
	 *
	 * The maximum is 256:
	 * - which would be a window of 256 MByte
	 *   for SMB2 with multi-credit
	 *   or smb1 unix extensions.
	 */
	uint16_t max_chunks;
	uint16_t num_chunks;
	uint16_t num_waiting;
	struct cli_push_chunk *chunks;
};

struct cli_push_chunk {
	struct cli_push_chunk *prev, *next;
	struct tevent_req *req;/* This is the main request! Not the subreq */
	struct tevent_req *subreq;
	off_t ofs;
	uint8_t *buf;
	size_t total_size;
	size_t tmp_size;
	bool done;
};

static void cli_push_setup_chunks(struct tevent_req *req);
static void cli_push_chunk_ship(struct cli_push_chunk *chunk);
static void cli_push_chunk_done(struct tevent_req *subreq);

/*
 * Used to write to a file remotely.
 * This is similar in functionality to cli_write_send(), except this API
 * handles writing a large file by breaking the data into chunks (so we don't
 * exceed the max write size of the underlying connection). To do this, the
 * (*source) callback handles copying the underlying file data into a message
 * buffer, one chunk at a time.
 * This API is recommended when writing a potentially large amount of data,
 * e.g. when copying a file (or doing a 'put').
 */
struct tevent_req *cli_push_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				 struct cli_state *cli,
				 uint16_t fnum, uint16_t mode,
				 off_t start_offset, size_t window_size,
				 size_t (*source)(uint8_t *buf, size_t n,
						  void *priv),
				 void *priv)
{
	struct tevent_req *req;
	struct cli_push_state *state;
	size_t page_size = 1024;
	uint64_t tmp64;

	req = tevent_req_create(mem_ctx, &state, struct cli_push_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->ev = ev;
	state->fnum = fnum;
	state->start_offset = start_offset;
	state->mode = mode;
	state->source = source;
	state->priv = priv;
	state->next_offset = start_offset;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		state->chunk_size = smb2cli_conn_max_write_size(cli->conn);
	} else {
		state->chunk_size = cli_write_max_bufsize(cli, mode, 14);
	}
	if (state->chunk_size > page_size) {
		state->chunk_size &= ~(page_size - 1);
	}

	if (window_size == 0) {
		/*
		 * We use 16 MByte as default window size.
		 */
		window_size = 16 * 1024 * 1024;
	}

	tmp64 = window_size/state->chunk_size;
	if ((window_size % state->chunk_size) > 0) {
		tmp64 += 1;
	}
	tmp64 = MAX(tmp64, 1);
	tmp64 = MIN(tmp64, 256);
	state->max_chunks = tmp64;

	/*
	 * We defer the callback because of the complex
	 * substate/subfunction logic
	 */
	tevent_req_defer_callback(req, ev);

	cli_push_setup_chunks(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void cli_push_setup_chunks(struct tevent_req *req)
{
	struct cli_push_state *state =
		tevent_req_data(req,
		struct cli_push_state);
	struct cli_push_chunk *chunk, *next = NULL;
	size_t i;

	for (chunk = state->chunks; chunk; chunk = next) {
		/*
		 * Note that chunk might be removed from this call.
		 */
		next = chunk->next;
		cli_push_chunk_ship(chunk);
		if (!tevent_req_is_in_progress(req)) {
			return;
		}
	}

	for (i = state->num_chunks; i < state->max_chunks; i++) {

		if (state->num_waiting > 0) {
			return;
		}

		if (state->eof) {
			break;
		}

		chunk = talloc_zero(state, struct cli_push_chunk);
		if (tevent_req_nomem(chunk, req)) {
			return;
		}
		chunk->req = req;
		chunk->ofs = state->next_offset;
		chunk->buf = talloc_array(chunk,
					  uint8_t,
					  state->chunk_size);
		if (tevent_req_nomem(chunk->buf, req)) {
			return;
		}
		chunk->total_size = state->source(chunk->buf,
						  state->chunk_size,
						  state->priv);
		if (chunk->total_size == 0) {
			/* nothing to send */
			talloc_free(chunk);
			state->eof = true;
			break;
		}
		state->next_offset += chunk->total_size;

		DLIST_ADD_END(state->chunks, chunk);
		state->num_chunks++;
		state->num_waiting++;

		cli_push_chunk_ship(chunk);
		if (!tevent_req_is_in_progress(req)) {
			return;
		}
	}

	if (!state->eof) {
		return;
	}

	if (state->num_chunks > 0) {
		return;
	}

	tevent_req_done(req);
}

static void cli_push_chunk_ship(struct cli_push_chunk *chunk)
{
	struct tevent_req *req = chunk->req;
	struct cli_push_state *state =
		tevent_req_data(req,
		struct cli_push_state);
	bool ok;
	const uint8_t *buf;
	off_t ofs;
	size_t size;

	if (chunk->done) {
		DLIST_REMOVE(state->chunks, chunk);
		SMB_ASSERT(state->num_chunks > 0);
		state->num_chunks--;
		TALLOC_FREE(chunk);

		return;
	}

	if (chunk->subreq != NULL) {
		return;
	}

	SMB_ASSERT(state->num_waiting > 0);

	buf = chunk->buf + chunk->tmp_size;
	ofs = chunk->ofs + chunk->tmp_size;
	size = chunk->total_size - chunk->tmp_size;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		uint32_t max_size;

		ok = smb2cli_conn_req_possible(state->cli->conn, &max_size);
		if (!ok) {
			return;
		}

		/*
		 * downgrade depending on the available credits
		 */
		size = MIN(max_size, size);

		chunk->subreq = cli_smb2_write_send(chunk,
						    state->ev,
						    state->cli,
						    state->fnum,
						    state->mode,
						    buf,
						    ofs,
						    size);
		if (tevent_req_nomem(chunk->subreq, req)) {
			return;
		}
	} else {
		ok = smb1cli_conn_req_possible(state->cli->conn);
		if (!ok) {
			return;
		}

		chunk->subreq = cli_write_andx_send(chunk,
						    state->ev,
						    state->cli,
						    state->fnum,
						    state->mode,
						    buf,
						    ofs,
						    size);
		if (tevent_req_nomem(chunk->subreq, req)) {
			return;
		}
	}
	tevent_req_set_callback(chunk->subreq,
				cli_push_chunk_done,
				chunk);

	state->num_waiting--;
	return;
}

static void cli_push_chunk_done(struct tevent_req *subreq)
{
	struct cli_push_chunk *chunk =
		tevent_req_callback_data(subreq,
		struct cli_push_chunk);
	struct tevent_req *req = chunk->req;
	struct cli_push_state *state =
		tevent_req_data(req,
		struct cli_push_state);
	NTSTATUS status;
	size_t expected = chunk->total_size - chunk->tmp_size;
	size_t written;

	chunk->subreq = NULL;

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		status = cli_smb2_write_recv(subreq, &written);
	} else {
		status = cli_write_andx_recv(subreq, &written);
	}
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (written > expected) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (written == 0) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	chunk->tmp_size += written;

	if (chunk->tmp_size == chunk->total_size) {
		chunk->done = true;
	} else {
		state->num_waiting++;
	}

	cli_push_setup_chunks(req);
}

NTSTATUS cli_push_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_push(struct cli_state *cli, uint16_t fnum, uint16_t mode,
		  off_t start_offset, size_t window_size,
		  size_t (*source)(uint8_t *buf, size_t n, void *priv),
		  void *priv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_push_send(frame, ev, cli, fnum, mode, start_offset,
			    window_size, source, priv);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = cli_push_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

#define SPLICE_BLOCK_SIZE 1024 * 1024

static NTSTATUS cli_splice_fallback(TALLOC_CTX *frame,
				    struct cli_state *srccli,
				    struct cli_state *dstcli,
				    uint16_t src_fnum, uint16_t dst_fnum,
				    off_t initial_size,
				    off_t src_offset, off_t dst_offset,
				    off_t *written,
				    int (*splice_cb)(off_t n, void *priv),
				    void *priv)
{
	NTSTATUS status;
	uint8_t *buf = talloc_size(frame, SPLICE_BLOCK_SIZE);
	size_t nread;
	off_t remaining = initial_size;
	*written = 0;

	while (remaining) {
		size_t to_read = MIN(remaining, SPLICE_BLOCK_SIZE);

		status = cli_read(srccli, src_fnum,
				  (char *)buf, src_offset, to_read,
				  &nread);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = cli_writeall(dstcli, dst_fnum, 0,
				      buf, dst_offset, nread, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if ((src_offset > INT64_MAX - nread) ||
		    (dst_offset > INT64_MAX - nread)) {
			return NT_STATUS_FILE_TOO_LARGE;
		}
		src_offset += nread;
		dst_offset += nread;
		*written += nread;
		if (remaining < nread) {
			return NT_STATUS_INTERNAL_ERROR;
		}
		remaining -= nread;
		if (!splice_cb(initial_size - remaining, priv)) {
			return NT_STATUS_CANCELLED;
		}
	}

	return NT_STATUS_OK;
}

NTSTATUS cli_splice(struct cli_state *srccli, struct cli_state *dstcli,
		    uint16_t src_fnum, uint16_t dst_fnum,
		    off_t size,
		    off_t src_offset, off_t dst_offset,
		    off_t *written,
		    int (*splice_cb)(off_t n, void *priv), void *priv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	bool retry_fallback = false;

	if (smbXcli_conn_has_async_calls(srccli->conn) ||
	    smbXcli_conn_has_async_calls(dstcli->conn))
	{
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	do {
		ev = samba_tevent_context_init(frame);
		if (ev == NULL) {
			goto out;
		}
		if (srccli == dstcli &&
		    smbXcli_conn_protocol(srccli->conn) >= PROTOCOL_SMB2_02 &&
		    !retry_fallback)
		{
			req = cli_smb2_splice_send(frame, ev,
						   srccli, src_fnum, dst_fnum,
						   size, src_offset, dst_offset,
						   splice_cb, priv);
		} else {
			status = cli_splice_fallback(frame,
						     srccli, dstcli,
						     src_fnum, dst_fnum,
						     size,
						     src_offset, dst_offset,
						     written,
						     splice_cb, priv);
			goto out;
		}
		if (req == NULL) {
			goto out;
		}
		if (!tevent_req_poll(req, ev)) {
			status = map_nt_error_from_unix(errno);
			goto out;
		}
		status = cli_smb2_splice_recv(req, written);

		/*
		 * Older versions of Samba don't support
		 * FSCTL_SRV_COPYCHUNK_WRITE so use the fallback.
		 */
		retry_fallback = NT_STATUS_EQUAL(status, NT_STATUS_INVALID_DEVICE_REQUEST);
	} while (retry_fallback);

 out:
	TALLOC_FREE(frame);
	return status;
}
