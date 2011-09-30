/*
   Unix SMB/CIFS implementation.
   smb2 lib
   Copyright (C) Volker Lendecke 2011
   Copyright (C) Stefan Metzmacher 2011

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
#include "read_smb.h"
#include "smb2cli_base.h"
#include "libsmb/proto.h"
#include "lib/async_req/async_sock.h"
#include "lib/util/tevent_ntstatus.h"

struct smb2cli_req_state {
	struct tevent_context *ev;
	struct cli_state *cli;

	const uint8_t *fixed;
	uint16_t fixed_len;
	const uint8_t *dyn;
	uint32_t dyn_len;

	uint8_t nbt[4];
	uint8_t hdr[64];
	uint8_t pad[7];	/* padding space for compounding */

	/* always an array of 3 talloc elements */
	struct iovec *recv_iov;
};

static void smb2cli_req_unset_pending(struct tevent_req *req)
{
	struct smb2cli_req_state *state =
		tevent_req_data(req,
		struct smb2cli_req_state);
	struct cli_state *cli = state->cli;
	int num_pending = talloc_array_length(cli->conn.pending);
	int i;

	talloc_set_destructor(req, NULL);

	if (num_pending == 1) {
		/*
		 * The pending read_smb tevent_req is a child of
		 * cli->conn.pending. So if nothing is pending anymore,
		 * we need to delete the socket read fde.
		 */
		TALLOC_FREE(cli->conn.pending);
		return;
	}

	for (i=0; i<num_pending; i++) {
		if (req == cli->conn.pending[i]) {
			break;
		}
	}
	if (i == num_pending) {
		/*
		 * Something's seriously broken. Just returning here is the
		 * right thing nevertheless, the point of this routine is to
		 * remove ourselves from cli->conn.pending.
		 */
		return;
	}

	/*
	 * Remove ourselves from the cli->pending array
	 */
	for (; i < (num_pending - 1); i++) {
		cli->conn.pending[i] = cli->conn.pending[i+1];
	}

	/*
	 * No NULL check here, we're shrinking by sizeof(void *), and
	 * talloc_realloc just adjusts the size for this.
	 */
	cli->conn.pending = talloc_realloc(NULL, cli->conn.pending,
					   struct tevent_req *,
					   num_pending - 1);
	return;
}

static int smb2cli_req_destructor(struct tevent_req *req)
{
	smb2cli_req_unset_pending(req);
	return 0;
}

static void smb2cli_inbuf_received(struct tevent_req *subreq);

static bool smb2cli_req_set_pending(struct tevent_req *req)
{
	struct smb2cli_req_state *state =
		tevent_req_data(req,
		struct smb2cli_req_state);
	struct cli_state *cli;
	struct tevent_req **pending;
	int num_pending;
	struct tevent_req *subreq;

	cli = state->cli;
	num_pending = talloc_array_length(cli->conn.pending);

	pending = talloc_realloc(cli, cli->conn.pending, struct tevent_req *,
				 num_pending+1);
	if (pending == NULL) {
		return false;
	}
	pending[num_pending] = req;
	cli->conn.pending = pending;
	talloc_set_destructor(req, smb2cli_req_destructor);

	if (num_pending > 0) {
		return true;
	}

	/*
	 * We're the first ones, add the read_smb request that waits for the
	 * answer from the server
	 */
	subreq = read_smb_send(cli->conn.pending, state->ev, cli->conn.fd);
	if (subreq == NULL) {
		smb2cli_req_unset_pending(req);
		return false;
	}
	tevent_req_set_callback(subreq, smb2cli_inbuf_received, cli);
	return true;
}

static void smb2cli_notify_pending(struct cli_state *cli, NTSTATUS status)
{
	if (cli->conn.fd != -1) {
		close(cli->conn.fd);
	}
	cli->conn.fd = -1;

	/*
	 * Cancel all pending requests. We don't do a for-loop walking
	 * cli->conn.pending because that array changes in
	 * cli_smb_req_destructor().
	 */
	while (talloc_array_length(cli->conn.pending) > 0) {
		struct tevent_req *req;
		struct smb2cli_req_state *state;

		req = cli->conn.pending[0];
		state = tevent_req_data(req, struct smb2cli_req_state);

		smb2cli_req_unset_pending(req);

		/*
		 * we need to defer the callback, because we may notify more
		 * then one caller.
		 */
		tevent_req_defer_callback(req, state->ev);
		tevent_req_nterror(req, status);
	}
}

struct tevent_req *smb2cli_req_create(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli,
				      uint16_t cmd,
				      uint32_t additional_flags,
				      uint32_t clear_flags,
				      unsigned int timeout,
				      uint32_t pid,
				      uint32_t tid,
				      uint64_t uid,
				      const uint8_t *fixed,
				      uint16_t fixed_len,
				      const uint8_t *dyn,
				      uint32_t dyn_len)
{
	struct tevent_req *req;
	struct smb2cli_req_state *state;
	uint32_t flags = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_req_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	state->recv_iov = talloc_zero_array(state, struct iovec, 3);
	if (state->recv_iov == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}

	flags |= additional_flags;
	flags &= ~clear_flags;

	state->fixed = fixed;
	state->fixed_len = fixed_len;
	state->dyn = dyn;
	state->dyn_len = dyn_len;

	SIVAL(state->hdr, SMB2_HDR_PROTOCOL_ID,	SMB2_MAGIC);
	SSVAL(state->hdr, SMB2_HDR_LENGTH,	SMB2_HDR_BODY);
	SSVAL(state->hdr, SMB2_HDR_EPOCH,	1);
	SIVAL(state->hdr, SMB2_HDR_STATUS,     	NT_STATUS_V(NT_STATUS_OK));
	SSVAL(state->hdr, SMB2_HDR_OPCODE,	cmd);
	SSVAL(state->hdr, SMB2_HDR_CREDIT,	31);
	SIVAL(state->hdr, SMB2_HDR_FLAGS,	flags);
	SIVAL(state->hdr, SMB2_HDR_PID,		pid);
	SIVAL(state->hdr, SMB2_HDR_TID,		tid);
	SBVAL(state->hdr, SMB2_HDR_SESSION_ID,	uid);

	if (timeout > 0) {
		struct timeval endtime;

		endtime = timeval_current_ofs_msec(timeout);
		if (!tevent_req_set_endtime(req, ev, endtime)) {
			return req;
		}
	}

	return req;
}

static void smb2cli_writev_done(struct tevent_req *subreq);

NTSTATUS smb2cli_req_compound_submit(struct tevent_req **reqs,
				     int num_reqs)
{
	struct smb2cli_req_state *state;
	struct tevent_req *subreq;
	struct iovec *iov;
	int i, num_iov, nbt_len;

	/*
	 * 1 for the nbt length
	 * per request: HDR, fixed, dyn, padding
	 * -1 because the last one does not need padding
	 */

	iov = talloc_array(reqs[0], struct iovec, 1 + 4*num_reqs - 1);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	num_iov = 1;
	nbt_len = 0;

	for (i=0; i<num_reqs; i++) {
		size_t reqlen;
		bool ret;
		uint64_t mid;

		if (!tevent_req_is_in_progress(reqs[i])) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		state = tevent_req_data(reqs[i], struct smb2cli_req_state);

		if (!cli_state_is_connected(state->cli)) {
			return NT_STATUS_CONNECTION_DISCONNECTED;
		}

		if (state->cli->smb2.mid == UINT64_MAX) {
			return NT_STATUS_CONNECTION_ABORTED;
		}

		mid = state->cli->smb2.mid;
		state->cli->smb2.mid += 1;

		SBVAL(state->hdr, SMB2_HDR_MESSAGE_ID, mid);

		iov[num_iov].iov_base = state->hdr;
		iov[num_iov].iov_len  = sizeof(state->hdr);
		num_iov += 1;

		iov[num_iov].iov_base = discard_const(state->fixed);
		iov[num_iov].iov_len  = state->fixed_len;
		num_iov += 1;

		if (state->dyn != NULL) {
			iov[num_iov].iov_base = discard_const(state->dyn);
			iov[num_iov].iov_len  = state->dyn_len;
			num_iov += 1;
		}

		reqlen = sizeof(state->hdr) + state->fixed_len +
			state->dyn_len;

		if (i < num_reqs-1) {
			if ((reqlen % 8) > 0) {
				uint8_t pad = 8 - (reqlen % 8);
				iov[num_iov].iov_base = state->pad;
				iov[num_iov].iov_len = pad;
				num_iov += 1;
				reqlen += pad;
			}
			SIVAL(state->hdr, SMB2_HDR_NEXT_COMMAND, reqlen);
		}
		nbt_len += reqlen;

		ret = smb2cli_req_set_pending(reqs[i]);
		if (!ret) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/*
	 * TODO: Do signing here
	 */

	state = tevent_req_data(reqs[0], struct smb2cli_req_state);
	_smb_setlen_large(state->nbt, nbt_len);
	iov[0].iov_base = state->nbt;
	iov[0].iov_len  = sizeof(state->nbt);

	subreq = writev_send(state, state->ev, state->cli->conn.outgoing,
			     state->cli->conn.fd, false, iov, num_iov);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smb2cli_writev_done, reqs[0]);
	return NT_STATUS_OK;
}

struct tevent_req *smb2cli_req_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli,
				    uint16_t cmd,
				    uint32_t additional_flags,
				    uint32_t clear_flags,
				    unsigned int timeout,
				    uint32_t pid,
				    uint32_t tid,
				    uint64_t uid,
				    const uint8_t *fixed,
				    uint16_t fixed_len,
				    const uint8_t *dyn,
				    uint32_t dyn_len)
{
	struct tevent_req *req;
	NTSTATUS status;

	req = smb2cli_req_create(mem_ctx, ev, cli, cmd,
				 additional_flags, clear_flags,
				 timeout,
				 pid, tid, uid,
				 fixed, fixed_len, dyn, dyn_len);
	if (req == NULL) {
		return NULL;
	}
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}
	status = smb2cli_req_compound_submit(&req, 1);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void smb2cli_writev_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_req_state *state =
		tevent_req_data(req,
		struct smb2cli_req_state);
	ssize_t nwritten;
	int err;

	nwritten = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		/* here, we need to notify all pending requests */
		smb2cli_notify_pending(state->cli, map_nt_error_from_unix(err));
		return;
	}
}

static NTSTATUS smb2cli_inbuf_parse_compound(uint8_t *buf, TALLOC_CTX *mem_ctx,
					     struct iovec **piov, int *pnum_iov)
{
	struct iovec *iov;
	int num_iov;
	size_t buflen;
	size_t taken;

	num_iov = 1;

	iov = talloc_array(mem_ctx, struct iovec, num_iov);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	iov[0].iov_base = buf;
	iov[0].iov_len = 4;

	buflen = smb_len_large(buf) + 4;
	taken = 4;

	while (taken < buflen) {
		size_t len = buflen - taken;
		uint8_t *hdr = buf + taken;
		struct iovec *cur;
		size_t full_size;
		size_t next_command_ofs;
		uint16_t body_size;
		struct iovec *iov_tmp;

		/*
		 * We need the header plus the body length field
		 */

		if (len < SMB2_HDR_BODY + 2) {
			DEBUG(10, ("%d bytes left, expected at least %d\n",
				   (int)len, SMB2_HDR_BODY));
			goto inval;
		}
		if (IVAL(hdr, 0) != SMB2_MAGIC) {
			DEBUG(10, ("Got non-SMB2 PDU: %x\n",
				   IVAL(hdr, 0)));
			goto inval;
		}
		if (SVAL(hdr, 4) != SMB2_HDR_BODY) {
			DEBUG(10, ("Got HDR len %d, expected %d\n",
				   SVAL(hdr, 4), SMB2_HDR_BODY));
			goto inval;
		}

		full_size = len;
		next_command_ofs = IVAL(hdr, SMB2_HDR_NEXT_COMMAND);
		body_size = SVAL(hdr, SMB2_HDR_BODY);

		if (next_command_ofs != 0) {
			if (next_command_ofs < (SMB2_HDR_BODY + 2)) {
				goto inval;
			}
			if (next_command_ofs > full_size) {
				goto inval;
			}
			full_size = next_command_ofs;
		}
		if (body_size < 2) {
			goto inval;
		}
		body_size &= 0xfffe;

		if (body_size > (full_size - SMB2_HDR_BODY)) {
			goto inval;
		}

		iov_tmp = talloc_realloc(mem_ctx, iov, struct iovec,
					 num_iov + 3);
		if (iov_tmp == NULL) {
			TALLOC_FREE(iov);
			return NT_STATUS_NO_MEMORY;
		}
		iov = iov_tmp;
		cur = &iov[num_iov];
		num_iov += 3;

		cur[0].iov_base = hdr;
		cur[0].iov_len  = SMB2_HDR_BODY;
		cur[1].iov_base = hdr + SMB2_HDR_BODY;
		cur[1].iov_len  = body_size;
		cur[2].iov_base = hdr + SMB2_HDR_BODY + body_size;
		cur[2].iov_len  = full_size - (SMB2_HDR_BODY + body_size);

		taken += full_size;
	}

	*piov = iov;
	*pnum_iov = num_iov;
	return NT_STATUS_OK;

inval:
	TALLOC_FREE(iov);
	return NT_STATUS_INVALID_NETWORK_RESPONSE;
}

static struct tevent_req *cli_smb2_find_pending(struct cli_state *cli,
						uint64_t mid)
{
	int num_pending = talloc_array_length(cli->conn.pending);
	int i;

	for (i=0; i<num_pending; i++) {
		struct tevent_req *req = cli->conn.pending[i];
		struct smb2cli_req_state *state =
			tevent_req_data(req,
			struct smb2cli_req_state);

		if (mid == BVAL(state->hdr, SMB2_HDR_MESSAGE_ID)) {
			return req;
		}
	}
	return NULL;
}

static void smb2cli_inbuf_received(struct tevent_req *subreq)
{
	struct cli_state *cli =
		tevent_req_callback_data(subreq,
		struct cli_state);
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req;
	struct smb2cli_req_state *state = NULL;
	struct iovec *iov;
	int i, num_iov;
	NTSTATUS status;
	uint8_t *inbuf;
	ssize_t received;
	int err;
	size_t num_pending;
	bool defer = true;

	received = read_smb_recv(subreq, frame, &inbuf, &err);
	TALLOC_FREE(subreq);
	if (received == -1) {
		/*
		 * We need to close the connection and notify
		 * all pending requests.
		 */
		smb2cli_notify_pending(cli, map_nt_error_from_unix(err));
		TALLOC_FREE(frame);
		return;
	}

	status = smb2cli_inbuf_parse_compound(inbuf, frame,
					      &iov, &num_iov);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * if we cannot parse the incoming pdu,
		 * the connection becomes unusable.
		 *
		 * We need to close the connection and notify
		 * all pending requests.
		 */
		smb2cli_notify_pending(cli, status);
		TALLOC_FREE(frame);
		return;
	}

	for (i=1; i<num_iov; i+=3) {
		uint8_t *inbuf_ref = NULL;
		struct iovec *cur = &iov[i];
		uint8_t *inhdr = (uint8_t *)cur[0].iov_base;
		uint16_t opcode = SVAL(inhdr, SMB2_HDR_OPCODE);
		uint32_t flags = IVAL(inhdr, SMB2_HDR_FLAGS);
		uint64_t mid = BVAL(inhdr, SMB2_HDR_MESSAGE_ID);
		uint16_t req_opcode;

		req = cli_smb2_find_pending(cli, mid);
		if (req == NULL) {
			/*
			 * TODO: handle oplock breaks and async responses
			 */

			/*
			 * We need to close the connection and notify
			 * all pending requests.
			 */
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			smb2cli_notify_pending(cli, status);
			TALLOC_FREE(frame);
			return;
		}
		state = tevent_req_data(req, struct smb2cli_req_state);

		req_opcode = SVAL(state->hdr, SMB2_HDR_OPCODE);
		if (opcode != req_opcode) {
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			smb2cli_notify_pending(cli, status);
			TALLOC_FREE(frame);
			return;
		}

		if (!(flags & SMB2_HDR_FLAG_REDIRECT)) {
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			smb2cli_notify_pending(cli, status);
			TALLOC_FREE(frame);
			return;
		}

		status = NT_STATUS(IVAL(inhdr, SMB2_HDR_STATUS));
		if ((flags & SMB2_HDR_FLAG_ASYNC) &&
		    NT_STATUS_EQUAL(status, STATUS_PENDING)) {
			uint32_t req_flags = IVAL(state->hdr, SMB2_HDR_FLAGS);
			uint64_t async_id = BVAL(inhdr, SMB2_HDR_ASYNC_ID);

			req_flags |= SMB2_HDR_FLAG_ASYNC;
			SBVAL(state->hdr, SMB2_HDR_FLAGS, req_flags);
			SBVAL(state->hdr, SMB2_HDR_ASYNC_ID, async_id);
			continue;
		}

		smb2cli_req_unset_pending(req);

		/*
		 * There might be more than one response
		 * we need to defer the notifications
		 */
		if ((num_iov == 4) && (talloc_array_length(cli->conn.pending) == 0)) {
			defer = false;
		}

		if (defer) {
			tevent_req_defer_callback(req, state->ev);
		}

		/*
		 * Note: here we use talloc_reference() in a way
		 *       that does not expose it to the caller.
		 */
		inbuf_ref = talloc_reference(state->recv_iov, inbuf);
		if (tevent_req_nomem(inbuf_ref, req)) {
			continue;
		}

		/* copy the related buffers */
		state->recv_iov[0] = cur[0];
		state->recv_iov[1] = cur[1];
		state->recv_iov[2] = cur[2];

		tevent_req_done(req);
	}

	TALLOC_FREE(frame);

	if (!defer) {
		return;
	}

	num_pending = talloc_array_length(cli->conn.pending);
	if (num_pending == 0) {
		if (state->cli->smb2.mid < UINT64_MAX) {
			/* no more pending requests, so we are done for now */
			return;
		}

		/*
		 * If there are no more requests possible,
		 * because we are out of message ids,
		 * we need to disconnect.
		 */
		smb2cli_notify_pending(cli, NT_STATUS_CONNECTION_ABORTED);
		return;
	}
	req = cli->conn.pending[0];
	state = tevent_req_data(req, struct smb2cli_req_state);

	/*
	 * add the read_smb request that waits for the
	 * next answer from the server
	 */
	subreq = read_smb_send(cli->conn.pending, state->ev, cli->conn.fd);
	if (subreq == NULL) {
		smb2cli_notify_pending(cli, NT_STATUS_NO_MEMORY);
		return;
	}
	tevent_req_set_callback(subreq, smb2cli_inbuf_received, cli);
}

NTSTATUS smb2cli_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct iovec **piov,
			  const struct smb2cli_req_expected_response *expected,
			  size_t num_expected)
{
	struct smb2cli_req_state *state =
		tevent_req_data(req,
		struct smb2cli_req_state);
	NTSTATUS status;
	size_t body_size;
	bool found_status = false;
	bool found_size = false;
	size_t i;

	if (piov != NULL) {
		*piov = NULL;
	}

	if (tevent_req_is_nterror(req, &status)) {
		for (i=0; i < num_expected; i++) {
			if (NT_STATUS_EQUAL(status, expected[i].status)) {
				found_status = true;
				break;
			}
		}

		if (found_status) {
			return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		}

		return status;
	}

	if (num_expected == 0) {
		found_status = true;
		found_size = true;
	}

	status = NT_STATUS(IVAL(state->recv_iov[0].iov_base, SMB2_HDR_STATUS));
	body_size = SVAL(state->recv_iov[1].iov_base, 0);

	for (i=0; i < num_expected; i++) {
		if (!NT_STATUS_EQUAL(status, expected[i].status)) {
			continue;
		}

		found_status = true;
		if (expected[i].body_size == 0) {
			found_size = true;
			break;
		}

		if (expected[i].body_size == body_size) {
			found_size = true;
			break;
		}
	}

	if (!found_status) {
		return status;
	}

	if (!found_size) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (piov != NULL) {
		*piov = talloc_move(mem_ctx, &state->recv_iov);
	}

	return status;
}
