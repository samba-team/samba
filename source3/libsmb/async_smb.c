/*
   Unix SMB/CIFS implementation.
   Infrastructure for async SMB client requests
   Copyright (C) Volker Lendecke 2008

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
#include "../lib/async_req/async_sock.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../lib/util/tevent_unix.h"
#include "async_smb.h"
#include "../libcli/smb/smb_seal.h"
#include "libsmb/nmblib.h"
#include "../libcli/smb/read_smb.h"

static NTSTATUS cli_pull_raw_error(const uint8_t *buf)
{
	const uint8_t *hdr = buf + NBT_HDR_SIZE;
	uint32_t flags2 = SVAL(hdr, HDR_FLG2);
	NTSTATUS status = NT_STATUS(IVAL(hdr, HDR_RCLS));

	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}

	if (flags2 & FLAGS2_32_BIT_ERROR_CODES) {
		return status;
	}

	return NT_STATUS_DOS(CVAL(hdr, HDR_RCLS), SVAL(hdr, HDR_ERR));
}

/**
 * Figure out if there is an andx command behind the current one
 * @param[in] buf	The smb buffer to look at
 * @param[in] ofs	The offset to the wct field that is followed by the cmd
 * @retval Is there a command following?
 */

static bool have_andx_command(const char *buf, uint16_t ofs)
{
	uint8_t wct;
	size_t buflen = talloc_get_size(buf);

	if ((ofs == buflen-1) || (ofs == buflen)) {
		return false;
	}

	wct = CVAL(buf, ofs);
	if (wct < 2) {
		/*
		 * Not enough space for the command and a following pointer
		 */
		return false;
	}
	return (CVAL(buf, ofs+1) != 0xff);
}

#define MAX_SMB_IOV 5

struct cli_smb_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint8_t header[smb_wct+1]; /* Space for the header including the wct */

	/*
	 * For normal requests, cli_smb_req_send chooses a mid. Secondary
	 * trans requests need to use the mid of the primary request, so we
	 * need a place to store it. Assume it's set if != 0.
	 */
	uint16_t mid;

	uint16_t *vwv;
	uint8_t bytecount_buf[2];

	struct iovec iov[MAX_SMB_IOV+3];
	int iov_count;

	uint8_t *inbuf;
	uint32_t seqnum;
	int chain_num;
	int chain_length;
	struct tevent_req **chained_requests;

	bool one_way;
};

static uint16_t cli_alloc_mid(struct cli_state *cli)
{
	int num_pending = talloc_array_length(cli->conn.pending);
	uint16_t result;

	while (true) {
		int i;

		result = cli->conn.smb1.mid++;
		if ((result == 0) || (result == 0xffff)) {
			continue;
		}

		for (i=0; i<num_pending; i++) {
			if (result == cli_smb_req_mid(cli->conn.pending[i])) {
				break;
			}
		}

		if (i == num_pending) {
			return result;
		}
	}
}

void cli_smb_req_unset_pending(struct tevent_req *req)
{
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);
	struct cli_state *cli = state->cli;
	int num_pending = talloc_array_length(cli->conn.pending);
	int i;

	if (state->mid != 0) {
		/*
		 * This is a [nt]trans[2] request which waits
		 * for more than one reply.
		 */
		return;
	}

	talloc_set_destructor(req, NULL);

	if (num_pending == 1) {
		/*
		 * The pending read_smb tevent_req is a child of
		 * cli->pending. So if nothing is pending anymore, we need to
		 * delete the socket read fde.
		 */
		TALLOC_FREE(cli->conn.pending);
		cli->conn.read_smb_req = NULL;
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
	 * Remove ourselves from the cli->conn.pending array
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

static int cli_smb_req_destructor(struct tevent_req *req)
{
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);
	/*
	 * Make sure we really remove it from
	 * the pending array on destruction.
	 */
	state->mid = 0;
	cli_smb_req_unset_pending(req);
	return 0;
}

static bool cli_state_receive_next(struct cli_state *cli);
static void cli_state_notify_pending(struct cli_state *cli, NTSTATUS status);

bool cli_smb_req_set_pending(struct tevent_req *req)
{
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);
	struct cli_state *cli;
	struct tevent_req **pending;
	int num_pending;

	cli = state->cli;
	num_pending = talloc_array_length(cli->conn.pending);

	pending = talloc_realloc(cli, cli->conn.pending, struct tevent_req *,
				 num_pending+1);
	if (pending == NULL) {
		return false;
	}
	pending[num_pending] = req;
	cli->conn.pending = pending;
	talloc_set_destructor(req, cli_smb_req_destructor);

	if (!cli_state_receive_next(cli)) {
		/*
		 * the caller should notify the current request
		 *
		 * And all other pending requests get notified
		 * by cli_state_notify_pending().
		 */
		cli_smb_req_unset_pending(req);
		cli_state_notify_pending(cli, NT_STATUS_NO_MEMORY);
		return false;
	}

	return true;
}

static void cli_smb_received(struct tevent_req *subreq);
static NTSTATUS cli_state_dispatch_smb1(struct cli_state *cli,
					TALLOC_CTX *frame,
					uint8_t *inbuf);

static bool cli_state_receive_next(struct cli_state *cli)
{
	size_t num_pending = talloc_array_length(cli->conn.pending);
	struct tevent_req *req;
	struct cli_smb_state *state;

	if (cli->conn.read_smb_req != NULL) {
		return true;
	}

	if (num_pending == 0) {
		return true;
	}

	req = cli->conn.pending[0];
	state = tevent_req_data(req, struct cli_smb_state);

	cli->conn.dispatch_incoming = cli_state_dispatch_smb1;

	/*
	 * We're the first ones, add the read_smb request that waits for the
	 * answer from the server
	 */
	cli->conn.read_smb_req = read_smb_send(cli->conn.pending, state->ev,
					       cli->conn.fd);
	if (cli->conn.read_smb_req == NULL) {
		return false;
	}
	tevent_req_set_callback(cli->conn.read_smb_req, cli_smb_received, cli);
	return true;
}

static void cli_state_notify_pending(struct cli_state *cli, NTSTATUS status)
{
	cli_state_disconnect(cli);

	/*
	 * Cancel all pending requests. We do not do a for-loop walking
	 * cli->conn.pending because that array changes in
	 * cli_smb_req_destructor().
	 */
	while (talloc_array_length(cli->conn.pending) > 0) {
		struct tevent_req *req;
		struct cli_smb_state *state;

		req = cli->conn.pending[0];
		state = tevent_req_data(req, struct cli_smb_state);

		/*
		 * We're dead. No point waiting for trans2
		 * replies.
		 */
		state->mid = 0;

		cli_smb_req_unset_pending(req);

		/*
		 * we need to defer the callback, because we may notify more
		 * then one caller.
		 */
		tevent_req_defer_callback(req, state->ev);
		tevent_req_nterror(req, status);
	}
}

/*
 * Fetch a smb request's mid. Only valid after the request has been sent by
 * cli_smb_req_send().
 */
uint16_t cli_smb_req_mid(struct tevent_req *req)
{
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);

	if (state->mid != 0) {
		return state->mid;
	}

	return SVAL(state->header, smb_mid);
}

void cli_smb_req_set_mid(struct tevent_req *req, uint16_t mid)
{
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);
	state->mid = mid;
}

uint32_t cli_smb_req_seqnum(struct tevent_req *req)
{
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);
	return state->seqnum;
}

void cli_smb_req_set_seqnum(struct tevent_req *req, uint32_t seqnum)
{
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);
	state->seqnum = seqnum;
}

static size_t iov_len(const struct iovec *iov, int count)
{
	size_t result = 0;
	int i;
	for (i=0; i<count; i++) {
		result += iov[i].iov_len;
	}
	return result;
}

static uint8_t *iov_concat(TALLOC_CTX *mem_ctx, const struct iovec *iov,
			   int count)
{
	size_t len = iov_len(iov, count);
	size_t copied;
	uint8_t *buf;
	int i;

	buf = talloc_array(mem_ctx, uint8_t, len);
	if (buf == NULL) {
		return NULL;
	}
	copied = 0;
	for (i=0; i<count; i++) {
		memcpy(buf+copied, iov[i].iov_base, iov[i].iov_len);
		copied += iov[i].iov_len;
	}
	return buf;
}

struct tevent_req *cli_smb_req_create(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli,
				      uint8_t smb_command,
				      uint8_t additional_flags,
				      uint8_t wct, uint16_t *vwv,
				      int iov_count,
				      struct iovec *bytes_iov)
{
	struct tevent_req *result;
	struct cli_smb_state *state;
	struct timeval endtime;

	if (iov_count > MAX_SMB_IOV) {
		/*
		 * Should not happen :-)
		 */
		return NULL;
	}

	result = tevent_req_create(mem_ctx, &state, struct cli_smb_state);
	if (result == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->mid = 0;		/* Set to auto-choose in cli_smb_req_send */
	state->chain_num = 0;
	state->chained_requests = NULL;

	cli_setup_packet_buf(cli, (char *)state->header);
	SCVAL(state->header, smb_com, smb_command);
	SSVAL(state->header, smb_tid, cli->smb1.tid);
	SCVAL(state->header, smb_wct, wct);

	state->vwv = vwv;

	SSVAL(state->bytecount_buf, 0, iov_len(bytes_iov, iov_count));

	state->iov[0].iov_base = (void *)state->header;
	state->iov[0].iov_len  = sizeof(state->header);
	state->iov[1].iov_base = (void *)state->vwv;
	state->iov[1].iov_len  = wct * sizeof(uint16_t);
	state->iov[2].iov_base = (void *)state->bytecount_buf;
	state->iov[2].iov_len  = sizeof(uint16_t);

	if (iov_count != 0) {
		memcpy(&state->iov[3], bytes_iov,
		       iov_count * sizeof(*bytes_iov));
	}
	state->iov_count = iov_count + 3;

	if (cli->timeout) {
		endtime = timeval_current_ofs_msec(cli->timeout);
		if (!tevent_req_set_endtime(result, ev, endtime)) {
			return result;
		}
	}

	switch (smb_command) {
	case SMBtranss:
	case SMBtranss2:
	case SMBnttranss:
	case SMBntcancel:
		state->one_way = true;
		break;
	case SMBlockingX:
		if ((wct == 8) &&
		    (CVAL(vwv+3, 0) == LOCKING_ANDX_OPLOCK_RELEASE)) {
			state->one_way = true;
		}
		break;
	}

	return result;
}

static NTSTATUS cli_signv(struct cli_state *cli, struct iovec *iov, int count,
		          uint32_t *seqnum)
{
	uint8_t *buf;

	/*
	 * Obvious optimization: Make cli_calculate_sign_mac work with struct
	 * iovec directly. MD5Update would do that just fine.
	 */

	if ((count <= 0) || (iov[0].iov_len < smb_wct)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	buf = iov_concat(talloc_tos(), iov, count);
	if (buf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	cli_calculate_sign_mac(cli, (char *)buf, seqnum);
	memcpy(iov[0].iov_base, buf, iov[0].iov_len);

	TALLOC_FREE(buf);
	return NT_STATUS_OK;
}

static void cli_smb_sent(struct tevent_req *subreq);

static NTSTATUS cli_smb_req_iov_send(struct tevent_req *req,
				     struct cli_smb_state *state,
				     struct iovec *iov, int iov_count)
{
	struct tevent_req *subreq;
	NTSTATUS status;

	if (!cli_state_is_connected(state->cli)) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	if (iov[0].iov_len < smb_wct) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state->mid != 0) {
		SSVAL(iov[0].iov_base, smb_mid, state->mid);
	} else {
		uint16_t mid = cli_alloc_mid(state->cli);
		SSVAL(iov[0].iov_base, smb_mid, mid);
	}

	smb_setlen_nbt((char *)iov[0].iov_base, iov_len(iov, iov_count) - 4);

	status = cli_signv(state->cli, iov, iov_count, &state->seqnum);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (cli_state_encryption_on(state->cli)) {
		char *buf, *enc_buf;

		buf = (char *)iov_concat(talloc_tos(), iov, iov_count);
		if (buf == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		status = common_encrypt_buffer(state->cli->trans_enc_state,
					       (char *)buf, &enc_buf);
		TALLOC_FREE(buf);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Error in encrypting client message: %s\n",
				  nt_errstr(status)));
			return status;
		}
		buf = (char *)talloc_memdup(state, enc_buf,
					    smb_len_nbt(enc_buf)+4);
		SAFE_FREE(enc_buf);
		if (buf == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		iov[0].iov_base = (void *)buf;
		iov[0].iov_len = talloc_get_size(buf);
		iov_count = 1;
	}
	subreq = writev_send(state, state->ev, state->cli->conn.outgoing,
			     state->cli->conn.fd, false, iov, iov_count);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, cli_smb_sent, req);
	return NT_STATUS_OK;
}

NTSTATUS cli_smb_req_send(struct tevent_req *req)
{
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);

	if (!tevent_req_is_in_progress(req)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	return cli_smb_req_iov_send(req, state, state->iov, state->iov_count);
}

struct tevent_req *cli_smb_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				uint8_t smb_command,
				uint8_t additional_flags,
				uint8_t wct, uint16_t *vwv,
				uint32_t num_bytes,
				const uint8_t *bytes)
{
	struct tevent_req *req;
	struct iovec iov;
	NTSTATUS status;

	iov.iov_base = discard_const_p(void, bytes);
	iov.iov_len = num_bytes;

	req = cli_smb_req_create(mem_ctx, ev, cli, smb_command,
				 additional_flags, wct, vwv, 1, &iov);
	if (req == NULL) {
		return NULL;
	}
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}
	status = cli_smb_req_send(req);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}
	return req;
}

static void cli_smb_sent(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);
	ssize_t nwritten;
	int err;

	nwritten = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		NTSTATUS status = map_nt_error_from_unix_common(err);
		cli_state_notify_pending(state->cli, status);
		return;
	}

	if (state->one_way) {
		state->inbuf = NULL;
		tevent_req_done(req);
		return;
	}

	if (!cli_smb_req_set_pending(req)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
}

static void cli_smb_received(struct tevent_req *subreq)
{
	struct cli_state *cli = tevent_req_callback_data(
		subreq, struct cli_state);
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	uint8_t *inbuf;
	ssize_t received;
	int err;

	if (subreq != cli->conn.read_smb_req) {
		DEBUG(1, ("Internal error: cli_smb_received called with "
			  "unexpected subreq\n"));
		status = NT_STATUS_INTERNAL_ERROR;
		cli_state_notify_pending(cli, status);
		TALLOC_FREE(frame);
		return;
	}

	received = read_smb_recv(subreq, frame, &inbuf, &err);
	TALLOC_FREE(subreq);
	cli->conn.read_smb_req = NULL;
	if (received == -1) {
		status = map_nt_error_from_unix_common(err);
		cli_state_notify_pending(cli, status);
		TALLOC_FREE(frame);
		return;
	}

	status = cli->conn.dispatch_incoming(cli, frame, inbuf);
	TALLOC_FREE(frame);
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * We should not do any more processing
		 * as the dispatch function called
		 * tevent_req_done().
		 */
		return;
	} else if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		/*
		 * We got an error, so notify all pending requests
		 */
		cli_state_notify_pending(cli, status);
		return;
	}

	/*
	 * We got NT_STATUS_RETRY, so we may ask for a
	 * next incoming pdu.
	 */
	if (!cli_state_receive_next(cli)) {
		cli_state_notify_pending(cli, NT_STATUS_NO_MEMORY);
	}
}

static NTSTATUS cli_state_dispatch_smb1(struct cli_state *cli,
					TALLOC_CTX *frame,
					uint8_t *inbuf)
{
	struct tevent_req *req;
	struct cli_smb_state *state;
	NTSTATUS status;
	int num_pending;
	int i;
	uint16_t mid;
	bool oplock_break;
	const uint8_t *inhdr = inbuf + NBT_HDR_SIZE;

	if ((IVAL(inhdr, 0) != SMB_MAGIC) /* 0xFF"SMB" */
	    && (SVAL(inhdr, 0) != 0x45ff)) /* 0xFF"E" */ {
		DEBUG(10, ("Got non-SMB PDU\n"));
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (cli_state_encryption_on(cli) && (CVAL(inbuf, 0) == 0)) {
		uint16_t enc_ctx_num;

		status = get_enc_ctx_num(inbuf, &enc_ctx_num);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("get_enc_ctx_num returned %s\n",
				   nt_errstr(status)));
			return status;
		}

		if (enc_ctx_num != cli->trans_enc_state->enc_ctx_num) {
			DEBUG(10, ("wrong enc_ctx %d, expected %d\n",
				   enc_ctx_num,
				   cli->trans_enc_state->enc_ctx_num));
			return NT_STATUS_INVALID_HANDLE;
		}

		status = common_decrypt_buffer(cli->trans_enc_state,
					       (char *)inbuf);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("common_decrypt_buffer returned %s\n",
				   nt_errstr(status)));
			return status;
		}
	}

	mid = SVAL(inhdr, HDR_MID);
	num_pending = talloc_array_length(cli->conn.pending);

	for (i=0; i<num_pending; i++) {
		if (mid == cli_smb_req_mid(cli->conn.pending[i])) {
			break;
		}
	}
	if (i == num_pending) {
		/* Dump unexpected reply */
		return NT_STATUS_RETRY;
	}

	oplock_break = false;

	if (mid == 0xffff) {
		/*
		 * Paranoia checks that this is really an oplock break request.
		 */
		oplock_break = (smb_len_nbt(inbuf) == 51); /* hdr + 8 words */
		oplock_break &= ((CVAL(inhdr, HDR_FLG) & FLAG_REPLY) == 0);
		oplock_break &= (CVAL(inhdr, HDR_COM) == SMBlockingX);
		oplock_break &= (SVAL(inhdr, HDR_VWV+VWV(6)) == 0);
		oplock_break &= (SVAL(inhdr, HDR_VWV+VWV(7)) == 0);

		if (!oplock_break) {
			/* Dump unexpected reply */
			return NT_STATUS_RETRY;
		}
	}

	req = cli->conn.pending[i];
	state = tevent_req_data(req, struct cli_smb_state);

	if (!oplock_break /* oplock breaks are not signed */
	    && !cli_check_sign_mac(cli, (char *)inbuf, state->seqnum+1)) {
		DEBUG(10, ("cli_check_sign_mac failed\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (state->chained_requests != NULL) {
		struct tevent_req **chain = talloc_move(frame,
					    &state->chained_requests);
		int num_chained = talloc_array_length(chain);

		/*
		 * We steal the inbuf to the chain,
		 * so that it will stay until all
		 * requests of the chain are finished.
		 *
		 * Each requests in the chain will
		 * hold a talloc reference to the chain.
		 * This way we do not expose the talloc_reference()
		 * behavior to the callers.
		 */
		talloc_steal(chain, inbuf);

		for (i=0; i<num_chained; i++) {
			struct tevent_req **ref;

			req = chain[i];
			state = tevent_req_data(req, struct cli_smb_state);

			cli_smb_req_unset_pending(req);

			/*
			 * as we finish multiple requests here
			 * we need to defer the callbacks as
			 * they could destroy our current stack state.
			 */
			tevent_req_defer_callback(req, state->ev);

			ref = talloc_reference(state, chain);
			if (tevent_req_nomem(ref, req)) {
				continue;
			}

			state->inbuf = inbuf;
			state->chain_num = i;
			state->chain_length = num_chained;

			tevent_req_done(req);
		}

		return NT_STATUS_RETRY;
	}

	cli_smb_req_unset_pending(req);

	state->inbuf = talloc_move(state, &inbuf);
	state->chain_num = 0;
	state->chain_length = 1;

	if (talloc_array_length(cli->conn.pending) == 0) {
		tevent_req_done(req);
		return NT_STATUS_OK;
	}

	tevent_req_defer_callback(req, state->ev);
	tevent_req_done(req);
	return NT_STATUS_RETRY;
}

NTSTATUS cli_smb_recv(struct tevent_req *req,
		      TALLOC_CTX *mem_ctx, uint8_t **pinbuf,
		      uint8_t min_wct, uint8_t *pwct, uint16_t **pvwv,
		      uint32_t *pnum_bytes, uint8_t **pbytes)
{
	struct cli_smb_state *state = tevent_req_data(
		req, struct cli_smb_state);
	NTSTATUS status = NT_STATUS_OK;
	uint8_t cmd, wct;
	uint16_t num_bytes;
	size_t wct_ofs, bytes_offset;
	int i;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (state->inbuf == NULL) {
		if (min_wct != 0) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		if (pinbuf) {
			*pinbuf = NULL;
		}
		if (pwct) {
			*pwct = 0;
		}
		if (pvwv) {
			*pvwv = NULL;
		}
		if (pnum_bytes) {
			*pnum_bytes = 0;
		}
		if (pbytes) {
			*pbytes = NULL;
		}
		/* This was a request without a reply */
		return NT_STATUS_OK;
	}

	wct_ofs = smb_wct;
	cmd = CVAL(state->inbuf, smb_com);

	for (i=0; i<state->chain_num; i++) {
		if (i < state->chain_num-1) {
			if (cmd == 0xff) {
				return NT_STATUS_REQUEST_ABORTED;
			}
			if (!is_andx_req(cmd)) {
				return NT_STATUS_INVALID_NETWORK_RESPONSE;
			}
		}

		if (!have_andx_command((char *)state->inbuf, wct_ofs)) {
			/*
			 * This request was not completed because a previous
			 * request in the chain had received an error.
			 */
			return NT_STATUS_REQUEST_ABORTED;
		}

		cmd = CVAL(state->inbuf, wct_ofs + 1);
		wct_ofs = SVAL(state->inbuf, wct_ofs + 3);

		/*
		 * Skip the all-present length field. No overflow, we've just
		 * put a 16-bit value into a size_t.
		 */
		wct_ofs += 4;

		if (wct_ofs+2 > talloc_get_size(state->inbuf)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
	}

	state->cli->raw_status = cli_pull_raw_error(state->inbuf);
	if (NT_STATUS_IS_DOS(state->cli->raw_status)) {
		uint8_t eclass = NT_STATUS_DOS_CLASS(state->cli->raw_status);
		uint16_t ecode = NT_STATUS_DOS_CODE(state->cli->raw_status);
		/*
		 * TODO: is it really a good idea to do a mapping here?
		 *
		 * The old cli_pull_error() also does it, so I do not change
		 * the behavior yet.
		 */
		status = dos_to_ntstatus(eclass, ecode);
	} else {
		status = state->cli->raw_status;
	}

	if (!have_andx_command((char *)state->inbuf, wct_ofs)) {

		if ((cmd == SMBsesssetupX)
		    && NT_STATUS_EQUAL(
			    status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			/*
			 * NT_STATUS_MORE_PROCESSING_REQUIRED is a
			 * valid return code for session setup
			 */
			goto no_err;
		}

		if (NT_STATUS_IS_ERR(status)) {
			/*
			 * The last command takes the error code. All
			 * further commands down the requested chain
			 * will get a NT_STATUS_REQUEST_ABORTED.
			 */
			return status;
		}
	}

no_err:

	wct = CVAL(state->inbuf, wct_ofs);
	bytes_offset = wct_ofs + 1 + wct * sizeof(uint16_t);
	num_bytes = SVAL(state->inbuf, bytes_offset);

	if (wct < min_wct) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	/*
	 * wct_ofs is a 16-bit value plus 4, wct is a 8-bit value, num_bytes
	 * is a 16-bit value. So bytes_offset being size_t should be far from
	 * wrapping.
	 */
	if ((bytes_offset + 2 > talloc_get_size(state->inbuf))
	    || (bytes_offset > 0xffff)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (pwct != NULL) {
		*pwct = wct;
	}
	if (pvwv != NULL) {
		*pvwv = (uint16_t *)(state->inbuf + wct_ofs + 1);
	}
	if (pnum_bytes != NULL) {
		*pnum_bytes = num_bytes;
	}
	if (pbytes != NULL) {
		*pbytes = (uint8_t *)state->inbuf + bytes_offset + 2;
	}
	if ((mem_ctx != NULL) && (pinbuf != NULL)) {
		if (state->chain_num == state->chain_length-1) {
			*pinbuf = talloc_move(mem_ctx, &state->inbuf);
		} else {
			*pinbuf = state->inbuf;
		}
	}

	return status;
}

size_t cli_smb_wct_ofs(struct tevent_req **reqs, int num_reqs)
{
	size_t wct_ofs;
	int i;

	wct_ofs = smb_wct - 4;

	for (i=0; i<num_reqs; i++) {
		struct cli_smb_state *state;
		state = tevent_req_data(reqs[i], struct cli_smb_state);
		wct_ofs += iov_len(state->iov+1, state->iov_count-1);
		wct_ofs = (wct_ofs + 3) & ~3;
	}
	return wct_ofs;
}

NTSTATUS cli_smb_chain_send(struct tevent_req **reqs, int num_reqs)
{
	struct cli_smb_state *first_state = tevent_req_data(
		reqs[0], struct cli_smb_state);
	struct cli_smb_state *last_state = tevent_req_data(
		reqs[num_reqs-1], struct cli_smb_state);
	struct cli_smb_state *state;
	size_t wct_offset;
	size_t chain_padding = 0;
	int i, iovlen;
	struct iovec *iov = NULL;
	struct iovec *this_iov;
	NTSTATUS status;

	iovlen = 0;
	for (i=0; i<num_reqs; i++) {
		if (!tevent_req_is_in_progress(reqs[i])) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		state = tevent_req_data(reqs[i], struct cli_smb_state);
		iovlen += state->iov_count;
	}

	iov = talloc_array(last_state, struct iovec, iovlen);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	first_state->chained_requests = (struct tevent_req **)talloc_memdup(
		last_state, reqs, sizeof(*reqs) * num_reqs);
	if (first_state->chained_requests == NULL) {
		TALLOC_FREE(iov);
		return NT_STATUS_NO_MEMORY;
	}

	wct_offset = smb_wct - 4;
	this_iov = iov;

	for (i=0; i<num_reqs; i++) {
		size_t next_padding = 0;
		uint16_t *vwv;

		state = tevent_req_data(reqs[i], struct cli_smb_state);

		if (i < num_reqs-1) {
			if (!is_andx_req(CVAL(state->header, smb_com))
			    || CVAL(state->header, smb_wct) < 2) {
				TALLOC_FREE(iov);
				TALLOC_FREE(first_state->chained_requests);
				return NT_STATUS_INVALID_PARAMETER;
			}
		}

		wct_offset += iov_len(state->iov+1, state->iov_count-1) + 1;
		if ((wct_offset % 4) != 0) {
			next_padding = 4 - (wct_offset % 4);
		}
		wct_offset += next_padding;
		vwv = state->vwv;

		if (i < num_reqs-1) {
			struct cli_smb_state *next_state = tevent_req_data(
				reqs[i+1], struct cli_smb_state);
			SCVAL(vwv+0, 0, CVAL(next_state->header, smb_com));
			SCVAL(vwv+0, 1, 0);
			SSVAL(vwv+1, 0, wct_offset);
		} else if (is_andx_req(CVAL(state->header, smb_com))) {
			/* properly end the chain */
			SCVAL(vwv+0, 0, 0xff);
			SCVAL(vwv+0, 1, 0xff);
			SSVAL(vwv+1, 0, 0);
		}

		if (i == 0) {
			this_iov[0] = state->iov[0];
		} else {
			/*
			 * This one is a bit subtle. We have to add
			 * chain_padding bytes between the requests, and we
			 * have to also include the wct field of the
			 * subsequent requests. We use the subsequent header
			 * for the padding, it contains the wct field in its
			 * last byte.
			 */
			this_iov[0].iov_len = chain_padding+1;
			this_iov[0].iov_base = (void *)&state->header[
				sizeof(state->header) - this_iov[0].iov_len];
			memset(this_iov[0].iov_base, 0, this_iov[0].iov_len-1);
		}
		memcpy(this_iov+1, state->iov+1,
		       sizeof(struct iovec) * (state->iov_count-1));
		this_iov += state->iov_count;
		chain_padding = next_padding;
	}

	status = cli_smb_req_iov_send(reqs[0], last_state, iov, iovlen);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(iov);
		TALLOC_FREE(first_state->chained_requests);
		return status;
	}

	for (i=0; i < (num_reqs - 1); i++) {
		state = tevent_req_data(reqs[i], struct cli_smb_state);

		state->seqnum = last_state->seqnum;
	}

	return NT_STATUS_OK;
}

bool cli_has_async_calls(struct cli_state *cli)
{
	return ((tevent_queue_length(cli->conn.outgoing) != 0)
		|| (talloc_array_length(cli->conn.pending) != 0));
}
