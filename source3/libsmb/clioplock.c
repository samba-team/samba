/*
   Unix SMB/CIFS implementation.
   SMB client oplock functions
   Copyright (C) Andrew Tridgell 2001

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
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "../libcli/smb/smbXcli_base.h"

struct cli_smb_oplock_break_waiter_state {
	uint16_t fnum;
	uint8_t level;
};

static void cli_smb_oplock_break_waiter_done(struct tevent_req *subreq);

struct tevent_req *cli_smb_oplock_break_waiter_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct cli_state *cli)
{
	struct tevent_req *req, *subreq;
	struct cli_smb_oplock_break_waiter_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb_oplock_break_waiter_state);
	if (req == NULL) {
		return NULL;
	}

	/*
	 * Create a fake SMB request that we will never send out. This is only
	 * used to be set into the pending queue with the right mid.
	 */
	subreq = smb1cli_req_create(mem_ctx, ev, cli->conn, 0, 0, 0, 0, 0, 0,
				    0, NULL, NULL, 0, NULL, 0, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	smb1cli_req_set_mid(subreq, 0xffff);

	if (!smbXcli_req_set_pending(subreq)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb_oplock_break_waiter_done, req);
	return req;
}

static void cli_smb_oplock_break_waiter_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb_oplock_break_waiter_state *state = tevent_req_data(
		req, struct cli_smb_oplock_break_waiter_state);
	struct iovec *iov;
	uint8_t wct;
	uint16_t *vwv;
	NTSTATUS status;

	status = smb1cli_req_recv(subreq, state,
				  &iov, /* piov */
				  NULL, /* phdr */
				  &wct,
				  &vwv,
				  NULL, /* pvwv_offset */
				  NULL, /* pnum_bytes */
				  NULL, /* pbytes */
				  NULL, /* pbytes_offset */
				  NULL, /* pinbuf */
				  NULL, 0); /* expected */
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (wct < 8) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
	state->fnum = SVAL(vwv+2, 0);
	state->level = CVAL(vwv+3, 1);
	tevent_req_done(req);
}

NTSTATUS cli_smb_oplock_break_waiter_recv(struct tevent_req *req,
					  uint16_t *pfnum,
					  uint8_t *plevel)
{
	struct cli_smb_oplock_break_waiter_state *state = tevent_req_data(
		req, struct cli_smb_oplock_break_waiter_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pfnum = state->fnum;
	*plevel = state->level;
	return NT_STATUS_OK;
}

/****************************************************************************
send an ack for an oplock break request
****************************************************************************/

struct cli_oplock_ack_state {
	uint8_t dummy;
};

static void cli_oplock_ack_done(struct tevent_req *subreq);

struct tevent_req *cli_oplock_ack_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct cli_state *cli,
				       uint16_t fnum, uint8_t level)
{
	struct tevent_req *req, *subreq;
	struct cli_oplock_ack_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_oplock_ack_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = cli_lockingx_send(
		state,				/* mem_ctx */
		ev,				/* tevent_context */
		cli,				/* cli */
		fnum,				/* fnum */
		LOCKING_ANDX_OPLOCK_RELEASE,	/* typeoflock */
		level,				/* newoplocklevel */
		0,				/* timeout */
		0,				/* num_unlocks */
		NULL,				/* unlocks */
		0,				/* num_locks */
		NULL);				/* locks */

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_oplock_ack_done, req);
	return req;
}

static void cli_oplock_ack_done(struct tevent_req *subreq)
{
	NTSTATUS status = cli_lockingx_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS cli_oplock_ack_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

