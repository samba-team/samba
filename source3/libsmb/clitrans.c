/*
   Unix SMB/CIFS implementation.
   client transaction calls
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
#include "../libcli/smb/smbXcli_base.h"

struct cli_trans_state {
	struct cli_state *cli;
	struct tevent_req *subreq;
	uint16_t recv_flags2;
	uint16_t *setup;
	uint8_t num_setup;
	uint8_t *param;
	uint32_t num_param;
	uint8_t *data;
	uint32_t num_data;
};

static void cli_trans_done(struct tevent_req *subreq);
static bool cli_trans_cancel(struct tevent_req *req);

struct tevent_req *cli_trans_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct cli_state *cli, uint16_t additional_flags2, uint8_t cmd,
	const char *pipe_name, uint16_t fid, uint16_t function, int flags,
	uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
	uint8_t *param, uint32_t num_param, uint32_t max_param,
	uint8_t *data, uint32_t num_data, uint32_t max_data)
{
	struct tevent_req *req;
	struct cli_trans_state *state;
	uint8_t additional_flags = 0;
	uint8_t clear_flags = 0;
	uint16_t clear_flags2 = 0;

	req = tevent_req_create(mem_ctx, &state, struct cli_trans_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	state->subreq = smb1cli_trans_send(state, ev,
					   cli->conn, cmd,
					   additional_flags, clear_flags,
					   additional_flags2, clear_flags2,
					   cli->timeout,
					   cli->smb1.pid,
					   cli->smb1.tcon,
					   cli->smb1.session,
					   pipe_name, fid, function, flags,
					   setup, num_setup, max_setup,
					   param, num_param, max_param,
					   data, num_data, max_data);
	if (tevent_req_nomem(state->subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->subreq, cli_trans_done, req);
	tevent_req_set_cancel_fn(req, cli_trans_cancel);
	return req;
}

static bool cli_trans_cancel(struct tevent_req *req)
{
	struct cli_trans_state *state = tevent_req_data(
		req, struct cli_trans_state);
	bool ok;

	ok = tevent_req_cancel(state->subreq);
	return ok;
}

static void cli_trans_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_trans_state *state = tevent_req_data(
		req, struct cli_trans_state);
	NTSTATUS status;

	status = smb1cli_trans_recv(
		subreq,
		state,
		&state->recv_flags2,
		&state->setup, 0, &state->num_setup,
		&state->param, 0, &state->num_param,
		&state->data, 0, &state->num_data);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_trans_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			uint16_t *recv_flags2,
			uint16_t **setup, uint8_t min_setup,
			uint8_t *num_setup,
			uint8_t **param, uint32_t min_param,
			uint32_t *num_param,
			uint8_t **data, uint32_t min_data,
			uint32_t *num_data)
{
	struct cli_trans_state *state = tevent_req_data(
		req, struct cli_trans_state);
	NTSTATUS status = NT_STATUS_OK;
	bool map_dos_errors = true;

	if (tevent_req_is_nterror(req, &status)) {
		goto map_error;
	}

	if ((state->num_setup < min_setup) ||
	    (state->num_param < min_param) ||
	    (state->num_data < min_data)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (recv_flags2 != NULL) {
		*recv_flags2 = state->recv_flags2;
	}
	if (setup != NULL) {
		*setup = talloc_move(mem_ctx, &state->setup);
		*num_setup = state->num_setup;
	}
	if (param != NULL) {
		*param = talloc_move(mem_ctx, &state->param);
		*num_param = state->num_param;
	}
	if (data != NULL) {
		*data = talloc_move(mem_ctx, &state->data);
		*num_data = state->num_data;
	}

map_error:
	map_dos_errors = state->cli->map_dos_errors;
	state->cli->raw_status = status;

	if (NT_STATUS_IS_DOS(status) && map_dos_errors) {
		uint8_t eclass = NT_STATUS_DOS_CLASS(status);
		uint16_t ecode = NT_STATUS_DOS_CODE(status);
		/*
		 * TODO: is it really a good idea to do a mapping here?
		 *
		 * The old cli_pull_error() also does it, so I do not change
		 * the behavior yet.
		 */
		status = dos_to_ntstatus(eclass, ecode);
	}

	return status;
}

NTSTATUS cli_trans(TALLOC_CTX *mem_ctx, struct cli_state *cli,
		   uint8_t trans_cmd,
		   const char *pipe_name, uint16_t fid, uint16_t function,
		   int flags,
		   uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
		   uint8_t *param, uint32_t num_param, uint32_t max_param,
		   uint8_t *data, uint32_t num_data, uint32_t max_data,
		   uint16_t *recv_flags2,
		   uint16_t **rsetup, uint8_t min_rsetup, uint8_t *num_rsetup,
		   uint8_t **rparam, uint32_t min_rparam, uint32_t *num_rparam,
		   uint8_t **rdata, uint32_t min_rdata, uint32_t *num_rdata)
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
	req = cli_trans_send(
		frame,		/* mem_ctx */
		ev,		/* ev */
		cli,		/* cli */
		0,		/* additional_flags2 */
		trans_cmd,	/* cmd */
		pipe_name, fid, function, flags,
		setup, num_setup, max_setup,
		param, num_param, max_param,
		data, num_data, max_data);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_trans_recv(
		req, mem_ctx, recv_flags2,
		rsetup, min_rsetup, num_rsetup,
		rparam, min_rparam, num_rparam,
		rdata, min_rdata, num_rdata);
fail:
	TALLOC_FREE(frame);
	return status;
}
