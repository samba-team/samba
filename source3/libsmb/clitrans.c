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
	struct tevent_req *req;
	struct cli_trans_state **ptr;
};

static int cli_trans_state_destructor(struct cli_trans_state *state)
{
	talloc_set_destructor(state->ptr, NULL);
	talloc_free(state->ptr);
	return 0;
}

static int cli_trans_state_ptr_destructor(struct cli_trans_state **ptr)
{
	struct cli_trans_state *state = *ptr;
	void *parent = talloc_parent(state);

	talloc_set_destructor(state, NULL);

	talloc_reparent(state, parent, state->req);
	talloc_free(state);
	return 0;
}

struct tevent_req *cli_trans_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct cli_state *cli, uint8_t cmd,
	const char *pipe_name, uint16_t fid, uint16_t function, int flags,
	uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
	uint8_t *param, uint32_t num_param, uint32_t max_param,
	uint8_t *data, uint32_t num_data, uint32_t max_data)
{
	struct cli_trans_state *state;
	uint8_t additional_flags = 0;
	uint8_t clear_flags = 0;
	uint16_t additional_flags2 = 0;
	uint16_t clear_flags2 = 0;

	state = talloc_zero(mem_ctx, struct cli_trans_state);
	if (state == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->ptr = talloc(state, struct cli_trans_state *);
	if (state->ptr == NULL) {
		talloc_free(state);
		return NULL;
	}
	*state->ptr = state;

	state->req = smb1cli_trans_send(state, ev,
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
	if (state->req == NULL) {
		talloc_free(state);
		return NULL;
	}

	talloc_reparent(state, state->req, state->ptr);
	talloc_set_destructor(state, cli_trans_state_destructor);
	talloc_set_destructor(state->ptr, cli_trans_state_ptr_destructor);

	return state->req;
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
	NTSTATUS status;
	void *parent = talloc_parent(req);
	struct cli_trans_state *state =
		talloc_get_type(parent,
		struct cli_trans_state);
	bool map_dos_errors = true;

	status = smb1cli_trans_recv(req, mem_ctx, recv_flags2,
				    setup, min_setup, num_setup,
				    param, min_param, num_param,
				    data, min_data, num_data);

	if (state) {
		map_dos_errors = state->cli->map_dos_errors;
		state->cli->raw_status = status;
		talloc_free(state->ptr);
		state = NULL;
	}

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
	NTSTATUS status;
	uint8_t additional_flags = 0;
	uint8_t clear_flags = 0;
	uint16_t additional_flags2 = 0;
	uint16_t clear_flags2 = 0;

	status = smb1cli_trans(mem_ctx,
			       cli->conn, trans_cmd,
			       additional_flags, clear_flags,
			       additional_flags2, clear_flags2,
			       cli->timeout,
			       cli->smb1.pid,
			       cli->smb1.tcon,
			       cli->smb1.session,
			       pipe_name, fid, function, flags,
			       setup, num_setup, max_setup,
			       param, num_param, max_param,
			       data, num_data, max_data,
			       recv_flags2,
			       rsetup, min_rsetup, num_rsetup,
			       rparam, min_rparam, num_rparam,
			       rdata, min_rdata, num_rdata);

	cli->raw_status = status;

	if (NT_STATUS_IS_DOS(status) && cli->map_dos_errors) {
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
