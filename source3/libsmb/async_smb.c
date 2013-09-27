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
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "../libcli/smb/smbXcli_base.h"

struct cli_smb_req_state {
	struct cli_state *cli;
	uint8_t smb_command;
	struct tevent_req *req;
	struct cli_smb_req_state **ptr;
};

static int cli_smb_req_state_destructor(struct cli_smb_req_state *state)
{
	talloc_set_destructor(state->ptr, NULL);
	talloc_free(state->ptr);
	return 0;
}

static int cli_smb_req_state_ptr_destructor(struct cli_smb_req_state **ptr)
{
	struct cli_smb_req_state *state = *ptr;
	void *parent = talloc_parent(state);

	talloc_set_destructor(state, NULL);

	talloc_reparent(state, parent, state->req);
	talloc_free(state);
	return 0;
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
	struct cli_smb_req_state *state;
	uint8_t clear_flags = 0;
	uint16_t additional_flags2 = 0;
	uint16_t clear_flags2 = 0;

	state = talloc_zero(mem_ctx, struct cli_smb_req_state);
	if (state == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->smb_command = smb_command;
	state->ptr = talloc(state, struct cli_smb_req_state *);
	if (state->ptr == NULL) {
		talloc_free(state);
		return NULL;
	}
	*state->ptr = state;

	state->req = smb1cli_req_create(state, ev, cli->conn, smb_command,
					additional_flags, clear_flags,
					additional_flags2, clear_flags2,
					cli->timeout,
					cli->smb1.pid,
					cli->smb1.tcon,
					cli->smb1.session,
					wct, vwv, iov_count, bytes_iov);
	if (state->req == NULL) {
		talloc_free(state);
		return NULL;
	}

	talloc_reparent(state, state->req, state->ptr);
	talloc_set_destructor(state, cli_smb_req_state_destructor);
	talloc_set_destructor(state->ptr, cli_smb_req_state_ptr_destructor);

	return state->req;
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
	struct cli_smb_req_state *state;
	uint8_t clear_flags = 0;
	uint16_t additional_flags2 = 0;
	uint16_t clear_flags2 = 0;

	state = talloc_zero(mem_ctx, struct cli_smb_req_state);
	if (state == NULL) {
		return NULL;
	}
	state->cli = cli;
	state->smb_command = smb_command;
	state->ptr = talloc(state, struct cli_smb_req_state *);
	if (state->ptr == NULL) {
		talloc_free(state);
		return NULL;
	}
	*state->ptr = state;

	state->req = smb1cli_req_send(state, ev, cli->conn, smb_command,
				additional_flags, clear_flags,
				additional_flags2, clear_flags2,
				cli->timeout,
				cli->smb1.pid,
				cli->smb1.tcon,
				cli->smb1.session,
				wct, vwv, num_bytes, bytes);
	if (state->req == NULL) {
		talloc_free(state);
		return NULL;
	}

	talloc_reparent(state, state->req, state->ptr);
	talloc_set_destructor(state, cli_smb_req_state_destructor);
	talloc_set_destructor(state->ptr, cli_smb_req_state_ptr_destructor);

	return state->req;
}

NTSTATUS cli_smb_recv(struct tevent_req *req,
		      TALLOC_CTX *mem_ctx, uint8_t **pinbuf,
		      uint8_t min_wct, uint8_t *pwct, uint16_t **pvwv,
		      uint32_t *pnum_bytes, uint8_t **pbytes)
{
	NTSTATUS status;
	void *parent = talloc_parent(req);
	struct cli_smb_req_state *state =
		talloc_get_type(parent,
		struct cli_smb_req_state);
	struct iovec *recv_iov = NULL;
	uint8_t wct = 0;
	uint16_t *vwv = NULL;
	uint32_t num_bytes;
	uint8_t *bytes = NULL;
	uint8_t *inbuf;
	bool is_expected = false;
	bool map_dos_errors = true;

	if (pinbuf != NULL) {
		*pinbuf = NULL;
	}
	if (pwct != NULL) {
		*pwct = 0;
	}
	if (pvwv != NULL) {
		*pvwv = NULL;
	}
	if (pnum_bytes != NULL) {
		*pnum_bytes = 0;
	}
	if (pbytes != NULL) {
		*pbytes = NULL;
	}

	status = smb1cli_req_recv(req, req,
				  &recv_iov,
				  NULL, /* phdr */
				  &wct,
				  &vwv,
				  NULL, /* pvwv_offset */
				  &num_bytes,
				  &bytes,
				  NULL, /* pbytes_offset */
				  &inbuf,
				  NULL, 0); /* expected */

	if (state) {
		if ((state->smb_command == SMBsesssetupX) &&
		     NT_STATUS_EQUAL(status,
				NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			/*
			 * NT_STATUS_MORE_PROCESSING_REQUIRED is a
			 * valid return code for session setup
			 */
			is_expected = true;
		}

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

	if (!NT_STATUS_IS_ERR(status)) {
		is_expected = true;
	}

	if (!is_expected) {
		TALLOC_FREE(recv_iov);
		return status;
	}

	if (wct < min_wct) {
		TALLOC_FREE(recv_iov);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (pwct != NULL) {
		*pwct = wct;
	}
	if (pvwv != NULL) {
		*pvwv = vwv;
	}
	if (pnum_bytes != NULL) {
		*pnum_bytes = num_bytes;
	}
	if (pbytes != NULL) {
		*pbytes = bytes;
	}

	if (pinbuf != NULL && mem_ctx != NULL) {
		if (talloc_reference_count(inbuf) == 0) {
			*pinbuf = talloc_move(mem_ctx, &inbuf);
			TALLOC_FREE(recv_iov);
		} else {
			*pinbuf = inbuf;
		}
	} else if (mem_ctx != NULL) {
		if (talloc_reference_count(inbuf) == 0) {
			(void)talloc_move(mem_ctx, &inbuf);
			TALLOC_FREE(recv_iov);
		}
	}

	return status;
}
