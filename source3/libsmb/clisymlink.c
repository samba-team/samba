/*
 * Unix SMB/CIFS implementation.
 * Client implementation of setting symlinks using reparse points
 * Copyright (C) Volker Lendecke 2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "system/filesys.h"
#include "libsmb/libsmb.h"
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "libsmb/clirap.h"
#include "trans2.h"
#include "libcli/security/secdesc.h"
#include "libcli/security/security.h"
#include "../libcli/smb/smbXcli_base.h"

struct cli_symlink_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *link_target;
	const char *newpath;
	uint32_t flags;

	uint16_t fnum;

	uint16_t setup[4];
	NTSTATUS set_reparse_status;
};

static void cli_symlink_create_done(struct tevent_req *subreq);
static void cli_symlink_set_reparse_done(struct tevent_req *subreq);
static void cli_symlink_delete_on_close_done(struct tevent_req *subreq);
static void cli_symlink_close_done(struct tevent_req *subreq);

struct tevent_req *cli_symlink_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli,
				    const char *link_target,
				    const char *newpath,
				    uint32_t flags)
{
	struct tevent_req *req, *subreq;
	struct cli_symlink_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_symlink_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->link_target = link_target;
	state->newpath = newpath;
	state->flags = flags;

	subreq = cli_ntcreate_send(
		state, ev, cli, state->newpath, 0,
		SYNCHRONIZE_ACCESS|DELETE_ACCESS|
		FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, FILE_CREATE,
		FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT|
		FILE_NON_DIRECTORY_FILE,
		SMB2_IMPERSONATION_IMPERSONATION, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_symlink_create_done, req);
	return req;
}

static void cli_symlink_create_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_symlink_state *state = tevent_req_data(
		req, struct cli_symlink_state);
	DATA_BLOB data;
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->fnum, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (!symlink_reparse_buffer_marshall(
		    state->link_target, NULL, state->flags, state,
		    &data.data, &data.length)) {
		tevent_req_oom(req);
		return;
	}

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		subreq = cli_smb2_set_reparse_point_fnum_send(state,
						state->ev,
						state->cli,
						state->fnum,
						data);
	} else {
		SIVAL(state->setup, 0, FSCTL_SET_REPARSE_POINT);
		SSVAL(state->setup, 4, state->fnum);
		SCVAL(state->setup, 6, 1); /* IsFcntl */
		SCVAL(state->setup, 7, 0); /* IsFlags */


		subreq = cli_trans_send(state, state->ev, state->cli, 0,
				SMBnttrans,
				NULL, -1, /* name, fid */
				NT_TRANSACT_IOCTL, 0,
				state->setup, 4, 0, /* setup */
				NULL, 0, 0,	    /* param */
				data.data, data.length, 0); /* data */
	}

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_symlink_set_reparse_done, req);
}

static void cli_symlink_set_reparse_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_symlink_state *state = tevent_req_data(
		req, struct cli_symlink_state);

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		state->set_reparse_status =
			cli_smb2_set_reparse_point_fnum_recv(subreq);
	} else {
		state->set_reparse_status = cli_trans_recv(
			subreq, NULL, NULL,
			NULL, 0, NULL,	/* rsetup */
			NULL, 0, NULL,	/* rparam */
			NULL, 0, NULL);	/* rdata */
	}
	TALLOC_FREE(subreq);

	if (NT_STATUS_IS_OK(state->set_reparse_status)) {
		subreq = cli_close_send(state, state->ev, state->cli,
					state->fnum);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, cli_symlink_close_done, req);
		return;
	}
	subreq = cli_nt_delete_on_close_send(
		state, state->ev, state->cli, state->fnum, true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_symlink_delete_on_close_done, req);
}

static void cli_symlink_delete_on_close_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_symlink_state *state = tevent_req_data(
		req, struct cli_symlink_state);

	/*
	 * Ignore status, we can't do much anyway in case of failure
	 */

	(void)cli_nt_delete_on_close_recv(subreq);
	TALLOC_FREE(subreq);

	subreq = cli_close_send(state, state->ev, state->cli, state->fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_symlink_close_done, req);
}

static void cli_symlink_close_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_symlink_state *state = tevent_req_data(
		req, struct cli_symlink_state);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);

	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (tevent_req_nterror(req, state->set_reparse_status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_symlink_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_symlink(struct cli_state *cli, const char *link_target,
		     const char *newname, uint32_t flags)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_symlink_send(frame, ev, cli, link_target, newname, flags);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_symlink_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_readlink_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t fnum;

	uint16_t setup[4];
	NTSTATUS get_reparse_status;
	uint8_t *data;
	uint32_t num_data;
};

static void cli_readlink_opened(struct tevent_req *subreq);
static void cli_readlink_got_reparse_data(struct tevent_req *subreq);
static void cli_readlink_closed(struct tevent_req *subreq);

struct tevent_req *cli_readlink_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli,
				     const char *fname)
{
	struct tevent_req *req, *subreq;
	struct cli_readlink_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_readlink_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	subreq = cli_ntcreate_send(
		state, ev, cli, fname, 0, FILE_READ_ATTRIBUTES | FILE_READ_EA,
		0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_OPEN_REPARSE_POINT,
		SMB2_IMPERSONATION_IMPERSONATION, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_readlink_opened, req);
	return req;
}

static void cli_readlink_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_readlink_state *state = tevent_req_data(
		req, struct cli_readlink_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->fnum, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		subreq = cli_smb2_get_reparse_point_fnum_send(state,
						state->ev,
						state->cli,
						state->fnum);
	} else {
		SIVAL(state->setup, 0, FSCTL_GET_REPARSE_POINT);
		SSVAL(state->setup, 4, state->fnum);
		SCVAL(state->setup, 6, 1); /* IsFcntl */
		SCVAL(state->setup, 7, 0); /* IsFlags */

		subreq = cli_trans_send(state, state->ev, state->cli,
				0, SMBnttrans,
				NULL, -1, /* name, fid */
				NT_TRANSACT_IOCTL, 0,
				state->setup, 4, 0, /* setup */
				NULL, 0, 0,	    /* param */
				NULL, 0, 16384); /* data */
	}

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_readlink_got_reparse_data, req);
}

static void cli_readlink_got_reparse_data(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_readlink_state *state = tevent_req_data(
		req, struct cli_readlink_state);

	if (smbXcli_conn_protocol(state->cli->conn) >= PROTOCOL_SMB2_02) {
		DATA_BLOB recv_data;
		state->get_reparse_status =
			cli_smb2_get_reparse_point_fnum_recv(subreq,
							state,
							&recv_data);
		if (NT_STATUS_IS_OK(state->get_reparse_status)) {
			state->data = recv_data.data;
			state->num_data = recv_data.length;
		}
	} else {
		state->get_reparse_status = cli_trans_recv(
			subreq, state, NULL,
			NULL, 0, NULL,	/* rsetup */
			NULL, 0, NULL,	/* rparam */
			&state->data, 20, &state->num_data); /* rdata */
	}
	TALLOC_FREE(subreq);

	subreq = cli_close_send(state, state->ev, state->cli, state->fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_readlink_closed, req);
}

static void cli_readlink_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_readlink_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   char **psubstitute_name, char **pprint_name,
			   uint32_t *pflags)
{
	struct cli_readlink_state *state = tevent_req_data(
		req, struct cli_readlink_state);
	NTSTATUS status;
	char *substitute_name;
	char *print_name;
	uint32_t flags;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (!symlink_reparse_buffer_parse(state->data, state->num_data,
					  talloc_tos(), &substitute_name,
					  &print_name, &flags)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (psubstitute_name != NULL) {
		*psubstitute_name = talloc_move(mem_ctx, &substitute_name);
	}
	TALLOC_FREE(substitute_name);

	if (pprint_name != NULL) {
		*pprint_name = talloc_move(mem_ctx, &print_name);
	}
	TALLOC_FREE(print_name);

	if (pflags != NULL) {
		*pflags = flags;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_readlink(struct cli_state *cli, const char *fname,
		       TALLOC_CTX *mem_ctx, char **psubstitute_name,
		      char **pprint_name, uint32_t *pflags)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_readlink_send(frame, ev, cli, fname);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_readlink_recv(req, mem_ctx, psubstitute_name,
				   pprint_name, pflags);
 fail:
	TALLOC_FREE(frame);
	return status;
}
