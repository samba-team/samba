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
#include "ntioctl.h"
#include "libcli/security/secdesc.h"
#include "libcli/security/security.h"

struct cli_symlink_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *oldpath;
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
				    const char *oldpath,
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
	state->oldpath = oldpath;
	state->newpath = newpath;
	state->flags = flags;

	subreq = cli_ntcreate_send(
		state, ev, cli, state->oldpath, 0,
		SYNCHRONIZE_ACCESS|DELETE_ACCESS|
		FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, FILE_CREATE,
		FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT|
		FILE_NON_DIRECTORY_FILE, 0);
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
	uint8_t *data;
	size_t data_len;
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->fnum);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	SIVAL(state->setup, 0, FSCTL_SET_REPARSE_POINT);
	SSVAL(state->setup, 4, state->fnum);
	SCVAL(state->setup, 6, 1); /* IsFcntl */
	SCVAL(state->setup, 7, 0); /* IsFlags */

	if (!symlink_reparse_buffer_marshall(
		    state->newpath, NULL, state->flags, state,
		    &data, &data_len)) {
		tevent_req_oom(req);
		return;
	}

	subreq = cli_trans_send(state, state->ev, state->cli, SMBnttrans,
				NULL, -1, /* name, fid */
				NT_TRANSACT_IOCTL, 0,
				state->setup, 4, 0, /* setup */
				NULL, 0, 0,	    /* param */
				data, data_len, 0); /* data */
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

	state->set_reparse_status = cli_trans_recv(
		subreq, NULL, NULL,
		NULL, 0, NULL,	/* rsetup */
		NULL, 0, NULL,	/* rparam */
		NULL, 0, NULL);	/* rdata */
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
	NTSTATUS status;

	status = cli_nt_delete_on_close_recv(subreq);
	TALLOC_FREE(subreq);

	/*
	 * Ignore status, we can't do much anyway in case of failure
	 */

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

NTSTATUS cli_symlink(struct cli_state *cli, const char *oldname,
		     const char *newname, uint32_t flags)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (cli_has_async_calls(cli)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = event_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = cli_symlink_send(frame, ev, cli, oldname, newname, flags);
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
