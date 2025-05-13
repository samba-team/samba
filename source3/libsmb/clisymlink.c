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
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "../lib/util/tevent_ntstatus.h"
#include "async_smb.h"
#include "libsmb/clirap.h"
#include "trans2.h"
#include "libcli/security/secdesc.h"
#include "libcli/security/security.h"
#include "../libcli/smb/smbXcli_base.h"
#include "libcli/smb/reparse.h"

struct cli_create_reparse_point_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	DATA_BLOB reparse_blob;
	uint16_t fnum;
	NTSTATUS set_reparse_status;
};

static void cli_create_reparse_point_opened(struct tevent_req *subreq);
static void cli_create_reparse_point_done(struct tevent_req *subreq);
static void cli_create_reparse_point_doc_done(struct tevent_req *subreq);
static void cli_create_reparse_point_closed(struct tevent_req *subreq);

struct tevent_req *cli_create_reparse_point_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct cli_state *cli,
						 const char *fname,
						 DATA_BLOB reparse_blob)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_create_reparse_point_state *state = NULL;

	req = tevent_req_create(mem_ctx,
				&state,
				struct cli_create_reparse_point_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->reparse_blob = reparse_blob;

	/*
	 * The create arguments were taken from a Windows->Windows
	 * symlink create call.
	 */
	subreq = cli_ntcreate_send(
		state,
		ev,
		cli,
		fname,
		0,
		SYNCHRONIZE_ACCESS | DELETE_ACCESS | FILE_READ_ATTRIBUTES |
			FILE_WRITE_ATTRIBUTES,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_NONE,
		FILE_CREATE,
		FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT |
			FILE_NON_DIRECTORY_FILE,
		SMB2_IMPERSONATION_IMPERSONATION,
		0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_create_reparse_point_opened, req);
	return req;
}

static void cli_create_reparse_point_opened(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct cli_create_reparse_point_state *state =
		tevent_req_data(req, struct cli_create_reparse_point_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->fnum, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = cli_fsctl_send(state,
				state->ev,
				state->cli,
				state->fnum,
				FSCTL_SET_REPARSE_POINT,
				&state->reparse_blob,
				0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_create_reparse_point_done, req);
}

static void cli_create_reparse_point_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_create_reparse_point_state *state =
		tevent_req_data(req, struct cli_create_reparse_point_state);

	state->set_reparse_status = cli_fsctl_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);

	if (NT_STATUS_IS_OK(state->set_reparse_status)) {
		subreq = cli_close_send(state,
					state->ev,
					state->cli,
					state->fnum,
					0);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					cli_create_reparse_point_closed,
					req);
		return;
	}
	subreq = cli_nt_delete_on_close_send(
		state, state->ev, state->cli, state->fnum, true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				cli_create_reparse_point_doc_done,
				req);
}

static void cli_create_reparse_point_doc_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_create_reparse_point_state *state =
		tevent_req_data(req, struct cli_create_reparse_point_state);

	/*
	 * Ignore status, we can't do much anyway in case of failure
	 */

	(void)cli_nt_delete_on_close_recv(subreq);
	TALLOC_FREE(subreq);

	subreq = cli_close_send(state, state->ev, state->cli, state->fnum, 0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_create_reparse_point_closed, req);
}

static void cli_create_reparse_point_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_create_reparse_point_state *state =
		tevent_req_data(req, struct cli_create_reparse_point_state);
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

NTSTATUS cli_create_reparse_point_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct cli_symlink_state {
	uint8_t dummy;
};

static void cli_symlink_done(struct tevent_req *subreq);

struct tevent_req *cli_symlink_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli,
				    const char *link_target,
				    const char *newpath,
				    uint32_t flags)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_symlink_state *state = NULL;
	struct reparse_data_buffer reparse_buf = {
		.tag = IO_REPARSE_TAG_SYMLINK,
		.parsed.lnk.substitute_name =
			discard_const_p(char, link_target),
		.parsed.lnk.print_name = discard_const_p(char, link_target),
		.parsed.lnk.flags = flags,
	};
	uint8_t *buf;
	ssize_t buflen;

	req = tevent_req_create(mem_ctx, &state, struct cli_symlink_state);
	if (req == NULL) {
		return NULL;
	}

	buflen = reparse_data_buffer_marshall(&reparse_buf, NULL, 0);
	if (buflen == -1) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	buf = talloc_array(state, uint8_t, buflen);
	if (tevent_req_nomem(buf, req)) {
		return tevent_req_post(req, ev);
	}

	buflen = reparse_data_buffer_marshall(&reparse_buf, buf, buflen);
	if (buflen != talloc_array_length(buf)) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	subreq = cli_create_reparse_point_send(state,
					       ev,
					       cli,
					       newpath,
					       (DATA_BLOB){
						       .data = buf,
						       .length = buflen,
					       });
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_symlink_done, req);
	return req;
}

static void cli_symlink_done(struct tevent_req *subreq)
{
	NTSTATUS status = cli_symlink_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
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

struct cli_get_reparse_data_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t fnum;

	NTSTATUS get_reparse_status;
	uint8_t *data;
	uint32_t datalen;
};

static void cli_get_reparse_data_opened(struct tevent_req *subreq);
static void cli_get_reparse_data_done(struct tevent_req *subreq);
static void cli_get_reparse_data_closed(struct tevent_req *subreq);

struct tevent_req *cli_get_reparse_data_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct cli_state *cli,
					     const char *fname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_get_reparse_data_state *state = NULL;

	req = tevent_req_create(mem_ctx,
				&state,
				struct cli_get_reparse_data_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	subreq = cli_ntcreate_send(state,
				   ev,
				   cli,
				   fname,
				   0,
				   FILE_READ_ATTRIBUTES | FILE_READ_EA,
				   0,
				   FILE_SHARE_READ | FILE_SHARE_WRITE |
					   FILE_SHARE_DELETE,
				   FILE_OPEN,
				   FILE_OPEN_REPARSE_POINT,
				   SMB2_IMPERSONATION_IMPERSONATION,
				   0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_get_reparse_data_opened, req);
	return req;
}

static void cli_get_reparse_data_opened(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct cli_get_reparse_data_state *state =
		tevent_req_data(req, struct cli_get_reparse_data_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->fnum, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = cli_fsctl_send(state,
				state->ev,
				state->cli,
				state->fnum,
				FSCTL_GET_REPARSE_POINT,
				NULL,
				65536);

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_get_reparse_data_done, req);
}

static void cli_get_reparse_data_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct cli_get_reparse_data_state *state =
		tevent_req_data(req, struct cli_get_reparse_data_state);
	DATA_BLOB out = {
		.data = NULL,
	};

	state->get_reparse_status = cli_fsctl_recv(subreq, state, &out);
	TALLOC_FREE(subreq);

	if (NT_STATUS_IS_OK(state->get_reparse_status)) {
		state->data = out.data;
		state->datalen = out.length;
	}

	subreq = cli_close_send(state, state->ev, state->cli, state->fnum, 0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_get_reparse_data_closed, req);
}

static void cli_get_reparse_data_closed(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq, struct tevent_req);
	struct cli_get_reparse_data_state *state =
		tevent_req_data(req, struct cli_get_reparse_data_state);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (tevent_req_nterror(req, state->get_reparse_status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_get_reparse_data_recv(struct tevent_req *req,
				   TALLOC_CTX *mem_ctx,
				   uint8_t **_data,
				   uint32_t *_datalen)
{
	struct cli_get_reparse_data_state *state =
		tevent_req_data(req, struct cli_get_reparse_data_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	*_data = talloc_move(mem_ctx, &state->data);
	*_datalen = state->datalen;

	tevent_req_received(req);

	return NT_STATUS_OK;
}

NTSTATUS cli_get_reparse_data(struct cli_state *cli,
			      const char *fname,
			      TALLOC_CTX *mem_ctx,
			      uint8_t **_data,
			      uint32_t *_datalen)
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
	req = cli_get_reparse_data_send(frame, ev, cli, fname);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = cli_get_reparse_data_recv(req, mem_ctx, _data, _datalen);
fail:
	TALLOC_FREE(frame);
	return status;
}

struct cli_readlink_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t fnum;

	uint16_t setup[4];
	uint8_t *data;
	uint32_t num_data;
	char *target;
};

static void cli_readlink_posix1_done(struct tevent_req *subreq);
static void cli_readlink_got_reparse_data(struct tevent_req *subreq);

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

	if (cli->requested_posix_capabilities != 0) {
		/*
		 * Only happens for negotiated SMB1 posix caps
		 */
		subreq = cli_posix_readlink_send(state, ev, cli, fname);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_readlink_posix1_done, req);
		return req;
	}

	subreq = cli_get_reparse_data_send(state, ev, cli, fname);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_readlink_got_reparse_data, req);
	return req;
}

static void cli_readlink_posix1_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_readlink_state *state = tevent_req_data(
		req, struct cli_readlink_state);
	NTSTATUS status;

	status = cli_posix_readlink_recv(subreq, state, &state->target);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static void cli_readlink_got_reparse_data(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_readlink_state *state = tevent_req_data(
		req, struct cli_readlink_state);
	NTSTATUS status;

	status = cli_get_reparse_data_recv(subreq,
					   state,
					   &state->data,
					   &state->num_data);
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
	struct reparse_data_buffer buf = {
		.tag = 0,
	};
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (state->target != NULL) {
		/*
		 * SMB1 posix version
		 */
		if (psubstitute_name != NULL) {
			*psubstitute_name = talloc_move(
				mem_ctx, &state->target);
		}
		if (pprint_name != NULL) {
			*pprint_name = NULL;
		}
		if (pflags != NULL) {
			*pflags = 0;
		}
		return NT_STATUS_OK;
	}

	status = reparse_data_buffer_parse(state,
					   &buf,
					   state->data,
					   state->num_data);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	if (buf.tag != IO_REPARSE_TAG_SYMLINK) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (psubstitute_name != NULL) {
		*psubstitute_name =
			talloc_move(mem_ctx, &buf.parsed.lnk.substitute_name);
	}

	if (pprint_name != NULL) {
		*pprint_name =
			talloc_move(mem_ctx, &buf.parsed.lnk.print_name);
	}

	if (pflags != NULL) {
		*pflags = buf.parsed.lnk.flags;
	}

	tevent_req_received(req);

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
