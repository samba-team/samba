/*
   Unix SMB/CIFS implementation.
   Test smbd chain routines

   Copyright (C) Volker Lendecke 2012

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
#include "torture/proto.h"
#include "libsmb/libsmb.h"
#include "system/filesys.h"
#include "async_smb.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/security/security.h"
#include "libcli/smb/smbXcli_base.h"

struct chain3_andx_state {
	uint16_t fnum;
	size_t written;
	char str[6];
};

static void chain3_andx_open_done(struct tevent_req *subreq);
static void chain3_andx_write_done(struct tevent_req *subreq);
static void chain3_andx_close_done(struct tevent_req *subreq);

static struct tevent_req *chain3_andx_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct cli_state *cli,
					   const char *fname)
{
	struct tevent_req *req, *subreq;
	struct tevent_req *smbreqs[3];
	struct chain3_andx_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct chain3_andx_state);
	if (req == NULL) {
		return NULL;
	}

	strlcpy(state->str, "hello", sizeof(state->str));

	subreq = cli_openx_create(state, ev, cli, fname,
				  O_CREAT|O_RDWR, 0, &smbreqs[0]);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, chain3_andx_open_done, req);

	subreq = cli_write_andx_create(state, ev, cli, 0, 0,
				       (const uint8_t *)state->str, 0,
				       strlen(state->str)+1,
				       smbreqs, 1, &smbreqs[1]);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, chain3_andx_write_done, req);

	subreq = cli_close_create(state, ev, cli, 0, &smbreqs[2]);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, chain3_andx_close_done, req);

	status = smb1cli_req_chain_submit(smbreqs, ARRAY_SIZE(smbreqs));
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void chain3_andx_open_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct chain3_andx_state *state = tevent_req_data(
		req, struct chain3_andx_state);
	NTSTATUS status;

	status = cli_openx_recv(subreq, &state->fnum);
	printf("cli_openx returned %s, fnum=%u\n", nt_errstr(status),
	       (unsigned)state->fnum);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
}

static void chain3_andx_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct chain3_andx_state *state = tevent_req_data(
		req, struct chain3_andx_state);
	NTSTATUS status;

	status = cli_write_andx_recv(subreq, &state->written);
	printf("cli_write_andx returned %s, written=%u\n", nt_errstr(status),
	       (unsigned)state->written);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
}

static void chain3_andx_close_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	printf("cli_close returned %s\n", nt_errstr(status));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS chain3_andx_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct chain3_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *fname;
	uint16_t fnum;
};

static void chain3_got_break(struct tevent_req *subreq);
static void chain3_ntcreate_done(struct tevent_req *subreq);
static void chain3_break_close_done(struct tevent_req *subreq);
static void chain3_andx_done(struct tevent_req *subreq);

static struct tevent_req *chain3_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev)
{
	struct tevent_req *req, *subreq;
	struct chain3_state *state;

	req = tevent_req_create(mem_ctx, &state, struct chain3_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fname = "chain3.txt";

	if (!torture_open_connection(&state->cli, 0)) {
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_oplock_break_waiter_send(
		state, state->ev, state->cli);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, chain3_got_break, req);

	subreq = cli_ntcreate_send(
		state, state->ev, state->cli, state->fname,
		REQUEST_OPLOCK|REQUEST_BATCH_OPLOCK,
		GENERIC_READ_ACCESS|GENERIC_WRITE_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OVERWRITE_IF, 0, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, chain3_ntcreate_done, req);
	return req;
}

static void chain3_got_break(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct chain3_state *state = tevent_req_data(
		req, struct chain3_state);
	uint16_t fnum;
	uint8_t level;
	NTSTATUS status;

	status = cli_smb_oplock_break_waiter_recv(subreq, &fnum, &level);
	TALLOC_FREE(subreq);
	printf("cli_smb_oplock_break_waiter_recv returned %s\n",
	       nt_errstr(status));
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = cli_close_send(state, state->ev, state->cli, fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, chain3_break_close_done, req);
}

static void chain3_break_close_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	printf("cli_close_recv returned %s\n", nt_errstr(status));
	if (tevent_req_nterror(req, status)) {
		return;
	}
}

static void chain3_ntcreate_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct chain3_state *state = tevent_req_data(
		req, struct chain3_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->fnum, NULL);
	TALLOC_FREE(subreq);
	printf("cli_ntcreate returned %s, fnum=%u\n", nt_errstr(status),
	       (unsigned)state->fnum);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = chain3_andx_send(state, state->ev, state->cli, state->fname);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, chain3_andx_done, req);
}

static void chain3_andx_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = chain3_andx_recv(subreq);
	TALLOC_FREE(subreq);
	printf("chain3_andx_recv returned %s\n", nt_errstr(status));
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS chain3_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

bool run_chain3(int dummy)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = chain3_send(frame, ev);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = chain3_recv(req);
fail:
	TALLOC_FREE(frame);
	printf("run_chain3 returns %s\n", nt_errstr(status));
	return NT_STATUS_IS_OK(status);
}
