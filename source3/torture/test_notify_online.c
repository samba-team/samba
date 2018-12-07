/*
   Unix SMB/CIFS implementation.
   Make sure that for offline files pread and pwrite trigger a notify
   Copyright (C) Volker Lendecke 2011

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
#include "libcli/security/security.h"
#include "lib/util/tevent_ntstatus.h"
#include "libsmb/libsmb.h"

extern char *test_filename;

struct notify_online_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t dnum;
	const char *fname;
	uint16_t fnum;
	bool got_notify;
};

static void notify_online_opened_dir(struct tevent_req *subreq);
static void notify_online_notify_callback(struct tevent_req *subreq);
static void notify_online_opened_file(struct tevent_req *subreq);
static void notify_online_sent_read(struct tevent_req *subreq);
static void notify_online_sent_closefile(struct tevent_req *subreq);
static void notify_online_waited(struct tevent_req *subreq);
static void notify_online_sent_closedir(struct tevent_req *subreq);

static struct tevent_req *notify_online_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct cli_state *cli, const char *dname, const char *fname)
{
	struct tevent_req *req, *subreq;
	struct notify_online_state *state;

	req = tevent_req_create(mem_ctx, &state, struct notify_online_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->fname = fname;

	subreq = cli_ntcreate_send(
		state, ev, cli, dname, EXTENDED_RESPONSE_REQUIRED,
		SEC_FILE_READ_DATA, 0,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, 0, SMB2_IMPERSONATION_IMPERSONATION, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, notify_online_opened_dir, req);
	return req;
}

static void notify_online_opened_dir(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_online_state *state = tevent_req_data(
		req, struct notify_online_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->dnum, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = cli_notify_send(state, state->ev, state->cli, state->dnum,
				 128, FILE_NOTIFY_CHANGE_ATTRIBUTES, false);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_online_notify_callback, req);

	subreq = cli_ntcreate_send(
		state, state->ev, state->cli, state->fname, 0,
		GENERIC_READ_ACCESS, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, FILE_NON_DIRECTORY_FILE,
		SMB2_IMPERSONATION_IMPERSONATION, 0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_online_opened_file, req);
}

static void notify_online_notify_callback(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_online_state *state = tevent_req_data(
		req, struct notify_online_state);
	NTSTATUS status;
	uint32_t num_changes;
	struct notify_change *changes;

	status = cli_notify_recv(subreq, state, &num_changes, &changes);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if ((num_changes == 1)
	    && (changes[0].action == NOTIFY_ACTION_MODIFIED)
	    && (strcmp(changes[0].name, state->fname) == 0)) {
		state->got_notify = true;
	}
	tevent_req_done(req);
}

static void notify_online_opened_file(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_online_state *state = tevent_req_data(
		req, struct notify_online_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->fnum, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = cli_read_andx_send(
		state, state->ev, state->cli, state->fnum, 0, 1);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_online_sent_read, req);
}

static void notify_online_sent_read(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_online_state *state = tevent_req_data(
		req, struct notify_online_state);
	NTSTATUS status;
	ssize_t received;
	uint8_t *buf;

	status = cli_read_andx_recv(subreq, &received, &buf);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = cli_close_send(
		state, state->ev, state->cli, state->fnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_online_sent_closefile, req);
}

static void notify_online_sent_closefile(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_online_state *state = tevent_req_data(
		req, struct notify_online_state);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = tevent_wakeup_send(
		state, state->ev, timeval_current_ofs(10, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_online_waited, req);
}

static void notify_online_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_online_state *state = tevent_req_data(
		req, struct notify_online_state);

	tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	subreq = cli_close_send(
		state, state->ev, state->cli, state->dnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_online_sent_closedir, req);
}

static void notify_online_sent_closedir(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
}

static NTSTATUS notify_online_recv(struct tevent_req *req, bool *got_notify)
{
	struct notify_online_state *state = tevent_req_data(
		req, struct notify_online_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*got_notify = state->got_notify;
	return NT_STATUS_OK;
}

static NTSTATUS notify_online(struct cli_state *cli,
			      const char *dirname, const char *filename,
			      bool *got_notify)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = notify_online_send(frame, ev, cli, dirname, filename);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = notify_online_recv(req, got_notify);
 fail:
	TALLOC_FREE(frame);
	return status;
}

bool run_notify_online(int dummy)
{
	struct cli_state *cli;
	NTSTATUS status;
	char *p;
	const char *dir;
	const char *file;
	bool got_notify = false;

	printf("Starting NOTIFY_ONLINE\n");

	if (test_filename == NULL) {
		fprintf(stderr, "<-f filename> missing\n");
		return false;
	}

	if (!torture_open_connection(&cli, 0)) {
		return false;
	}

	p = strrchr(test_filename, '/');
	if (p != NULL) {
		dir = SMB_STRNDUP(test_filename, p-test_filename);
		file = SMB_STRDUP(p+1);
	} else {
		dir = "";
		file = test_filename;
	}

	status = notify_online(cli, dir, file, &got_notify);
	d_printf("notify_online returned %s (%d)\n", nt_errstr(status),
		 (int)got_notify);
	torture_close_connection(cli);
	return NT_STATUS_IS_OK(status) && got_notify;
}
