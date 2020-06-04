/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2020
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
#include "torture/proto.h"
#include "libsmb/libsmb.h"
#include "libsmb/clirap.h"
#include "lib/util/tevent_ntstatus.h"

extern int torture_nprocs;
extern int torture_numops;

struct create_ts_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	unsigned timestamp_idx;
	uint16_t fnum;
};

static void create_ts_opened(struct tevent_req *subreq);
static void create_ts_setinfo_done(struct tevent_req *subreq);
static void create_ts_waited(struct tevent_req *subreq);
static void create_ts_written(struct tevent_req *subreq);
static void create_ts_doc_done(struct tevent_req *subreq);

static struct tevent_req *create_ts_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *fname,
	unsigned timestamp_idx)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct create_ts_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct create_ts_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->timestamp_idx = timestamp_idx;

	subreq = cli_ntcreate_send(
		state,
		ev,
		cli,
		fname,
		0,			/* CreatFlags */
		SEC_FILE_WRITE_ATTRIBUTE|
		SEC_FILE_WRITE_DATA|
		SEC_STD_DELETE,		/* DesiredAccess */
		FILE_ATTRIBUTE_NORMAL,  /* FileAttributes */
		FILE_SHARE_WRITE|FILE_SHARE_READ, /* ShareAccess */
		FILE_OPEN_IF,		 /* CreateDisposition */
		FILE_NON_DIRECTORY_FILE, /* CreateOptions */
		0,			 /* Impersonation */
		0);			 /* SecurityFlags */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, create_ts_opened, req);
	return req;
}

static void create_ts_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct create_ts_state *state = tevent_req_data(
		req, struct create_ts_state);
	struct smb_create_returns cr;
	struct timespec mtime;
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->fnum, &cr);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	mtime = nt_time_to_unix_timespec(cr.last_write_time);

	mtime.tv_sec &= ~(0xFFFFULL);
	mtime.tv_sec |= (state->timestamp_idx & 0xFFFF);

	subreq = cli_setfileinfo_ext_send(
		state,
		state->ev,
		state->cli,
		state->fnum,
		(struct timespec) { .tv_nsec = SAMBA_UTIME_OMIT }, /* create */
		(struct timespec) { .tv_nsec = SAMBA_UTIME_OMIT }, /* access */
		mtime,
		(struct timespec) { .tv_nsec = SAMBA_UTIME_OMIT }, /* change */
		UINT32_MAX);	/* attr */
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, create_ts_setinfo_done, req);
}

static void create_ts_setinfo_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct create_ts_state *state = tevent_req_data(
		req, struct create_ts_state);
	NTSTATUS status;

	status = cli_setfileinfo_ext_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = tevent_wakeup_send(
		state, state->ev, timeval_current_ofs_msec(100));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, create_ts_waited, req);
}

static void create_ts_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct create_ts_state *state = tevent_req_data(
		req, struct create_ts_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(subreq);
		return;
	}

	subreq = cli_write_send(
		state,
		state->ev,
		state->cli,
		state->fnum,
		0,
		(uint8_t *)&state->fnum,
		0,
		sizeof(state->fnum));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, create_ts_written, req);
}

static void create_ts_written(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct create_ts_state *state = tevent_req_data(
		req, struct create_ts_state);
	size_t written;
	NTSTATUS status;

	status = cli_write_recv(subreq, &written);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(subreq, status)) {
		return;
	}

	subreq = cli_nt_delete_on_close_send(
		state, state->ev, state->cli, state->fnum, true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, create_ts_doc_done, req);
}

static void create_ts_doc_done(struct tevent_req *subreq)
{
	NTSTATUS status = cli_nt_delete_on_close_recv(subreq);
	tevent_req_simple_finish_ntstatus(subreq, status);
}

static NTSTATUS create_ts_recv(struct tevent_req *req, uint16_t *fnum)
{
	struct create_ts_state *state = tevent_req_data(
		req, struct create_ts_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*fnum = state->fnum;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct create_ts_files_state {
	size_t num_files;
	size_t num_received;
	uint16_t *fnums;
};

static void create_ts_files_done(struct tevent_req *subreq);

static struct tevent_req *create_ts_files_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *prefix,
	size_t idx,
	size_t num_files)
{
	struct tevent_req *req = NULL;
	struct create_ts_files_state *state = NULL;
	size_t i;

	req = tevent_req_create(mem_ctx, &state, struct create_ts_files_state);
	if (req == NULL) {
		return NULL;
	}
	state->num_files = num_files;

	state->fnums = talloc_array(state, uint16_t, num_files);
	if (tevent_req_nomem(state->fnums, req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<num_files; i++) {
		struct tevent_req *subreq = NULL;
		const char *fname = NULL;

		fname = talloc_asprintf(state, "%s%zu_%zu", prefix, idx, i);
		if (tevent_req_nomem(fname, req)) {
			return tevent_req_post(req, ev);
		}

		subreq = create_ts_send(state, ev, cli, fname, i);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		talloc_steal(subreq, fname);

		tevent_req_set_callback(subreq, create_ts_files_done, req);
	}
	return req;
}

static void create_ts_files_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct create_ts_files_state *state = tevent_req_data(
		req, struct create_ts_files_state);
	NTSTATUS status;

	status = create_ts_recv(subreq, &state->fnums[state->num_received]);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->num_received += 1;
	if (state->num_received == state->num_files) {
		tevent_req_done(req);
	}
}

static NTSTATUS create_ts_files_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx, uint16_t **fnums)
{
	struct create_ts_files_state *state = tevent_req_data(
		req, struct create_ts_files_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*fnums = talloc_move(mem_ctx, &state->fnums);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct create_files_state {
	size_t num_reqs;
	size_t num_received;
	struct tevent_req **reqs;
	uint16_t **fnums;
};

static void create_files_done(struct tevent_req *subreq);

static struct tevent_req *create_files_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state **cli,
	size_t num_cli,
	const char *prefix,
	size_t num_files)
{
	struct tevent_req *req = NULL;
	struct create_files_state *state = NULL;
	size_t i;

	req = tevent_req_create(mem_ctx, &state, struct create_files_state);
	if (req == NULL) {
		return NULL;
	}
	state->num_reqs = num_cli;

	state->reqs = talloc_array(state, struct tevent_req *, num_cli);
	if (tevent_req_nomem(state->reqs, req)) {
		return tevent_req_post(req, ev);
	}
	state->fnums = talloc_array(state, uint16_t *, num_cli);
	if (tevent_req_nomem(state->fnums, req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<num_cli; i++) {
		state->reqs[i] = create_ts_files_send(
			state, ev, cli[i], prefix, i, num_files);
		if (tevent_req_nomem(state->reqs[i], req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			state->reqs[i], create_files_done, req);
	}
	return req;
}

static void create_files_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct create_files_state *state = tevent_req_data(
		req, struct create_files_state);
	uint16_t *fnums = NULL;
	NTSTATUS status;
	size_t i;

	status = create_ts_files_recv(subreq, state->fnums, &fnums);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	for (i=0; i<state->num_reqs; i++) {
		if (state->reqs[i] == subreq) {
			break;
		}
	}
	if (i == state->num_reqs) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	TALLOC_FREE(subreq);
	state->reqs[i] = NULL;
	state->fnums[i] = fnums;

	state->num_received += 1;

	if (state->num_reqs == state->num_received) {
		tevent_req_done(req);
	}
}

static NTSTATUS create_files_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx, uint16_t ***fnums)
{
	struct create_files_state *state = tevent_req_data(
		req, struct create_files_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	*fnums = talloc_move(mem_ctx, &state->fnums);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct list_cb_state {
	size_t found;
	bool ok;
};

static NTSTATUS list_cb(
	const char *mntpoint,
	struct file_info *f,
	const char *mask,
	void *private_data)
{
	struct list_cb_state *state = private_data;
	char *underbar = NULL;
	unsigned long long int name_idx;
	int err;

	underbar = strchr(f->name, '_');
	if (underbar == NULL) {
		/* alien filename, . or ..? */
		return NT_STATUS_OK;
	}

	name_idx = smb_strtoull(underbar+1, NULL, 10, &err, SMB_STR_STANDARD);
	if (err != 0) {
		/* non-numeric? */
		return NT_STATUS_OK;
	}

	if ((name_idx & 0xFFFF) != (f->mtime_ts.tv_sec & 0xFFFF)) {
		d_printf("idx=%llu, nsec=%ld\n",
			 name_idx,
			 f->mtime_ts.tv_nsec);
		state->ok = false;
	}
	state->found += 1;

	return NT_STATUS_OK;
}

bool run_readdir_timestamp(int dummy)
{
	struct cli_state **cli = NULL;
	int i;
	bool ret = false;
	bool ok;
	const char prefix[] = "readdir_ts/";
	struct list_cb_state state = { .ok = true };
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	uint16_t **fnums = NULL;
	NTSTATUS status;
	size_t expected;

	cli = talloc_array(talloc_tos(), struct cli_state *, torture_nprocs);
	if (cli == NULL) {
		d_printf("talloc_array failed\n");
		goto fail;
	}

	for (i=0; i<torture_nprocs; i++) {
	        ok = torture_open_connection_flags(&cli[i], i, 0);
		if (!ok) {
			d_printf("torture_open_connection_flags(%d) failed\n",
				 i);
			goto fail;
		}
	}

	status = cli_mkdir(cli[0], "readdir_ts");
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_mkdir failed: %s\n", nt_errstr(status));
		goto fail;
	}

	ev = samba_tevent_context_init(cli);
	if (ev == NULL) {
		d_printf("samba_tevent_context_init() failed\n");
		goto fail;
	}

	req = create_files_send(
		cli, ev, cli, torture_nprocs, prefix, torture_numops);
	if (req == NULL) {
		d_printf("create_files_send() failed\n");
		goto fail;
	}

	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		d_printf("tevent_req_poll_ntstatus failed: %s\n",
			 nt_errstr(status));
		goto fail;
	}

	status = create_files_recv(req, talloc_tos(), &fnums);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("create_files_recv failed: %s\n",
			 nt_errstr(status));
		goto fail;
	}

	status = cli_list(cli[0],
			  "readdir_ts\\*",
			  FILE_ATTRIBUTE_DIRECTORY |
			  FILE_ATTRIBUTE_SYSTEM |
			  FILE_ATTRIBUTE_HIDDEN,
			  list_cb,
			  &state);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_list failed: %s\n",
			 nt_errstr(status));
		goto fail;
	}

	expected = torture_nprocs * torture_numops;
	if (state.found != expected) {
		d_printf("Expected %zu, got %zu files\n",
			 expected,
			 state.found);
		goto fail;
	}
	if (!state.ok) {
		d_printf("timestamp mismatch\n");
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(cli);
	return ret;
}
