/*
   Unix SMB/CIFS implementation.
   Scalability test for notifies
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
#include "lib/util/tevent_ntstatus.h"
#include "libcli/security/security.h"
#include "lib/tevent_barrier.h"

extern int torture_nprocs, torture_numops;

struct wait_for_one_notify_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint16_t dnum;
	uint32_t filter;
	bool recursive;
	unsigned *num_notifies;
};

static void wait_for_one_notify_opened(struct tevent_req *subreq);
static void wait_for_one_notify_chkpath_done(struct tevent_req *subreq);
static void wait_for_one_notify_done(struct tevent_req *subreq);
static void wait_for_one_notify_closed(struct tevent_req *subreq);

static struct tevent_req *wait_for_one_notify_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct cli_state *cli,
						   const char *path,
						   uint32_t filter,
						   bool recursive,
						   unsigned *num_notifies)
{
	struct tevent_req *req, *subreq;
	struct wait_for_one_notify_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct wait_for_one_notify_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->filter = filter;
	state->recursive = recursive;
	state->num_notifies = num_notifies;

	subreq = cli_ntcreate_send(
		state, state->ev, state->cli, path, 0,
		MAXIMUM_ALLOWED_ACCESS,
		0, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, FILE_DIRECTORY_FILE, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wait_for_one_notify_opened, req);
	return req;
}

static void wait_for_one_notify_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wait_for_one_notify_state *state = tevent_req_data(
		req, struct wait_for_one_notify_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->dnum);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = cli_notify_send(state, state->ev, state->cli, state->dnum,
				 0xffff, state->filter, state->recursive);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wait_for_one_notify_done, req);

	/*
	 * To make sure the notify received at the server, we do another no-op
	 * that is replied to.
	 */
	subreq = cli_chkpath_send(state, state->ev, state->cli, "\\");
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wait_for_one_notify_chkpath_done, req);
}

static void wait_for_one_notify_chkpath_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wait_for_one_notify_state *state = tevent_req_data(
		req, struct wait_for_one_notify_state);
	NTSTATUS status;

	status = cli_chkpath_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	*state->num_notifies += 1;
}

static void wait_for_one_notify_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wait_for_one_notify_state *state = tevent_req_data(
		req, struct wait_for_one_notify_state);
	uint32_t num_changes;
	struct notify_change *changes;
	NTSTATUS status;

	status = cli_notify_recv(subreq, state, &num_changes, &changes);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = cli_close_send(state, state->ev, state->cli, state->dnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wait_for_one_notify_closed, req);
}

static void wait_for_one_notify_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wait_for_one_notify_state *state = tevent_req_data(
		req, struct wait_for_one_notify_state);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	*state->num_notifies -= 1;
	tevent_req_done(req);
}

static NTSTATUS wait_for_one_notify_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static void notify_bench2_done(struct tevent_req *req);

bool run_notify_bench2(int dummy)
{
	struct cli_state *cli;
	struct cli_state **clis;
	struct tevent_context *ev;
	unsigned num_notifies = 0;
	NTSTATUS status;
	int i;

	if (!torture_open_connection(&cli, 0)) {
		return false;
	}

	printf("starting notify bench 2 test\n");

	cli_rmdir(cli, "\\notify.dir\\subdir");
	cli_rmdir(cli, "\\notify.dir");

	status = cli_mkdir(cli, "\\notify.dir");
	if (!NT_STATUS_IS_OK(status)) {
		printf("mkdir failed : %s\n", nt_errstr(status));
		return false;
	}

	clis = talloc_array(talloc_tos(), struct cli_state *, torture_nprocs);
	if (clis == NULL) {
		printf("talloc failed\n");
		return false;
	}

	ev = tevent_context_init(talloc_tos());
	if (ev == NULL) {
		printf("tevent_context_create failed\n");
		return false;
	}

	for (i=0; i<torture_nprocs; i++) {
		int j;
		if (!torture_open_connection(&clis[i], i)) {
			return false;
		}

		for (j=0; j<torture_numops; j++) {
			struct tevent_req *req;
			req = wait_for_one_notify_send(
				talloc_tos(), ev, clis[i], "\\notify.dir",
				FILE_NOTIFY_CHANGE_ALL, true,
				&num_notifies);
			if (req == NULL) {
				printf("wait_for_one_notify_send failed\n");
				return false;
			}
			tevent_req_set_callback(req, notify_bench2_done, NULL);
		}
	}

	while (num_notifies < torture_nprocs * torture_numops) {
		int ret;
		ret = tevent_loop_once(ev);
		if (ret != 0) {
			printf("tevent_loop_once failed: %s\n",
			       strerror(errno));
			return false;
		}
	}

	cli_mkdir(cli, "\\notify.dir\\subdir");

	while (num_notifies > 0) {
		int ret;
		ret = tevent_loop_once(ev);
		if (ret != 0) {
			printf("tevent_loop_once failed: %s\n",
			       strerror(errno));
			return false;
		}
	}

	return true;
}

static void notify_bench2_done(struct tevent_req *req)
{
	NTSTATUS status;

	status = wait_for_one_notify_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("wait_for_one_notify returned %s\n",
		       nt_errstr(status));
	}
}

/*
 * This test creates a subdirectory. It then waits on a barrier before the
 * notify is sent. Then it creates the notify. It then waits for another
 * barrier, so that all of the notifies have gone through. It then creates
 * another subdirectory, which will trigger notifications to be sent. When the
 * notifies have been received, it waits once more before everything is
 * cleaned up.
 */

struct notify_bench3_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	const char *dir;
	uint16_t dnum;
	const char *subdir_path;
	uint16_t subdir_dnum;
	int wait_timeout;
	struct tevent_barrier *small;
	struct tevent_barrier *large;
};

static void notify_bench3_mkdir1_done(struct tevent_req *subreq);
static void notify_bench3_before_notify(struct tevent_req *subreq);
static void notify_bench3_chkpath_done(struct tevent_req *subreq);
static void notify_bench3_before_mkdir2(struct tevent_req *subreq);
static void notify_bench3_notify_done(struct tevent_req *subreq);
static void notify_bench3_notifies_done(struct tevent_req *subreq);
static void notify_bench3_mksubdir_done(struct tevent_req *subreq);
static void notify_bench3_before_close_subdir(struct tevent_req *subreq);
static void notify_bench3_close_subdir_done(struct tevent_req *subreq);
static void notify_bench3_deleted_subdir(struct tevent_req *subreq);
static void notify_bench3_deleted_subdirs(struct tevent_req *subreq);
static void notify_bench3_del_on_close_set(struct tevent_req *subreq);
static void notify_bench3_closed(struct tevent_req *subreq);

static struct tevent_req *notify_bench3_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	const char *dir, const char *subdir_path,
	struct tevent_barrier *small, struct tevent_barrier *large)
{
	struct tevent_req *req, *subreq;
	struct notify_bench3_state *state;

	req = tevent_req_create(mem_ctx, &state, struct notify_bench3_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->dir = dir;
	state->subdir_path = subdir_path;
	state->small = small;
	state->large = large;

	subreq = cli_ntcreate_send(
		state, state->ev, state->cli, state->dir, 0,
		MAXIMUM_ALLOWED_ACCESS, 0,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, notify_bench3_mkdir1_done, req);
	return req;
}

static void notify_bench3_mkdir1_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->dnum);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = tevent_barrier_wait_send(state, state->ev, state->small);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_before_notify, req);
}

static void notify_bench3_before_notify(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	int ret;

	ret = tevent_barrier_wait_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}
	subreq = cli_notify_send(state, state->ev, state->cli, state->dnum,
				 0xffff, FILE_NOTIFY_CHANGE_ALL, true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_notify_done, req);

	/*
	 * To make sure the notify received at the server, we do another no-op
	 * that is replied to.
	 */
	subreq = cli_chkpath_send(state, state->ev, state->cli, "\\");
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_chkpath_done, req);
}

static void notify_bench3_notify_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	uint32_t num_changes;
	struct notify_change *changes;
	NTSTATUS status;

	status = cli_notify_recv(subreq, state, &num_changes, &changes);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = tevent_barrier_wait_send(state, state->ev, state->large);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_notifies_done, req);
}

static void notify_bench3_notifies_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;

	ret = tevent_barrier_wait_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}
}

static void notify_bench3_chkpath_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	NTSTATUS status;

	status = cli_chkpath_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (state->subdir_path == NULL) {
		return;
	}
	subreq = tevent_barrier_wait_send(state, state->ev, state->small);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_before_mkdir2, req);
}

static void notify_bench3_before_mkdir2(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	int ret;

	ret = tevent_barrier_wait_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}
	subreq =  cli_ntcreate_send(
		state, state->ev, state->cli, state->subdir_path, 0,
		MAXIMUM_ALLOWED_ACCESS,	0,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_CREATE,
		FILE_DIRECTORY_FILE, 0);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_mksubdir_done, req);
}

static void notify_bench3_mksubdir_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	NTSTATUS status;

	status = cli_ntcreate_recv(subreq, &state->subdir_dnum);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = tevent_barrier_wait_send(state, state->ev, state->large);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_before_close_subdir,
				req);
}

static void notify_bench3_before_close_subdir(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	int ret;

	ret = tevent_barrier_wait_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}
	subreq = cli_close_send(state, state->ev, state->cli,
				state->subdir_dnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_close_subdir_done, req);
}

static void notify_bench3_close_subdir_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	NTSTATUS status;

	status = cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = cli_rmdir_send(state, state->ev, state->cli,
				state->subdir_path);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_deleted_subdir, req);
}

static void notify_bench3_deleted_subdir(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	NTSTATUS status;

	status = cli_rmdir_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = tevent_barrier_wait_send(state, state->ev, state->small);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_deleted_subdirs, req);
}

static void notify_bench3_deleted_subdirs(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	int ret;

	ret = tevent_barrier_wait_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(ret));
		return;
	}
	subreq = cli_nt_delete_on_close_send(state, state->ev, state->cli,
					     state->dnum, true);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_del_on_close_set, req);
}

static void notify_bench3_del_on_close_set(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct notify_bench3_state *state = tevent_req_data(
		req, struct notify_bench3_state);
	NTSTATUS status;

	status = cli_nt_delete_on_close_recv(subreq);
	TALLOC_FREE(subreq);
	subreq = cli_close_send(state, state->ev, state->cli, state->dnum);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, notify_bench3_closed, req);
}

static void notify_bench3_closed(struct tevent_req *subreq)
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

static NTSTATUS notify_bench3_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static void notify_bench3_done(struct tevent_req *req)
{
	unsigned *num_done = (unsigned *)tevent_req_callback_data_void(req);
	NTSTATUS status;

	status = notify_bench3_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("notify_bench3 returned %s\n", nt_errstr(status));
	}
	*num_done += 1;
}

static void notify_bench3_barrier_cb(void *private_data)
{
	struct timeval *ts = (struct timeval *)private_data;
	struct timeval now;

	GetTimeOfDay(&now);
	printf("barrier triggered: %f\n", timeval_elapsed2(ts, &now));
	GetTimeOfDay(ts);
}

bool run_notify_bench3(int dummy)
{
	struct cli_state **clis;
	struct tevent_context *ev;
	struct tevent_barrier *small;
	struct tevent_barrier *large;
	unsigned i, j;
	unsigned num_done = 0;
	struct timeval ts, now;

	clis = talloc_array(talloc_tos(), struct cli_state *, torture_nprocs);
	if (clis == NULL) {
		printf("talloc failed\n");
		return false;
	}

	GetTimeOfDay(&ts);

	small = tevent_barrier_init(
		talloc_tos(), torture_nprocs * torture_numops,
		notify_bench3_barrier_cb, &ts);
	if (small == NULL) {
		return false;
	}

	large = tevent_barrier_init(
		talloc_tos(), 2 * torture_nprocs * torture_numops,
		notify_bench3_barrier_cb, &ts);
	if (large == NULL) {
		return false;
	}

	ev = tevent_context_init(talloc_tos());
	if (ev == NULL) {
		printf("tevent_context_create failed\n");
		return false;
	}

	for (i=0; i<torture_nprocs; i++) {
		if (!torture_open_connection(&clis[i], i)) {
			return false;
		}
	}

	for (i=0; i<torture_nprocs; i++) {
		for (j=0; j<torture_numops; j++) {
			int idx = i * torture_numops + j;
			struct tevent_req *req;
			char *dirname, *subdirname;

			dirname = talloc_asprintf(
				talloc_tos(), "\\dir%.8d", idx);
			if (dirname == NULL) {
				return false;
			}
			subdirname = talloc_asprintf(
				talloc_tos(), "\\dir%.8d\\subdir",
				(idx + torture_numops + 1) %
				(torture_nprocs * torture_numops));
			if (subdirname == NULL) {
				return false;
			}

			req = notify_bench3_send(
				talloc_tos(), ev, clis[i], dirname,
				subdirname, small, large);
			if (req == NULL) {
				return false;
			}
			tevent_req_set_callback(req, notify_bench3_done,
						&num_done);
		}
	}

	while (num_done < torture_nprocs * torture_numops) {
		int ret;
		ret = tevent_loop_once(ev);
		if (ret != 0) {
			printf("tevent_loop_once failed: %s\n",
			       strerror(errno));
			return false;
		}
	}

	GetTimeOfDay(&now);
	printf("turndow: %f\n", timeval_elapsed2(&ts, &now));
	TALLOC_FREE(small);
	TALLOC_FREE(large);
	return true;
}
