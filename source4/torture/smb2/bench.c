/*
   Unix SMB/CIFS implementation.

   SMB2 bench test suite

   Copyright (C) Stefan Metzmacher 2022

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
#include "lib/param/param.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"

#include "system/filesys.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/cmdline.h"
#include "librpc/gen_ndr/security.h"
#include "lib/events/events.h"

#define FNAME "test_create.dat"
#define DNAME "smb2_open"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect status %s - should be %s\n", \
			 __location__, nt_errstr(status), nt_errstr(correct)); \
		return false; \
	}} while (0)

#define CHECK_EQUAL(v, correct) do { \
	if (v != correct) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect value for %s 0x%08llx - " \
		        "should be 0x%08llx\n", \
			 __location__, #v, \
		        (unsigned long long)v, \
		        (unsigned long long)correct); \
		return false;					\
	}} while (0)

#define CHECK_TIME(t, field) do { \
	time_t t1, t2; \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo.all_info.in.file.handle = h1; \
	status = smb2_getinfo_file(tree, tctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	t1 = t & ~1; \
	t2 = nt_time_to_unix(finfo.all_info.out.field) & ~1; \
	if (abs(t1-t2) > 2) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong time for field %s  %s - %s\n", \
			__location__, #field, \
			timestring(tctx, t1), \
			timestring(tctx, t2)); \
		dump_all_info(tctx, &finfo); \
		ret = false; \
	}} while (0)

#define CHECK_NTTIME(t, field) do { \
	NTTIME t2; \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo.all_info.in.file.handle = h1; \
	status = smb2_getinfo_file(tree, tctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	t2 = finfo.all_info.out.field; \
	if (llabs((int64_t)(t-t2)) > 20000) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong time for field %s  %s - %s\n", \
		       __location__, #field, \
		       nt_time_string(tctx, t), \
		       nt_time_string(tctx, t2)); \
		dump_all_info(tctx, &finfo); \
		ret = false; \
	}} while (0)

#define CHECK_ALL_INFO(v, field) do { \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo.all_info.in.file.handle = h1; \
	status = smb2_getinfo_file(tree, tctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	if ((v) != (finfo.all_info.out.field)) { \
	       torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong value for field %s  0x%x - 0x%x\n", \
			__location__, #field, (int)v,\
			(int)(finfo.all_info.out.field)); \
		dump_all_info(tctx, &finfo); \
		ret = false; \
	}} while (0)

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong value for %s  0x%x - should be 0x%x\n", \
		       __location__, #v, (int)(v), (int)correct); \
		ret = false; \
	}} while (0)

#define SET_ATTRIB(sattrib) do { \
	union smb_setfileinfo sfinfo; \
	ZERO_STRUCT(sfinfo.basic_info.in); \
	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION; \
	sfinfo.basic_info.in.file.handle = h1; \
	sfinfo.basic_info.in.attrib = sattrib; \
	status = smb2_setinfo_file(tree, &sfinfo); \
	if (!NT_STATUS_IS_OK(status)) { \
		torture_comment(tctx, \
		    "(%s) Failed to set attrib 0x%x on %s\n", \
		       __location__, (unsigned int)(sattrib), fname); \
	}} while (0)

/*
   stress testing keepalive iops
 */

struct test_smb2_bench_echo_conn;
struct test_smb2_bench_echo_loop;

struct test_smb2_bench_echo_state {
	struct torture_context *tctx;
	size_t num_conns;
	struct test_smb2_bench_echo_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_echo_loop *loops;
	size_t pending_loops;
	struct timeval starttime;
	int timecount;
	int timelimit;
	uint64_t num_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	bool ok;
	bool stop;
};

struct test_smb2_bench_echo_conn {
	struct test_smb2_bench_echo_state *state;
	int idx;
	struct smb2_tree *tree;
};

struct test_smb2_bench_echo_loop {
	struct test_smb2_bench_echo_state *state;
	struct test_smb2_bench_echo_conn *conn;
	int idx;
	struct tevent_immediate *im;
	struct tevent_req *req;
	struct timeval starttime;
	uint64_t num_started;
	uint64_t num_finished;
	uint64_t total_finished;
	uint64_t max_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	NTSTATUS error;
};

static void test_smb2_bench_echo_loop_do(
	struct test_smb2_bench_echo_loop *loop);

static void test_smb2_bench_echo_loop_start(struct tevent_context *ctx,
						       struct tevent_immediate *im,
						       void *private_data)
{
	struct test_smb2_bench_echo_loop *loop =
		(struct test_smb2_bench_echo_loop *)
		private_data;

	test_smb2_bench_echo_loop_do(loop);
}

static void test_smb2_bench_echo_loop_done(struct tevent_req *req);

static void test_smb2_bench_echo_loop_do(
	struct test_smb2_bench_echo_loop *loop)
{
	struct test_smb2_bench_echo_state *state = loop->state;

	loop->num_started += 1;
	loop->starttime = timeval_current();
	loop->req = smb2cli_echo_send(state->loops,
				      state->tctx->ev,
				      loop->conn->tree->session->transport->conn,
				      1000);
	torture_assert_goto(state->tctx, loop->req != NULL,
			    state->ok, asserted, "smb2cli_echo_send");

	tevent_req_set_callback(loop->req,
				test_smb2_bench_echo_loop_done,
				loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_echo_loop_done(struct tevent_req *req)
{
	struct test_smb2_bench_echo_loop *loop =
		(struct test_smb2_bench_echo_loop *)
		_tevent_req_callback_data(req);
	struct test_smb2_bench_echo_state *state = loop->state;
	double latency = timeval_elapsed(&loop->starttime);
	TALLOC_CTX *frame = talloc_stackframe();

	torture_assert_goto(state->tctx, loop->req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2cli_echo_recv(req);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->num_finished == 0) {
		/* first round */
		loop->min_latency = latency;
		loop->max_latency = latency;
	}

	loop->num_finished += 1;
	loop->total_finished += 1;
	loop->total_latency += latency;

	if (latency < loop->min_latency) {
		loop->min_latency = latency;
	}

	if (latency > loop->max_latency) {
		loop->max_latency = latency;
	}

	if (loop->total_finished >= loop->max_finished) {
		if (state->pending_loops > 0) {
			state->pending_loops -= 1;
		}
		if (state->pending_loops == 0) {
			goto asserted;
		}
	}

	TALLOC_FREE(frame);
	test_smb2_bench_echo_loop_do(loop);
	return;
asserted:
	state->stop = true;
	TALLOC_FREE(frame);
}

static void test_smb2_bench_echo_progress(struct tevent_context *ev,
					  struct tevent_timer *te,
					  struct timeval current_time,
					  void *private_data)
{
	struct test_smb2_bench_echo_state *state =
		(struct test_smb2_bench_echo_state *)private_data;
	uint64_t num_echos = 0;
	double total_echo_latency = 0;
	double min_echo_latency = 0;
	double max_echo_latency = 0;
	double avs_echo_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_echo_loop *loop =
			&state->loops[i];

		num_echos += loop->num_finished;
		total_echo_latency += loop->total_latency;
		if (min_echo_latency == 0.0 && loop->min_latency != 0.0) {
			min_echo_latency = loop->min_latency;
		}
		if (loop->min_latency < min_echo_latency) {
			min_echo_latency = loop->min_latency;
		}
		if (max_echo_latency == 0.0) {
			max_echo_latency = loop->max_latency;
		}
		if (loop->max_latency > max_echo_latency) {
			max_echo_latency = loop->max_latency;
		}
		loop->num_finished = 0;
		loop->total_latency = 0.0;
	}

	state->num_finished += num_echos;
	state->total_latency += total_echo_latency;
	if (state->min_latency == 0.0 && min_echo_latency != 0.0) {
		state->min_latency = min_echo_latency;
	}
	if (min_echo_latency < state->min_latency) {
		state->min_latency = min_echo_latency;
	}
	if (state->max_latency == 0.0) {
		state->max_latency = max_echo_latency;
	}
	if (max_echo_latency > state->max_latency) {
		state->max_latency = max_echo_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_echo_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_echo_latency = total_echo_latency / num_echos;

		torture_comment(state->tctx,
				"%.2f second: "
				"echo[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]      \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_echos,
				avs_echo_latency,
				min_echo_latency,
				max_echo_latency);
		return;
	}

	avs_echo_latency = state->total_latency / state->num_finished;
	num_echos = state->num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"echo[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_echos,
			avs_echo_latency,
			state->min_latency,
			state->max_latency);

asserted:
	state->stop = true;
}

static bool test_smb2_bench_echo(struct torture_context *tctx,
			         struct smb2_tree *tree)
{
	struct test_smb2_bench_echo_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	size_t i;
	size_t li = 0;
	int looplimit = torture_setting_int(tctx, "looplimit", -1);
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;

	state = talloc_zero(tctx, struct test_smb2_bench_echo_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_echo_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_echo_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zu connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;
		size_t pcli;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			state->conns[i].tree = ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			state->conns[i].tree = talloc_steal(state->conns, ct);
		}

		smb2cli_conn_set_max_credits(ct->session->transport->conn, 8192);
		smb2cli_ioctl(ct->session->transport->conn,
			      timeout_msec,
			      ct->session->smbXcli,
			      ct->smbXcli,
			      UINT64_MAX, /* in_fid_persistent */
			      UINT64_MAX, /* in_fid_volatile */
			      UINT32_MAX,
			      0, /* in_max_input_length */
			      NULL, /* in_input_buffer */
			      1, /* in_max_output_length */
			      NULL, /* in_output_buffer */
			      SMB2_IOCTL_FLAG_IS_FSCTL,
			      ct,
			      &out_input_buffer,
			      &out_output_buffer);
		torture_assert(tctx,
		       smbXcli_conn_is_connected(ct->session->transport->conn),
		       "smbXcli_conn_is_connected");

		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_echo_loop *loop = &state->loops[li];

			loop->idx = li++;
			if (looplimit != -1) {
				loop->max_finished = looplimit;
			} else {
				loop->max_finished = UINT64_MAX;
			}
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);
		}
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_echo_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_echo_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with qdepth=%d => %zu loops\n",
			state->num_conns, torture_qdepth, state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();
	state->pending_loops = state->num_loops;

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_echo_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	return ret;
}

/*
   stress testing path base operations
   e.g. contention on lockting.tdb records
 */

struct test_smb2_bench_path_contention_shared_conn;
struct test_smb2_bench_path_contention_shared_loop;

struct test_smb2_bench_path_contention_shared_state {
	struct torture_context *tctx;
	size_t num_conns;
	struct test_smb2_bench_path_contention_shared_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_path_contention_shared_loop *loops;
	struct timeval starttime;
	int timecount;
	int timelimit;
	struct {
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} opens;
	struct {
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} closes;
	bool ok;
	bool stop;
};

struct test_smb2_bench_path_contention_shared_conn {
	struct test_smb2_bench_path_contention_shared_state *state;
	int idx;
	struct smb2_tree *tree;
};

struct test_smb2_bench_path_contention_shared_loop {
	struct test_smb2_bench_path_contention_shared_state *state;
	struct test_smb2_bench_path_contention_shared_conn *conn;
	int idx;
	struct tevent_immediate *im;
	struct {
		struct smb2_create io;
		struct smb2_request *req;
		struct timeval starttime;
		uint64_t num_started;
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} opens;
	struct {
		struct smb2_close io;
		struct smb2_request *req;
		struct timeval starttime;
		uint64_t num_started;
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} closes;
	NTSTATUS error;
};

static void test_smb2_bench_path_contention_loop_open(
	struct test_smb2_bench_path_contention_shared_loop *loop);

static void test_smb2_bench_path_contention_loop_start(struct tevent_context *ctx,
						       struct tevent_immediate *im,
						       void *private_data)
{
	struct test_smb2_bench_path_contention_shared_loop *loop =
		(struct test_smb2_bench_path_contention_shared_loop *)
		private_data;

	test_smb2_bench_path_contention_loop_open(loop);
}

static void test_smb2_bench_path_contention_loop_opened(struct smb2_request *req);

static void test_smb2_bench_path_contention_loop_open(
	struct test_smb2_bench_path_contention_shared_loop *loop)
{
	struct test_smb2_bench_path_contention_shared_state *state = loop->state;

	loop->opens.num_started += 1;
	loop->opens.starttime = timeval_current();
	loop->opens.req = smb2_create_send(loop->conn->tree, &loop->opens.io);
	torture_assert_goto(state->tctx, loop->opens.req != NULL,
			    state->ok, asserted, "smb2_create_send");

	loop->opens.req->async.fn = test_smb2_bench_path_contention_loop_opened;
	loop->opens.req->async.private_data = loop;
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_path_contention_loop_close(
	struct test_smb2_bench_path_contention_shared_loop *loop);

static void test_smb2_bench_path_contention_loop_opened(struct smb2_request *req)
{
	struct test_smb2_bench_path_contention_shared_loop *loop =
		(struct test_smb2_bench_path_contention_shared_loop *)
		req->async.private_data;
	struct test_smb2_bench_path_contention_shared_state *state = loop->state;
	double latency = timeval_elapsed(&loop->opens.starttime);
	TALLOC_CTX *frame = talloc_stackframe();

	torture_assert_goto(state->tctx, loop->opens.req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2_create_recv(req, frame, &loop->opens.io);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	ZERO_STRUCT(loop->opens.io.out.blobs);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->opens.num_finished == 0) {
		/* first round */
		loop->opens.min_latency = latency;
		loop->opens.max_latency = latency;
	}

	loop->opens.num_finished += 1;
	loop->opens.total_latency += latency;

	if (latency < loop->opens.min_latency) {
		loop->opens.min_latency = latency;
	}

	if (latency > loop->opens.max_latency) {
		loop->opens.max_latency = latency;
	}

	TALLOC_FREE(frame);
	test_smb2_bench_path_contention_loop_close(loop);
	return;
asserted:
	state->stop = true;
	TALLOC_FREE(frame);
}

static void test_smb2_bench_path_contention_loop_closed(struct smb2_request *req);

static void test_smb2_bench_path_contention_loop_close(
	struct test_smb2_bench_path_contention_shared_loop *loop)
{
	struct test_smb2_bench_path_contention_shared_state *state = loop->state;

	loop->closes.num_started += 1;
	loop->closes.starttime = timeval_current();
	loop->closes.io.in.file = loop->opens.io.out.file;
	loop->closes.req = smb2_close_send(loop->conn->tree, &loop->closes.io);
	torture_assert_goto(state->tctx, loop->closes.req != NULL,
			    state->ok, asserted, "smb2_close_send");

	loop->closes.req->async.fn = test_smb2_bench_path_contention_loop_closed;
	loop->closes.req->async.private_data = loop;
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_path_contention_loop_closed(struct smb2_request *req)
{
	struct test_smb2_bench_path_contention_shared_loop *loop =
		(struct test_smb2_bench_path_contention_shared_loop *)
		req->async.private_data;
	struct test_smb2_bench_path_contention_shared_state *state = loop->state;
	double latency = timeval_elapsed(&loop->closes.starttime);

	torture_assert_goto(state->tctx, loop->closes.req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2_close_recv(req, &loop->closes.io);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);
	if (loop->closes.num_finished == 0) {
		/* first round */
		loop->closes.min_latency = latency;
		loop->closes.max_latency = latency;
	}
	loop->closes.num_finished += 1;

	loop->closes.total_latency += latency;

	if (latency < loop->closes.min_latency) {
		loop->closes.min_latency = latency;
	}

	if (latency > loop->closes.max_latency) {
		loop->closes.max_latency = latency;
	}

	test_smb2_bench_path_contention_loop_open(loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_path_contention_progress(struct tevent_context *ev,
						     struct tevent_timer *te,
						     struct timeval current_time,
						     void *private_data)
{
	struct test_smb2_bench_path_contention_shared_state *state =
		(struct test_smb2_bench_path_contention_shared_state *)private_data;
	uint64_t num_opens = 0;
	double total_open_latency = 0;
	double min_open_latency = 0;
	double max_open_latency = 0;
	double avs_open_latency = 0;
	uint64_t num_closes = 0;
	double total_close_latency = 0;
	double min_close_latency = 0;
	double max_close_latency = 0;
	double avs_close_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_path_contention_shared_loop *loop =
			&state->loops[i];

		num_opens += loop->opens.num_finished;
		total_open_latency += loop->opens.total_latency;
		if (min_open_latency == 0.0 && loop->opens.min_latency != 0.0) {
			min_open_latency = loop->opens.min_latency;
		}
		if (loop->opens.min_latency < min_open_latency) {
			min_open_latency = loop->opens.min_latency;
		}
		if (max_open_latency == 0.0) {
			max_open_latency = loop->opens.max_latency;
		}
		if (loop->opens.max_latency > max_open_latency) {
			max_open_latency = loop->opens.max_latency;
		}
		loop->opens.num_finished = 0;
		loop->opens.total_latency = 0.0;

		num_closes += loop->closes.num_finished;
		total_close_latency += loop->closes.total_latency;
		if (min_close_latency == 0.0 && loop->closes.min_latency != 0.0) {
			min_close_latency = loop->closes.min_latency;
		}
		if (loop->closes.min_latency < min_close_latency) {
			min_close_latency = loop->closes.min_latency;
		}
		if (max_close_latency == 0.0) {
			max_close_latency = loop->closes.max_latency;
		}
		if (loop->closes.max_latency > max_close_latency) {
			max_close_latency = loop->closes.max_latency;
		}
		loop->closes.num_finished = 0;
		loop->closes.total_latency = 0.0;
	}

	state->opens.num_finished += num_opens;
	state->opens.total_latency += total_open_latency;
	if (state->opens.min_latency == 0.0 && min_open_latency != 0.0) {
		state->opens.min_latency = min_open_latency;
	}
	if (min_open_latency < state->opens.min_latency) {
		state->opens.min_latency = min_open_latency;
	}
	if (state->opens.max_latency == 0.0) {
		state->opens.max_latency = max_open_latency;
	}
	if (max_open_latency > state->opens.max_latency) {
		state->opens.max_latency = max_open_latency;
	}

	state->closes.num_finished += num_closes;
	state->closes.total_latency += total_close_latency;
	if (state->closes.min_latency == 0.0 && min_close_latency != 0.0) {
		state->closes.min_latency = min_close_latency;
	}
	if (min_close_latency < state->closes.min_latency) {
		state->closes.min_latency = min_close_latency;
	}
	if (state->closes.max_latency == 0.0) {
		state->closes.max_latency = max_close_latency;
	}
	if (max_close_latency > state->closes.max_latency) {
		state->closes.max_latency = max_close_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_path_contention_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_open_latency = total_open_latency / num_opens;
		avs_close_latency = total_close_latency / num_closes;

		torture_comment(state->tctx,
				"%.2f second: "
				"open[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f] "
				"close[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]     \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_opens,
				avs_open_latency,
				min_open_latency,
				max_open_latency,
				(unsigned long long)num_closes,
				avs_close_latency,
				min_close_latency,
				max_close_latency);
		return;
	}

	avs_open_latency = state->opens.total_latency / state->opens.num_finished;
	avs_close_latency = state->closes.total_latency / state->closes.num_finished;
	num_opens = state->opens.num_finished / state->timelimit;
	num_closes = state->closes.num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"open[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f] "
			"close[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_opens,
			avs_open_latency,
			state->opens.min_latency,
			state->opens.max_latency,
			(unsigned long long)num_closes,
			avs_close_latency,
			state->closes.min_latency,
			state->closes.max_latency);

asserted:
	state->stop = true;
}

bool test_smb2_bench_path_contention_shared(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	struct test_smb2_bench_path_contention_shared_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	size_t i;
	size_t li = 0;
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	const char *path = torture_setting_string(tctx, "bench_path", "");
	struct smb2_create open_io = { .level = RAW_OPEN_SMB2, };
	struct smb2_close close_io = { .level = RAW_CLOSE_SMB2, };
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;

	state = talloc_zero(tctx, struct test_smb2_bench_path_contention_shared_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_path_contention_shared_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_path_contention_shared_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);

	open_io.in.desired_access = SEC_DIR_READ_ATTRIBUTE;
	open_io.in.alloc_size = 0;
	open_io.in.file_attributes = 0;
	open_io.in.share_access = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
	open_io.in.create_disposition = FILE_OPEN;
	open_io.in.create_options = FILE_OPEN_REPARSE_POINT;
	open_io.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	open_io.in.security_flags = 0;
	open_io.in.fname = path;
	open_io.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	open_io.in.oplock_level = SMB2_OPLOCK_LEVEL_NONE;

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zd connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;
		size_t pcli;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			state->conns[i].tree = ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			state->conns[i].tree = talloc_steal(state->conns, ct);
		}

		smb2cli_conn_set_max_credits(ct->session->transport->conn, 8192);
		smb2cli_ioctl(ct->session->transport->conn,
			      timeout_msec,
			      ct->session->smbXcli,
			      ct->smbXcli,
			      UINT64_MAX, /* in_fid_persistent */
			      UINT64_MAX, /* in_fid_volatile */
			      UINT32_MAX,
			      0, /* in_max_input_length */
			      NULL, /* in_input_buffer */
			      1, /* in_max_output_length */
			      NULL, /* in_output_buffer */
			      SMB2_IOCTL_FLAG_IS_FSCTL,
			      ct,
			      &out_input_buffer,
			      &out_output_buffer);
		torture_assert(tctx,
		       smbXcli_conn_is_connected(ct->session->transport->conn),
		       "smbXcli_conn_is_connected");
		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_path_contention_shared_loop *loop = &state->loops[li];

			loop->idx = li++;
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);
			loop->opens.io = open_io;
			loop->closes.io = close_io;
		}
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_path_contention_shared_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_path_contention_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with qdepth=%d => %zu loops\n",
			state->num_conns, torture_qdepth, state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_path_contention_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	return ret;
}

/*
   stress testing read iops
 */

struct test_smb2_bench_read_conn;
struct test_smb2_bench_read_loop;

struct test_smb2_bench_read_state {
	struct torture_context *tctx;
	size_t num_conns;
	struct test_smb2_bench_read_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_read_loop *loops;
	size_t pending_loops;
	uint32_t io_size;
	struct timeval starttime;
	int timecount;
	int timelimit;
	uint64_t num_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	bool ok;
	bool stop;
};

struct test_smb2_bench_read_conn {
	struct test_smb2_bench_read_state *state;
	int idx;
	struct smb2_tree *tree;
};

struct test_smb2_bench_read_loop {
	struct test_smb2_bench_read_state *state;
	struct test_smb2_bench_read_conn *conn;
	int idx;
	struct tevent_immediate *im;
	char *fname;
	struct smb2_handle handle;
	struct tevent_req *req;
	struct timeval starttime;
	uint64_t num_started;
	uint64_t num_finished;
	uint64_t total_finished;
	uint64_t max_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	NTSTATUS error;
};

static void test_smb2_bench_read_loop_do(
	struct test_smb2_bench_read_loop *loop);

static void test_smb2_bench_read_loop_start(struct tevent_context *ctx,
						       struct tevent_immediate *im,
						       void *private_data)
{
	struct test_smb2_bench_read_loop *loop =
		(struct test_smb2_bench_read_loop *)
		private_data;

	test_smb2_bench_read_loop_do(loop);
}

static void test_smb2_bench_read_loop_done(struct tevent_req *req);

static void test_smb2_bench_read_loop_do(
	struct test_smb2_bench_read_loop *loop)
{
	struct test_smb2_bench_read_state *state = loop->state;
	uint32_t timeout_msec;

	timeout_msec = loop->conn->tree->session->transport->options.request_timeout * 1000;

	loop->num_started += 1;
	loop->starttime = timeval_current();
	loop->req = smb2cli_read_send(state->loops,
				      state->tctx->ev,
				      loop->conn->tree->session->transport->conn,
				      timeout_msec,
				      loop->conn->tree->session->smbXcli,
				      loop->conn->tree->smbXcli,
				      state->io_size, /* length */
				      0,              /* offset */
				      loop->handle.data[0],/* fid_persistent */
				      loop->handle.data[1],/* fid_volatile */
				      state->io_size, /* minimum_count */
				      0);              /* remaining_bytes */
	torture_assert_goto(state->tctx, loop->req != NULL,
			    state->ok, asserted, "smb2cli_read_send");

	tevent_req_set_callback(loop->req,
				test_smb2_bench_read_loop_done,
				loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_read_loop_done(struct tevent_req *req)
{
	struct test_smb2_bench_read_loop *loop =
		(struct test_smb2_bench_read_loop *)
		_tevent_req_callback_data(req);
	struct test_smb2_bench_read_state *state = loop->state;
	double latency = timeval_elapsed(&loop->starttime);
	TALLOC_CTX *frame = talloc_stackframe();
	uint8_t *data = NULL;
	uint32_t data_length = 0;

	torture_assert_goto(state->tctx, loop->req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2cli_read_recv(req, frame, &data, &data_length);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	torture_assert_u32_equal_goto(state->tctx, data_length, state->io_size,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->num_finished == 0) {
		/* first round */
		loop->min_latency = latency;
		loop->max_latency = latency;
	}

	loop->num_finished += 1;
	loop->total_finished += 1;
	loop->total_latency += latency;

	if (latency < loop->min_latency) {
		loop->min_latency = latency;
	}

	if (latency > loop->max_latency) {
		loop->max_latency = latency;
	}

	if (loop->total_finished >= loop->max_finished) {
		if (state->pending_loops > 0) {
			state->pending_loops -= 1;
		}
		if (state->pending_loops == 0) {
			goto asserted;
		}
	}

	TALLOC_FREE(frame);
	test_smb2_bench_read_loop_do(loop);
	return;
asserted:
	state->stop = true;
	TALLOC_FREE(frame);
}

static void test_smb2_bench_read_progress(struct tevent_context *ev,
					  struct tevent_timer *te,
					  struct timeval current_time,
					  void *private_data)
{
	struct test_smb2_bench_read_state *state =
		(struct test_smb2_bench_read_state *)private_data;
	uint64_t num_reads = 0;
	double total_read_latency = 0;
	double min_read_latency = 0;
	double max_read_latency = 0;
	double avs_read_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_read_loop *loop =
			&state->loops[i];

		num_reads += loop->num_finished;
		total_read_latency += loop->total_latency;
		if (min_read_latency == 0.0 && loop->min_latency != 0.0) {
			min_read_latency = loop->min_latency;
		}
		if (loop->min_latency < min_read_latency) {
			min_read_latency = loop->min_latency;
		}
		if (max_read_latency == 0.0) {
			max_read_latency = loop->max_latency;
		}
		if (loop->max_latency > max_read_latency) {
			max_read_latency = loop->max_latency;
		}
		loop->num_finished = 0;
		loop->total_latency = 0.0;
	}

	state->num_finished += num_reads;
	state->total_latency += total_read_latency;
	if (state->min_latency == 0.0 && min_read_latency != 0.0) {
		state->min_latency = min_read_latency;
	}
	if (min_read_latency < state->min_latency) {
		state->min_latency = min_read_latency;
	}
	if (state->max_latency == 0.0) {
		state->max_latency = max_read_latency;
	}
	if (max_read_latency > state->max_latency) {
		state->max_latency = max_read_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_read_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_read_latency = total_read_latency / num_reads;

		torture_comment(state->tctx,
				"%.2f second: "
				"read[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]      \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_reads,
				(unsigned long long)num_reads*state->io_size,
				avs_read_latency,
				min_read_latency,
				max_read_latency);
		return;
	}

	avs_read_latency = state->total_latency / state->num_finished;
	num_reads = state->num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"read[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_reads,
			(unsigned long long)num_reads*state->io_size,
			avs_read_latency,
			state->min_latency,
			state->max_latency);

asserted:
	state->stop = true;
}

static bool test_smb2_bench_read(struct torture_context *tctx,
			         struct smb2_tree *tree)
{
	struct test_smb2_bench_read_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	int torture_io_size = torture_setting_int(tctx, "io_size", 4096);
	size_t i;
	size_t li = 0;
	int looplimit = torture_setting_int(tctx, "looplimit", -1);
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;
	const char *dname = "bench_read_dir";
	const char *unique = generate_random_str(tctx, 8);
	struct smb2_handle dh;
	NTSTATUS status;

	smb2_deltree(tree, dname);

	status = torture_smb2_testdir(tree, dname, &dh);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, dh);
	CHECK_STATUS(status, NT_STATUS_OK);

	state = talloc_zero(tctx, struct test_smb2_bench_read_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_read_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_read_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);
	state->io_size = MAX(torture_io_size, 1);
	state->io_size = MIN(state->io_size, 16*1024*1024);

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zu connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;
		size_t pcli;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			state->conns[i].tree = ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			state->conns[i].tree = talloc_steal(state->conns, ct);
		}

		smb2cli_conn_set_max_credits(ct->session->transport->conn, 8192);
		smb2cli_ioctl(ct->session->transport->conn,
			      timeout_msec,
			      ct->session->smbXcli,
			      ct->smbXcli,
			      UINT64_MAX, /* in_fid_persistent */
			      UINT64_MAX, /* in_fid_volatile */
			      UINT32_MAX,
			      0, /* in_max_input_length */
			      NULL, /* in_input_buffer */
			      1, /* in_max_output_length */
			      NULL, /* in_output_buffer */
			      SMB2_IOCTL_FLAG_IS_FSCTL,
			      ct,
			      &out_input_buffer,
			      &out_output_buffer);
		torture_assert(tctx,
		       smbXcli_conn_is_connected(ct->session->transport->conn),
		       "smbXcli_conn_is_connected");

		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_read_loop *loop = &state->loops[li];
			struct smb2_create cr;
			union smb_setfileinfo sfinfo;

			loop->idx = li++;
			if (looplimit != -1) {
				loop->max_finished = looplimit;
			} else {
				loop->max_finished = UINT64_MAX;
			}
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);

			loop->fname = talloc_asprintf(state->loops,
						"%s\\%s_loop_%zu_conn_%zu_loop_%zu.dat",
						dname, unique, li, i, pcli);
			torture_assert(tctx, loop->fname != NULL, __location__);

			/* reasonable default parameters */
			ZERO_STRUCT(cr);
			cr.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
			cr.in.alloc_size = state->io_size;
			cr.in.desired_access = SEC_RIGHTS_FILE_ALL;
			cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
			cr.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
			cr.in.create_disposition = NTCREATEX_DISP_CREATE;
			cr.in.create_options =
				NTCREATEX_OPTIONS_DELETE_ON_CLOSE |
				NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
			cr.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
			cr.in.security_flags = 0;
			cr.in.fname = loop->fname;
			status = smb2_create(state->conns[i].tree, tctx, &cr);
			CHECK_STATUS(status, NT_STATUS_OK);
			loop->handle = cr.out.file.handle;

			ZERO_STRUCT(sfinfo);
			sfinfo.end_of_file_info.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
			sfinfo.end_of_file_info.in.file.handle = loop->handle;
			sfinfo.end_of_file_info.in.size = state->io_size;
			status = smb2_setinfo_file(state->conns[i].tree, &sfinfo);
			CHECK_STATUS(status, NT_STATUS_OK);
		}
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_read_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_read_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with qdepth=%d => %zu loops\n",
			state->num_conns, torture_qdepth, state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();
	state->pending_loops = state->num_loops;

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_read_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	smb2_deltree(tree, dname);
	return ret;
}

/*
   stress testing write iops
 */

struct test_smb2_bench_write_conn;
struct test_smb2_bench_write_loop;

struct test_smb2_bench_write_state {
	struct torture_context *tctx;
	size_t num_conns;
	struct test_smb2_bench_write_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_write_loop *loops;
	size_t pending_loops;
	uint32_t io_size;
	uint8_t *data_buffer;
	struct timeval starttime;
	int timecount;
	int timelimit;
	uint64_t num_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	bool ok;
	bool stop;
};

struct test_smb2_bench_write_conn {
	struct test_smb2_bench_write_state *state;
	int idx;
	struct smb2_tree *tree;
};

struct test_smb2_bench_write_loop {
	struct test_smb2_bench_write_state *state;
	struct test_smb2_bench_write_conn *conn;
	int idx;
	struct tevent_immediate *im;
	char *fname;
	struct smb2_handle handle;
	struct tevent_req *req;
	struct timeval starttime;
	uint64_t num_started;
	uint64_t num_finished;
	uint64_t total_finished;
	uint64_t max_finished;
	double total_latency;
	double min_latency;
	double max_latency;
	NTSTATUS error;
};

static void test_smb2_bench_write_loop_do(
	struct test_smb2_bench_write_loop *loop);

static void test_smb2_bench_write_loop_start(struct tevent_context *ctx,
						       struct tevent_immediate *im,
						       void *private_data)
{
	struct test_smb2_bench_write_loop *loop =
		(struct test_smb2_bench_write_loop *)
		private_data;

	test_smb2_bench_write_loop_do(loop);
}

static void test_smb2_bench_write_loop_done(struct tevent_req *req);

static void test_smb2_bench_write_loop_do(
	struct test_smb2_bench_write_loop *loop)
{
	struct test_smb2_bench_write_state *state = loop->state;
	uint32_t timeout_msec;

	timeout_msec = loop->conn->tree->session->transport->options.request_timeout * 1000;

	loop->num_started += 1;
	loop->starttime = timeval_current();
	loop->req = smb2cli_write_send(state->loops,
				       state->tctx->ev,
				       loop->conn->tree->session->transport->conn,
				       timeout_msec,
				       loop->conn->tree->session->smbXcli,
				       loop->conn->tree->smbXcli,
				       state->io_size, /* length */
				       0,              /* offset */
				       loop->handle.data[0],/* fid_persistent */
				       loop->handle.data[1],/* fid_volatile */
				       0,              /* remaining_bytes */
				       0,              /* flags */
				       state->data_buffer);
	torture_assert_goto(state->tctx, loop->req != NULL,
			    state->ok, asserted, "smb2cli_write_send");

	tevent_req_set_callback(loop->req,
				test_smb2_bench_write_loop_done,
				loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_write_loop_done(struct tevent_req *req)
{
	struct test_smb2_bench_write_loop *loop =
		(struct test_smb2_bench_write_loop *)
		_tevent_req_callback_data(req);
	struct test_smb2_bench_write_state *state = loop->state;
	double latency = timeval_elapsed(&loop->starttime);
	uint32_t data_length = 0;

	torture_assert_goto(state->tctx, loop->req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2cli_write_recv(req, &data_length);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	torture_assert_u32_equal_goto(state->tctx, data_length, state->io_size,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->num_finished == 0) {
		/* first round */
		loop->min_latency = latency;
		loop->max_latency = latency;
	}

	loop->num_finished += 1;
	loop->total_finished += 1;
	loop->total_latency += latency;

	if (latency < loop->min_latency) {
		loop->min_latency = latency;
	}

	if (latency > loop->max_latency) {
		loop->max_latency = latency;
	}

	if (loop->total_finished >= loop->max_finished) {
		if (state->pending_loops > 0) {
			state->pending_loops -= 1;
		}
		if (state->pending_loops == 0) {
			goto asserted;
		}
	}

	test_smb2_bench_write_loop_do(loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_write_progress(struct tevent_context *ev,
					  struct tevent_timer *te,
					  struct timeval current_time,
					  void *private_data)
{
	struct test_smb2_bench_write_state *state =
		(struct test_smb2_bench_write_state *)private_data;
	uint64_t num_writes = 0;
	double total_write_latency = 0;
	double min_write_latency = 0;
	double max_write_latency = 0;
	double avs_write_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_write_loop *loop =
			&state->loops[i];

		num_writes += loop->num_finished;
		total_write_latency += loop->total_latency;
		if (min_write_latency == 0.0 && loop->min_latency != 0.0) {
			min_write_latency = loop->min_latency;
		}
		if (loop->min_latency < min_write_latency) {
			min_write_latency = loop->min_latency;
		}
		if (max_write_latency == 0.0) {
			max_write_latency = loop->max_latency;
		}
		if (loop->max_latency > max_write_latency) {
			max_write_latency = loop->max_latency;
		}
		loop->num_finished = 0;
		loop->total_latency = 0.0;
	}

	state->num_finished += num_writes;
	state->total_latency += total_write_latency;
	if (state->min_latency == 0.0 && min_write_latency != 0.0) {
		state->min_latency = min_write_latency;
	}
	if (min_write_latency < state->min_latency) {
		state->min_latency = min_write_latency;
	}
	if (state->max_latency == 0.0) {
		state->max_latency = max_write_latency;
	}
	if (max_write_latency > state->max_latency) {
		state->max_latency = max_write_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_write_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_write_latency = total_write_latency / num_writes;

		torture_comment(state->tctx,
				"%.2f second: "
				"write[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]      \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_writes,
				(unsigned long long)num_writes*state->io_size,
				avs_write_latency,
				min_write_latency,
				max_write_latency);
		return;
	}

	avs_write_latency = state->total_latency / state->num_finished;
	num_writes = state->num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"write[num/s=%llu,bytes/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_writes,
			(unsigned long long)num_writes*state->io_size,
			avs_write_latency,
			state->min_latency,
			state->max_latency);

asserted:
	state->stop = true;
}

static bool test_smb2_bench_write(struct torture_context *tctx,
			         struct smb2_tree *tree)
{
	struct test_smb2_bench_write_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	int torture_io_size = torture_setting_int(tctx, "io_size", 4096);
	size_t i;
	size_t li = 0;
	int looplimit = torture_setting_int(tctx, "looplimit", -1);
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;
	const char *dname = "bench_write_dir";
	const char *unique = generate_random_str(tctx, 8);
	struct smb2_handle dh;
	NTSTATUS status;

	smb2_deltree(tree, dname);

	status = torture_smb2_testdir(tree, dname, &dh);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_util_close(tree, dh);
	CHECK_STATUS(status, NT_STATUS_OK);

	state = talloc_zero(tctx, struct test_smb2_bench_write_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_write_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_write_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);
	state->io_size = MAX(torture_io_size, 1);
	state->io_size = MIN(state->io_size, 16*1024*1024);
	state->data_buffer = talloc_zero_array(state, uint8_t, state->io_size);
	torture_assert(tctx, state->data_buffer != NULL, __location__);

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zu connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;
		size_t pcli;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			state->conns[i].tree = ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			state->conns[i].tree = talloc_steal(state->conns, ct);
		}

		smb2cli_conn_set_max_credits(ct->session->transport->conn, 8192);
		smb2cli_ioctl(ct->session->transport->conn,
			      timeout_msec,
			      ct->session->smbXcli,
			      ct->smbXcli,
			      UINT64_MAX, /* in_fid_persistent */
			      UINT64_MAX, /* in_fid_volatile */
			      UINT32_MAX,
			      0, /* in_max_input_length */
			      NULL, /* in_input_buffer */
			      1, /* in_max_output_length */
			      NULL, /* in_output_buffer */
			      SMB2_IOCTL_FLAG_IS_FSCTL,
			      ct,
			      &out_input_buffer,
			      &out_output_buffer);
		torture_assert(tctx,
		       smbXcli_conn_is_connected(ct->session->transport->conn),
		       "smbXcli_conn_is_connected");

		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_write_loop *loop = &state->loops[li];
			struct smb2_create cr;
			union smb_setfileinfo sfinfo;

			loop->idx = li++;
			if (looplimit != -1) {
				loop->max_finished = looplimit;
			} else {
				loop->max_finished = UINT64_MAX;
			}
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);

			loop->fname = talloc_asprintf(state->loops,
						"%s\\%s_loop_%zu_conn_%zu_loop_%zu.dat",
						dname, unique, li, i, pcli);
			torture_assert(tctx, loop->fname != NULL, __location__);

			/* reasonable default parameters */
			ZERO_STRUCT(cr);
			cr.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
			cr.in.alloc_size = state->io_size;
			cr.in.desired_access = SEC_RIGHTS_FILE_ALL;
			cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
			cr.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
			cr.in.create_disposition = NTCREATEX_DISP_CREATE;
			cr.in.create_options =
				NTCREATEX_OPTIONS_DELETE_ON_CLOSE |
				NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
			cr.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
			cr.in.security_flags = 0;
			cr.in.fname = loop->fname;
			status = smb2_create(state->conns[i].tree, tctx, &cr);
			CHECK_STATUS(status, NT_STATUS_OK);
			loop->handle = cr.out.file.handle;

			ZERO_STRUCT(sfinfo);
			sfinfo.end_of_file_info.level = RAW_SFILEINFO_END_OF_FILE_INFORMATION;
			sfinfo.end_of_file_info.in.file.handle = loop->handle;
			sfinfo.end_of_file_info.in.size = state->io_size;
			status = smb2_setinfo_file(state->conns[i].tree, &sfinfo);
			CHECK_STATUS(status, NT_STATUS_OK);
		}
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_write_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_write_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with qdepth=%d => %zu loops\n",
			state->num_conns, torture_qdepth, state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();
	state->pending_loops = state->num_loops;

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_write_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	smb2_deltree(tree, dname);
	return ret;
}

/*
   stress testing session setups
 */

struct test_smb2_bench_session_setup_shared_conn;
struct test_smb2_bench_session_setup_shared_loop;

struct test_smb2_bench_session_setup_shared_state {
	struct torture_context *tctx;
	struct cli_credentials *credentials;
	struct gensec_settings *gensec_settings;
	size_t num_conns;
	struct test_smb2_bench_session_setup_shared_conn *conns;
	size_t num_loops;
	struct test_smb2_bench_session_setup_shared_loop *loops;
	struct timeval starttime;
	int timecount;
	int timelimit;
	struct {
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} setups;
	struct {
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} logoffs;
	bool ok;
	bool stop;
};

struct test_smb2_bench_session_setup_shared_conn {
	struct test_smb2_bench_session_setup_shared_state *state;
	int idx;
	struct smb2_transport *transport;
};

struct test_smb2_bench_session_setup_shared_loop {
	struct test_smb2_bench_session_setup_shared_state *state;
	struct test_smb2_bench_session_setup_shared_conn *conn;
	int idx;
	struct smb2_session *session;
	struct tevent_immediate *im;
	struct {
		struct tevent_req *req;
		struct timeval starttime;
		uint64_t num_started;
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} setups;
	struct {
		struct smb2_request *req;
		struct timeval starttime;
		uint64_t num_started;
		uint64_t num_finished;
		double total_latency;
		double min_latency;
		double max_latency;
	} logoffs;
	NTSTATUS error;
};

static void test_smb2_bench_session_setup_loop_do_setup(
	struct test_smb2_bench_session_setup_shared_loop *loop);

static void test_smb2_bench_session_setup_loop_start(struct tevent_context *ctx,
						     struct tevent_immediate *im,
						     void *private_data)
{
	struct test_smb2_bench_session_setup_shared_loop *loop =
		(struct test_smb2_bench_session_setup_shared_loop *)
		private_data;

	test_smb2_bench_session_setup_loop_do_setup(loop);
}

static void test_smb2_bench_session_setup_loop_done_setup(struct tevent_req *subreq);

static void test_smb2_bench_session_setup_loop_do_setup(
	struct test_smb2_bench_session_setup_shared_loop *loop)
{
	struct test_smb2_bench_session_setup_shared_state *state = loop->state;

	loop->session = smb2_session_init(loop->conn->transport,
					  state->tctx->lp_ctx,
					  state->gensec_settings,
					  loop->conn->transport);
	torture_assert_goto(state->tctx, loop->session != NULL,
			    state->ok, asserted, "smb2_session_init");
	talloc_steal(state->conns, loop->conn->transport);

	loop->setups.num_started += 1;
	loop->setups.starttime = timeval_current();
	loop->setups.req = smb2_session_setup_spnego_send(loop->session,
							  state->tctx->ev,
							  loop->session,
							  state->credentials,
							  0); /* previous_session_id */
	torture_assert_goto(state->tctx, loop->setups.req != NULL,
			    state->ok, asserted,
			    "smb2_session_setup_spnego_send");

	tevent_req_set_callback(loop->setups.req,
				test_smb2_bench_session_setup_loop_done_setup,
				loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_session_setup_loop_do_logoff(
	struct test_smb2_bench_session_setup_shared_loop *loop);

static void test_smb2_bench_session_setup_loop_done_setup(struct tevent_req *subreq)
{
	struct test_smb2_bench_session_setup_shared_loop *loop =
		(struct test_smb2_bench_session_setup_shared_loop *)
		tevent_req_callback_data_void(subreq);
	struct test_smb2_bench_session_setup_shared_state *state = loop->state;
	double latency = timeval_elapsed(&loop->setups.starttime);
	TALLOC_CTX *frame = talloc_stackframe();

	torture_assert_goto(state->tctx, loop->setups.req == subreq,
			    state->ok, asserted, __location__);
	loop->setups.req = NULL;
	loop->error = smb2_session_setup_spnego_recv(subreq);
	TALLOC_FREE(subreq);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	SMB_ASSERT(latency >= 0.000001);

	if (loop->setups.num_finished == 0) {
		/* first round */
		loop->setups.min_latency = latency;
		loop->setups.max_latency = latency;
	}

	loop->setups.num_finished += 1;
	loop->setups.total_latency += latency;

	if (latency < loop->setups.min_latency) {
		loop->setups.min_latency = latency;
	}

	if (latency > loop->setups.max_latency) {
		loop->setups.max_latency = latency;
	}

	TALLOC_FREE(frame);
	test_smb2_bench_session_setup_loop_do_logoff(loop);
	return;
asserted:
	state->stop = true;
	TALLOC_FREE(frame);
}

static void test_smb2_bench_session_setup_loop_done_logoff(struct smb2_request *req);

static void test_smb2_bench_session_setup_loop_do_logoff(
	struct test_smb2_bench_session_setup_shared_loop *loop)
{
	struct test_smb2_bench_session_setup_shared_state *state = loop->state;

	loop->logoffs.num_started += 1;
	loop->logoffs.starttime = timeval_current();
	loop->logoffs.req = smb2_logoff_send(loop->session);
	torture_assert_goto(state->tctx, loop->logoffs.req != NULL,
			    state->ok, asserted, "smb2_logoff_send");

	loop->logoffs.req->async.fn = test_smb2_bench_session_setup_loop_done_logoff;
	loop->logoffs.req->async.private_data = loop;
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_session_setup_loop_done_logoff(struct smb2_request *req)
{
	struct test_smb2_bench_session_setup_shared_loop *loop =
		(struct test_smb2_bench_session_setup_shared_loop *)
		req->async.private_data;
	struct test_smb2_bench_session_setup_shared_state *state = loop->state;
	double latency = timeval_elapsed(&loop->logoffs.starttime);

	torture_assert_goto(state->tctx, loop->logoffs.req == req,
			    state->ok, asserted, __location__);
	loop->error = smb2_logoff_recv(req);
	torture_assert_ntstatus_ok_goto(state->tctx, loop->error,
					state->ok, asserted, __location__);
	TALLOC_FREE(loop->session);
	SMB_ASSERT(latency >= 0.000001);
	if (loop->logoffs.num_finished == 0) {
		/* first round */
		loop->logoffs.min_latency = latency;
		loop->logoffs.max_latency = latency;
	}
	loop->logoffs.num_finished += 1;

	loop->logoffs.total_latency += latency;

	if (latency < loop->logoffs.min_latency) {
		loop->logoffs.min_latency = latency;
	}

	if (latency > loop->logoffs.max_latency) {
		loop->logoffs.max_latency = latency;
	}

	test_smb2_bench_session_setup_loop_do_setup(loop);
	return;
asserted:
	state->stop = true;
}

static void test_smb2_bench_session_setup_progress(struct tevent_context *ev,
						   struct tevent_timer *te,
						   struct timeval current_time,
						   void *private_data)
{
	struct test_smb2_bench_session_setup_shared_state *state =
		(struct test_smb2_bench_session_setup_shared_state *)private_data;
	uint64_t num_setups = 0;
	double total_setup_latency = 0;
	double min_setup_latency = 0;
	double max_setup_latency = 0;
	double avs_setup_latency = 0;
	uint64_t num_logoffs = 0;
	double total_logoff_latency = 0;
	double min_logoff_latency = 0;
	double max_logoff_latency = 0;
	double avs_logoff_latency = 0;
	size_t i;

	state->timecount += 1;

	for (i=0;i<state->num_loops;i++) {
		struct test_smb2_bench_session_setup_shared_loop *loop =
			&state->loops[i];

		num_setups += loop->setups.num_finished;
		total_setup_latency += loop->setups.total_latency;
		if (min_setup_latency == 0.0 && loop->setups.min_latency != 0.0) {
			min_setup_latency = loop->setups.min_latency;
		}
		if (loop->setups.min_latency < min_setup_latency) {
			min_setup_latency = loop->setups.min_latency;
		}
		if (max_setup_latency == 0.0) {
			max_setup_latency = loop->setups.max_latency;
		}
		if (loop->setups.max_latency > max_setup_latency) {
			max_setup_latency = loop->setups.max_latency;
		}
		loop->setups.num_finished = 0;
		loop->setups.total_latency = 0.0;

		num_logoffs += loop->logoffs.num_finished;
		total_logoff_latency += loop->logoffs.total_latency;
		if (min_logoff_latency == 0.0 && loop->logoffs.min_latency != 0.0) {
			min_logoff_latency = loop->logoffs.min_latency;
		}
		if (loop->logoffs.min_latency < min_logoff_latency) {
			min_logoff_latency = loop->logoffs.min_latency;
		}
		if (max_logoff_latency == 0.0) {
			max_logoff_latency = loop->logoffs.max_latency;
		}
		if (loop->logoffs.max_latency > max_logoff_latency) {
			max_logoff_latency = loop->logoffs.max_latency;
		}
		loop->logoffs.num_finished = 0;
		loop->logoffs.total_latency = 0.0;
	}

	state->setups.num_finished += num_setups;
	state->setups.total_latency += total_setup_latency;
	if (state->setups.min_latency == 0.0 && min_setup_latency != 0.0) {
		state->setups.min_latency = min_setup_latency;
	}
	if (min_setup_latency < state->setups.min_latency) {
		state->setups.min_latency = min_setup_latency;
	}
	if (state->setups.max_latency == 0.0) {
		state->setups.max_latency = max_setup_latency;
	}
	if (max_setup_latency > state->setups.max_latency) {
		state->setups.max_latency = max_setup_latency;
	}

	state->logoffs.num_finished += num_logoffs;
	state->logoffs.total_latency += total_logoff_latency;
	if (state->logoffs.min_latency == 0.0 && min_logoff_latency != 0.0) {
		state->logoffs.min_latency = min_logoff_latency;
	}
	if (min_logoff_latency < state->logoffs.min_latency) {
		state->logoffs.min_latency = min_logoff_latency;
	}
	if (state->logoffs.max_latency == 0.0) {
		state->logoffs.max_latency = max_logoff_latency;
	}
	if (max_logoff_latency > state->logoffs.max_latency) {
		state->logoffs.max_latency = max_logoff_latency;
	}

	if (state->timecount < state->timelimit) {
		te = tevent_add_timer(state->tctx->ev,
				      state,
				      timeval_current_ofs(1, 0),
				      test_smb2_bench_session_setup_progress,
				      state);
		torture_assert_goto(state->tctx, te != NULL,
				    state->ok, asserted, "tevent_add_timer");

		if (!torture_setting_bool(state->tctx, "progress", true)) {
			return;
		}

		avs_setup_latency = total_setup_latency / num_setups;
		avs_logoff_latency = total_logoff_latency / num_logoffs;

		torture_comment(state->tctx,
				"%.2f second: "
				"setup[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f] "
				"logoff[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]     \r",
				timeval_elapsed(&state->starttime),
				(unsigned long long)num_setups,
				avs_setup_latency,
				min_setup_latency,
				max_setup_latency,
				(unsigned long long)num_logoffs,
				avs_logoff_latency,
				min_logoff_latency,
				max_logoff_latency);
		return;
	}

	avs_setup_latency = state->setups.total_latency / state->setups.num_finished;
	avs_logoff_latency = state->logoffs.total_latency / state->logoffs.num_finished;
	num_setups = state->setups.num_finished / state->timelimit;
	num_logoffs = state->logoffs.num_finished / state->timelimit;

	torture_comment(state->tctx,
			"%.2f second: "
			"setup[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f] "
			"logoff[num/s=%llu,avslat=%.6f,minlat=%.6f,maxlat=%.6f]\n",
			timeval_elapsed(&state->starttime),
			(unsigned long long)num_setups,
			avs_setup_latency,
			state->setups.min_latency,
			state->setups.max_latency,
			(unsigned long long)num_logoffs,
			avs_logoff_latency,
			state->logoffs.min_latency,
			state->logoffs.max_latency);

asserted:
	state->stop = true;
}

static bool test_smb2_bench_session_setup(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	struct test_smb2_bench_session_setup_shared_state *state = NULL;
	bool ret = true;
	int torture_nprocs = torture_setting_int(tctx, "nprocs", 4);
	int torture_qdepth = torture_setting_int(tctx, "qdepth", 1);
	size_t i;
	size_t li = 0;
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	struct tevent_timer *te = NULL;
	uint32_t timeout_msec;

	state = talloc_zero(tctx, struct test_smb2_bench_session_setup_shared_state);
	torture_assert(tctx, state != NULL, __location__);
	state->tctx = tctx;
	state->credentials = samba_cmdline_get_creds();
	torture_assert(tctx, state->credentials != NULL, __location__);
	state->gensec_settings = lpcfg_gensec_settings(state, tctx->lp_ctx);
	torture_assert(tctx, state->gensec_settings != NULL, __location__);
	state->num_conns = torture_nprocs;
	state->conns = talloc_zero_array(state,
			struct test_smb2_bench_session_setup_shared_conn,
			state->num_conns);
	torture_assert(tctx, state->conns != NULL, __location__);
	state->num_loops = torture_nprocs * torture_qdepth;
	state->loops = talloc_zero_array(state,
			struct test_smb2_bench_session_setup_shared_loop,
			state->num_loops);
	torture_assert(tctx, state->loops != NULL, __location__);
	state->ok = true;
	state->timelimit = MAX(timelimit, 1);

	timeout_msec = tree->session->transport->options.request_timeout * 1000;

	torture_comment(tctx, "Opening %zd connections\n", state->num_conns);

	for (i=0;i<state->num_conns;i++) {
		struct smb2_tree *ct = NULL;
		DATA_BLOB out_input_buffer = data_blob_null;
		DATA_BLOB out_output_buffer = data_blob_null;
		size_t pcli;

		state->conns[i].state = state;
		state->conns[i].idx = i;

		if (state->num_conns == 1) {
			/*
			 * Use the existing connection
			 */
			ct = tree;
		} else {
			if (!torture_smb2_connection(tctx, &ct)) {
				torture_comment(tctx,
					"Failed opening %zu/%zu connections\n",
					i, state->num_conns);
				return false;
			}
			talloc_steal(state->conns, ct);
		}
		state->conns[i].transport = ct->session->transport;

		smb2cli_conn_set_max_credits(ct->session->transport->conn, 8192);
		smb2cli_ioctl(ct->session->transport->conn,
			      timeout_msec,
			      ct->session->smbXcli,
			      ct->smbXcli,
			      UINT64_MAX, /* in_fid_persistent */
			      UINT64_MAX, /* in_fid_volatile */
			      UINT32_MAX,
			      0, /* in_max_input_length */
			      NULL, /* in_input_buffer */
			      1, /* in_max_output_length */
			      NULL, /* in_output_buffer */
			      SMB2_IOCTL_FLAG_IS_FSCTL,
			      ct,
			      &out_input_buffer,
			      &out_output_buffer);
		torture_assert(tctx,
		       smbXcli_conn_is_connected(ct->session->transport->conn),
		       "smbXcli_conn_is_connected");
		for (pcli = 0; pcli < torture_qdepth; pcli++) {
			struct test_smb2_bench_session_setup_shared_loop *loop = &state->loops[li];

			loop->idx = li++;
			loop->state = state;
			loop->conn = &state->conns[i];
			loop->im = tevent_create_immediate(state->loops);
			torture_assert(tctx, loop->im != NULL, __location__);
		}
	}

	for (li = 0; li <state->num_loops; li++) {
		struct test_smb2_bench_session_setup_shared_loop *loop = &state->loops[li];

		tevent_schedule_immediate(loop->im,
					  tctx->ev,
					  test_smb2_bench_session_setup_loop_start,
					  loop);
	}

	torture_comment(tctx, "Opened %zu connections with qdepth=%d => %zu loops\n",
			state->num_conns, torture_qdepth, state->num_loops);

	torture_comment(tctx, "Running for %d seconds\n", state->timelimit);

	state->starttime = timeval_current();

	te = tevent_add_timer(tctx->ev,
			      state,
			      timeval_current_ofs(1, 0),
			      test_smb2_bench_session_setup_progress,
			      state);
	torture_assert(tctx, te != NULL, __location__);

	while (!state->stop) {
		int rc = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, rc, 0, "tevent_loop_once");
	}

	torture_comment(tctx, "%.2f seconds\n", timeval_elapsed(&state->starttime));
	TALLOC_FREE(state);
	return ret;
}

struct torture_suite *torture_smb2_bench_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "bench");

	torture_suite_add_1smb2_test(suite, "oplock1", test_smb2_bench_oplock);
	torture_suite_add_1smb2_test(suite, "echo", test_smb2_bench_echo);
	torture_suite_add_1smb2_test(suite, "path-contention-shared", test_smb2_bench_path_contention_shared);
	torture_suite_add_1smb2_test(suite, "read", test_smb2_bench_read);
	torture_suite_add_1smb2_test(suite, "write", test_smb2_bench_write);
	torture_suite_add_1smb2_test(suite, "session-setup", test_smb2_bench_session_setup);

	suite->description = talloc_strdup(suite, "SMB2-BENCH tests");

	return suite;
}
