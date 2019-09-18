/* 
   Unix SMB/CIFS implementation.

   local test for messaging code

   Copyright (C) Andrew Tridgell 2004
   
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
#include "lib/events/events.h"
#include "lib/messaging/irpc.h"
#include "torture/torture.h"
#include "cluster/cluster.h"
#include "param/param.h"
#include "torture/local/proto.h"
#include "system/select.h"
#include "system/filesys.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static uint32_t msg_pong;

static void ping_message(struct imessaging_context *msg,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id src,
			 size_t num_fds,
			 int *fds,
			 DATA_BLOB *data)
{
	NTSTATUS status;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	status = imessaging_send(msg, src, msg_pong, data);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pong failed - %s\n", nt_errstr(status));
	}
}

static void pong_message(struct imessaging_context *msg,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id src,
			 size_t num_fds,
			 int *fds,
			 DATA_BLOB *data)
{
	int *count = (int *)private_data;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	(*count)++;
}

static void exit_message(struct imessaging_context *msg,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id src,
			 size_t num_fds,
			 int *fds,
			 DATA_BLOB *data)
{
	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	talloc_free(private_data);
	exit(0);
}

/*
  test ping speed
*/
static bool test_ping_speed(struct torture_context *tctx)
{
	struct tevent_context *ev;
	struct imessaging_context *msg_client_ctx;
	struct imessaging_context *msg_server_ctx;
	int ping_count = 0;
	int pong_count = 0;
	struct timeval tv;
	int timelimit = torture_setting_int(tctx, "timelimit", 10);
	uint32_t msg_ping, msg_exit;

	lpcfg_set_cmdline(tctx->lp_ctx, "pid directory", "piddir.tmp");

	ev = tctx->ev;

	msg_server_ctx = imessaging_init(tctx,
					 tctx->lp_ctx, cluster_id(0, 1),
					 ev);
	
	torture_assert(tctx, msg_server_ctx != NULL, "Failed to init ping messaging context");
		
	imessaging_register_tmp(msg_server_ctx, NULL, ping_message, &msg_ping);
	imessaging_register_tmp(msg_server_ctx, tctx, exit_message, &msg_exit);

	msg_client_ctx = imessaging_init(tctx,
					 tctx->lp_ctx,
					 cluster_id(0, 2),
					 ev);

	torture_assert(tctx, msg_client_ctx != NULL, 
		       "msg_client_ctx imessaging_init() failed");

	imessaging_register_tmp(msg_client_ctx, &pong_count, pong_message, &msg_pong);

	tv = timeval_current();

	torture_comment(tctx, "Sending pings for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		DATA_BLOB data;
		NTSTATUS status1, status2;

		data.data = discard_const_p(uint8_t, "testing");
		data.length = strlen((const char *)data.data);

		status1 = imessaging_send(msg_client_ctx, cluster_id(0, 1), msg_ping, &data);
		status2 = imessaging_send(msg_client_ctx, cluster_id(0, 1), msg_ping, NULL);

		torture_assert_ntstatus_ok(tctx, status1, "msg1 failed");
		ping_count++;

		torture_assert_ntstatus_ok(tctx, status2, "msg2 failed");
		ping_count++;

		while (ping_count > pong_count + 20) {
			tevent_loop_once(ev);
		}
	}

	torture_comment(tctx, "waiting for %d remaining replies (done %d)\n", 
	       ping_count - pong_count, pong_count);
	while (timeval_elapsed(&tv) < 30 && pong_count < ping_count) {
		tevent_loop_once(ev);
	}

	torture_comment(tctx, "sending exit\n");
	imessaging_send(msg_client_ctx, cluster_id(0, 1), msg_exit, NULL);

	torture_assert_int_equal(tctx, ping_count, pong_count, "ping test failed");

	torture_comment(tctx, "ping rate of %.0f messages/sec\n", 
	       (ping_count+pong_count)/timeval_elapsed(&tv));

	talloc_free(msg_client_ctx);
	talloc_free(msg_server_ctx);

	return true;
}

static bool test_messaging_overflow(struct torture_context *tctx)
{
	struct imessaging_context *msg_ctx;
	ssize_t nwritten, nread;
	pid_t child;
	char c = 0;
	int up_pipe[2], down_pipe[2];
	int i, ret, child_status;

	ret = pipe(up_pipe);
	torture_assert(tctx, ret == 0, "pipe failed");
	ret = pipe(down_pipe);
	torture_assert(tctx, ret == 0, "pipe failed");

	child = fork();
	if (child < 0) {
		torture_fail(tctx, "fork failed");
	}

	if (child == 0) {
		ret = tevent_re_initialise(tctx->ev);
		torture_assert(tctx, ret == 0, "tevent_re_initialise failed");

		msg_ctx = imessaging_init(tctx, tctx->lp_ctx,
					  cluster_id(getpid(), 0),
					  tctx->ev);
		torture_assert(tctx, msg_ctx != NULL,
			       "imessaging_init failed");

		do {
			nwritten = write(up_pipe[1], &c, 1);
		} while ((nwritten == -1) && (errno == EINTR));

		ret = close(down_pipe[1]);
		torture_assert(tctx, ret == 0, "close failed");

		do {
			nread = read(down_pipe[0], &c, 1);
		} while ((nread == -1) && (errno == EINTR));

		exit(0);
	}

	do {
		nread = read(up_pipe[0], &c, 1);
	} while ((nread == -1) && (errno == EINTR));

	msg_ctx = imessaging_init(tctx, tctx->lp_ctx, cluster_id(getpid(), 0),
				  tctx->ev);
	torture_assert(tctx, msg_ctx != NULL, "imessaging_init failed");

	for (i=0; i<1000; i++) {
		NTSTATUS status;
		status = imessaging_send(msg_ctx, cluster_id(child, 0),
					 MSG_PING, NULL);
		torture_assert_ntstatus_ok(tctx, status,
					   "imessaging_send failed");
	}

	tevent_loop_once(tctx->ev);

	talloc_free(msg_ctx);

	ret = close(down_pipe[1]);
	torture_assert(tctx, ret == 0, "close failed");

	ret = waitpid(child, &child_status, 0);
	torture_assert(tctx, ret == child, "wrong child exited");
	torture_assert(tctx, child_status == 0, "child failed");

	poll(NULL, 0, 500);

	return true;
}

struct overflow_parent_child {
	gnutls_hash_hd_t md5_hash_hnd;
	bool done;
};

static void overflow_md5_child_handler(struct imessaging_context *msg,
				       void *private_data,
				       uint32_t msg_type,
				       struct server_id server_id,
				       size_t num_fds,
				       int *fds,
				       DATA_BLOB *data)
{
	struct overflow_parent_child *state = private_data;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	if (data->length == 0) {
		state->done = true;
		return;
	}

	gnutls_hash(state->md5_hash_hnd, data->data, data->length);
}

struct overflow_child_parent {
	uint8_t final[16];
	bool done;
};

static void overflow_md5_parent_handler(struct imessaging_context *msg_ctx,
					void *private_data,
					uint32_t msg_type,
					struct server_id server_id,
					size_t num_fds,
					int *fds,
					DATA_BLOB *data)
{
	struct overflow_child_parent *state = private_data;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	if (data->length != sizeof(state->final)) {
		memset(state->final, 0, sizeof(state->final));
		state->done = true;
		return;
	}
	memcpy(state->final, data->data, 16);
	state->done = true;
}

static bool test_messaging_overflow_check(struct torture_context *tctx)
{
	struct imessaging_context *msg_ctx;
	ssize_t nwritten, nread;
	pid_t child;
	char c = 0;
	int up_pipe[2], down_pipe[2];
	int i, ret, child_status;
	gnutls_hash_hd_t hash_hnd;
	uint8_t final[16];
	struct overflow_child_parent child_msg = { .done = false };
	NTSTATUS status;

	ret = pipe(up_pipe);
	torture_assert(tctx, ret == 0, "pipe failed");
	ret = pipe(down_pipe);
	torture_assert(tctx, ret == 0, "pipe failed");

	child = fork();
	if (child < 0) {
		torture_fail(tctx, "fork failed");
	}

	if (child == 0) {
		struct overflow_parent_child child_state = { .done = false };
		DATA_BLOB retblob = { .data = final, .length = sizeof(final) };

		ret = tevent_re_initialise(tctx->ev);
		torture_assert(tctx, ret == 0, "tevent_re_initialise failed");

		gnutls_hash_init(&child_state.md5_hash_hnd, GNUTLS_DIG_MD5);

		msg_ctx = imessaging_init(tctx, tctx->lp_ctx,
					  cluster_id(getpid(), 0),
					  tctx->ev);
		torture_assert(tctx, msg_ctx != NULL,
			       "imessaging_init failed");

		status = imessaging_register(msg_ctx, &child_state,
					     MSG_TMP_BASE-1,
					     overflow_md5_child_handler);
		torture_assert(tctx, NT_STATUS_IS_OK(status),
			       "imessaging_register failed");

		do {
			nwritten = write(up_pipe[1], &c, 1);
		} while ((nwritten == -1) && (errno == EINTR));

		ret = close(down_pipe[1]);
		torture_assert(tctx, ret == 0, "close failed");

		do {
			nread = read(down_pipe[0], &c, 1);
		} while ((nread == -1) && (errno == EINTR));

		while (!child_state.done) {
			tevent_loop_once(tctx->ev);
		}

		gnutls_hash_deinit(child_state.md5_hash_hnd, final);

		status = imessaging_send(msg_ctx,
					 cluster_id(getppid(), 0),
					 MSG_TMP_BASE-2,
					 &retblob);
		torture_assert(tctx, NT_STATUS_IS_OK(status),
			       "imessaging_send failed");

		exit(0);
	}

	do {
		nread = read(up_pipe[0], &c, 1);
	} while ((nread == -1) && (errno == EINTR));

	msg_ctx = imessaging_init(tctx, tctx->lp_ctx, cluster_id(getpid(), 0),
				  tctx->ev);
	torture_assert(tctx, msg_ctx != NULL, "imessaging_init failed");

	status = imessaging_register(msg_ctx,
				     &child_msg,
				     MSG_TMP_BASE-2,
				     overflow_md5_parent_handler);
	torture_assert(tctx,
		       NT_STATUS_IS_OK(status),
		       "imessaging_register failed");

	gnutls_hash_init(&hash_hnd, GNUTLS_DIG_MD5);

	for (i=0; i<1000; i++) {
		size_t len = ((random() % 100) + 1);
		uint8_t buf[len];
		DATA_BLOB blob = { .data = buf, .length = len };

		generate_random_buffer(buf, len);

		gnutls_hash(hash_hnd, buf, len);

		status = imessaging_send(msg_ctx, cluster_id(child, 0),
					 MSG_TMP_BASE-1, &blob);
		torture_assert_ntstatus_ok(tctx, status,
					   "imessaging_send failed");
	}

	status = imessaging_send(msg_ctx, cluster_id(child, 0),
				 MSG_TMP_BASE-1, NULL);
	torture_assert_ntstatus_ok(tctx, status,
				   "imessaging_send failed");

	gnutls_hash_deinit(hash_hnd, final);

	do {
		nwritten = write(down_pipe[1], &c, 1);
	} while ((nwritten == -1) && (errno == EINTR));

	while (!child_msg.done) {
		tevent_loop_once(tctx->ev);
	}

	ret = close(down_pipe[1]);
	torture_assert(tctx, ret == 0, "close failed");

	talloc_free(msg_ctx);

	ret = waitpid(child, &child_status, 0);
	torture_assert(tctx, ret == child, "wrong child exited");
	torture_assert(tctx, child_status == 0, "child failed");

	if (memcmp(final, child_msg.final, 16) != 0) {
		dump_data_file(final, 16, false, stderr);
		dump_data_file(child_msg.final, 16, false, stderr);
		fflush(stderr);
		torture_fail(tctx, "checksum comparison failed");
	}

	return true;
}

struct test_multi_ctx {
	struct torture_context *tctx;
	struct imessaging_context *server_ctx;
	struct imessaging_context *client_ctx[4];
	size_t num_missing;
	bool got_server;
	bool got_client_0_1;
	bool got_client_2_3;
	bool ok;
};

static void multi_ctx_server_handler(struct imessaging_context *msg,
				     void *private_data,
				     uint32_t msg_type,
				     struct server_id server_id,
				     size_t num_fds,
				     int *fds,
				     DATA_BLOB *data)
{
	struct test_multi_ctx *state = private_data;
	char *str = NULL;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	torture_assert_goto(state->tctx, state->num_missing >= 1,
			    state->ok, fail,
			    "num_missing should be at least 1.");
	state->num_missing -= 1;

	torture_assert_goto(state->tctx, !state->got_server,
			    state->ok, fail,
			    "already got server.");
	state->got_server = true;

	/*
	 * We free the context itself and most likely reuse
	 * the memory immediately.
	 */
	TALLOC_FREE(state->server_ctx);
	str = generate_random_str(state->tctx, 128);
	torture_assert_goto(state->tctx, str != NULL,
			    state->ok, fail,
			    "generate_random_str()");

fail:
	return;
}

static void multi_ctx_client_0_1_handler(struct imessaging_context *msg,
					 void *private_data,
					 uint32_t msg_type,
					 struct server_id server_id,
					 size_t num_fds,
					 int *fds,
					 DATA_BLOB *data)
{
	struct test_multi_ctx *state = private_data;
	char *str = NULL;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	torture_assert_goto(state->tctx, state->num_missing >= 2,
			    state->ok, fail,
			    "num_missing should be at least 2.");
	state->num_missing -= 2;

	torture_assert_goto(state->tctx, !state->got_client_0_1,
			    state->ok, fail,
			    "already got client_0_1.");
	state->got_client_0_1 = true;

	/*
	 * We free two contexts and most likely reuse
	 * the memory immediately.
	 */
	TALLOC_FREE(state->client_ctx[0]);
	str = generate_random_str(state->tctx, 128);
	torture_assert_goto(state->tctx, str != NULL,
			    state->ok, fail,
			    "generate_random_str()");
	TALLOC_FREE(state->client_ctx[1]);
	str = generate_random_str(state->tctx, 128);
	torture_assert_goto(state->tctx, str != NULL,
			    state->ok, fail,
			    "generate_random_str()");

fail:
	return;
}

static void multi_ctx_client_2_3_handler(struct imessaging_context *msg,
					 void *private_data,
					 uint32_t msg_type,
					 struct server_id server_id,
					 size_t num_fds,
					 int *fds,
					 DATA_BLOB *data)
{
	struct test_multi_ctx *state = private_data;
	char *str = NULL;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	torture_assert_goto(state->tctx, state->num_missing >= 2,
			    state->ok, fail,
			    "num_missing should be at least 2.");
	state->num_missing -= 2;

	torture_assert_goto(state->tctx, !state->got_client_2_3,
			    state->ok, fail,
			    "already got client_2_3.");
	state->got_client_2_3 = true;

	/*
	 * We free two contexts and most likely reuse
	 * the memory immediately.
	 */
	TALLOC_FREE(state->client_ctx[2]);
	str = generate_random_str(state->tctx, 128);
	torture_assert_goto(state->tctx, str != NULL,
			    state->ok, fail,
			    "generate_random_str()");
	TALLOC_FREE(state->client_ctx[3]);
	str = generate_random_str(state->tctx, 128);
	torture_assert_goto(state->tctx, str != NULL,
			    state->ok, fail,
			    "generate_random_str()");

fail:
	return;
}

static bool test_multi_ctx(struct torture_context *tctx)
{
	struct test_multi_ctx state = {
		.tctx = tctx,
		.ok = true,
	};
	struct timeval tv;
	NTSTATUS status;

	lpcfg_set_cmdline(tctx->lp_ctx, "pid directory", "piddir.tmp");

	/*
	 * We use cluster_id(0, 0) as that gets for
	 * all task ids.
	 */
	state.server_ctx = imessaging_init(tctx,
					   tctx->lp_ctx,
					   cluster_id(0, 0),
					   tctx->ev);
	torture_assert(tctx, state.server_ctx != NULL,
		       "Failed to init messaging context");

	status = imessaging_register(state.server_ctx, &state,
				     MSG_TMP_BASE-1,
				     multi_ctx_server_handler);
	torture_assert(tctx, NT_STATUS_IS_OK(status), "imessaging_register failed");

	state.client_ctx[0] = imessaging_init(tctx,
					      tctx->lp_ctx,
					      cluster_id(0, 0),
					      tctx->ev);
	torture_assert(tctx, state.client_ctx[0] != NULL,
		       "msg_client_ctx imessaging_init() failed");
	status = imessaging_register(state.client_ctx[0], &state,
				     MSG_TMP_BASE-1,
				     multi_ctx_client_0_1_handler);
	torture_assert(tctx, NT_STATUS_IS_OK(status), "imessaging_register failed");
	state.client_ctx[1] = imessaging_init(tctx,
					      tctx->lp_ctx,
					      cluster_id(0, 0),
					      tctx->ev);
	torture_assert(tctx, state.client_ctx[1] != NULL,
		       "msg_client_ctx imessaging_init() failed");
	status = imessaging_register(state.client_ctx[1], &state,
				     MSG_TMP_BASE-1,
				     multi_ctx_client_0_1_handler);
	torture_assert(tctx, NT_STATUS_IS_OK(status), "imessaging_register failed");
	state.client_ctx[2] = imessaging_init(tctx,
					      tctx->lp_ctx,
					      cluster_id(0, 0),
					      tctx->ev);
	torture_assert(tctx, state.client_ctx[2] != NULL,
		       "msg_client_ctx imessaging_init() failed");
	status = imessaging_register(state.client_ctx[2], &state,
				     MSG_TMP_BASE-1,
				     multi_ctx_client_2_3_handler);
	torture_assert(tctx, NT_STATUS_IS_OK(status), "imessaging_register failed");
	state.client_ctx[3] = imessaging_init(tctx,
					      tctx->lp_ctx,
					      cluster_id(0, 0),
					      tctx->ev);
	torture_assert(tctx, state.client_ctx[3] != NULL,
		       "msg_client_ctx imessaging_init() failed");
	status = imessaging_register(state.client_ctx[3], &state,
				     MSG_TMP_BASE-1,
				     multi_ctx_client_2_3_handler);
	torture_assert(tctx, NT_STATUS_IS_OK(status), "imessaging_register failed");

	/*
	 * Send one message that need to arrive on 3 ( 5 - 2 ) handlers.
	 */
	state.num_missing = 5;

	status = imessaging_send(state.server_ctx,
				 cluster_id(0, 0),
				 MSG_TMP_BASE-1, NULL);
	torture_assert_ntstatus_ok(tctx, status, "msg failed");

	tv = timeval_current();
	while (timeval_elapsed(&tv) < 30 && state.num_missing > 0 && state.ok) {
		int ret;

		ret = tevent_loop_once(tctx->ev);
		torture_assert_int_equal(tctx, ret, 0, "tevent_loop_once()");
	}

	if (!state.ok) {
		return false;
	}

	torture_assert_int_equal(tctx, state.num_missing, 0,
				 "wrong message count");

	torture_assert(tctx, state.got_client_0_1, "got_client_0_1");
	torture_assert(tctx, state.got_client_2_3, "got_client_2_3");
	torture_assert(tctx, state.got_server, "got_server");

	return true;
}

struct torture_suite *torture_local_messaging(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *s = torture_suite_create(mem_ctx, "messaging");
	torture_suite_add_simple_test(s, "overflow", test_messaging_overflow);
	torture_suite_add_simple_test(s, "overflow_check",
				      test_messaging_overflow_check);
	torture_suite_add_simple_test(s, "ping_speed", test_ping_speed);
	torture_suite_add_simple_test(s, "multi_ctx", test_multi_ctx);
	return s;
}
