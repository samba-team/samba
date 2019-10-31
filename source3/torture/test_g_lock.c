/*
 * Unix SMB/CIFS implementation.
 * Test g_lock API
 * Copyright (C) Volker Lendecke 2017
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
#include "system/filesys.h"
#include "g_lock.h"
#include "messages.h"
#include "lib/util/server_id.h"
#include "lib/util/sys_rw.h"
#include "lib/util/util_tdb.h"
#include "lib/util/tevent_ntstatus.h"

static bool get_g_lock_ctx(TALLOC_CTX *mem_ctx,
			   struct tevent_context **ev,
			   struct messaging_context **msg,
			   struct g_lock_ctx **ctx)
{
	*ev = global_event_context();
	if (*ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		return false;
	}
	*msg = global_messaging_context();
	if (*msg == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		TALLOC_FREE(*ev);
		return false;
	}
	*ctx = g_lock_ctx_init(*ev, *msg);
	if (*ctx == NULL) {
		fprintf(stderr, "g_lock_ctx_init failed\n");
		TALLOC_FREE(*msg);
		TALLOC_FREE(*ev);
		return false;
	}

	return true;
}

bool run_g_lock1(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock1";
	NTSTATUS status;
	bool ret = false;
	bool ok;

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	status = g_lock_lock(ctx, string_term_tdb_data(lockname), G_LOCK_WRITE,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_lock(ctx, string_term_tdb_data(lockname), G_LOCK_WRITE,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_EQUAL(status, NT_STATUS_WAS_LOCKED)) {
		fprintf(stderr, "Double lock got %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_unlock(ctx, string_term_tdb_data(lockname));
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_unlock failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_unlock(ctx, string_term_tdb_data(lockname));
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		fprintf(stderr, "g_lock_unlock returned: %s\n",
			nt_errstr(status));
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

struct lock2_parser_state {
	uint8_t *rdata;
	bool ok;
};

static void lock2_parser(struct server_id exclusive,
			 size_t num_shared,
			 struct server_id *shared,
			 const uint8_t *data,
			 size_t datalen,
			 void *private_data)
{
	struct lock2_parser_state *state = private_data;

	if (datalen != sizeof(uint8_t)) {
		return;
	}
	*state->rdata = *data;
	state->ok = true;
}

/*
 * Test g_lock_write_data
 */

bool run_g_lock2(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock2";
	uint8_t data = 42;
	uint8_t rdata;
	struct lock2_parser_state state = { .rdata = &rdata };
	NTSTATUS status;
	bool ret = false;
	bool ok;

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	status = g_lock_write_data(ctx, string_term_tdb_data(lockname),
				   &data, sizeof(data));
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_LOCKED)) {
		fprintf(stderr, "unlocked g_lock_write_data returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_lock(ctx, string_term_tdb_data(lockname), G_LOCK_WRITE,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_write_data(ctx, string_term_tdb_data(lockname),
				   &data, sizeof(data));
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_write_data failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_unlock(ctx, string_term_tdb_data(lockname));
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_unlock failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_dump(ctx, string_term_tdb_data(lockname),
			     lock2_parser, &state);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_dump failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	if (!state.ok) {
		fprintf(stderr, "Could not parse data\n");
		goto fail;
	}
	if (rdata != data) {
		fprintf(stderr, "Returned %"PRIu8", expected %"PRIu8"\n",
			rdata, data);
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

struct lock3_parser_state {
	struct server_id self;
	enum g_lock_type lock_type;
	bool ok;
};

static void lock3_parser(struct server_id exclusive,
			 size_t num_shared,
			 struct server_id *shared,
			 const uint8_t *data,
			 size_t datalen,
			 void *private_data)
{
	struct lock3_parser_state *state = private_data;
	size_t num_locks = num_shared + ((exclusive.pid != 0) ? 1 : 0);
	struct server_id *pid;

	if (datalen != 0) {
		fprintf(stderr, "datalen=%zu\n", datalen);
		return;
	}
	if (num_locks != 1) {
		fprintf(stderr, "num_locks=%zu\n", num_locks);
		return;
	}

	if (state->lock_type == G_LOCK_WRITE) {
		if (exclusive.pid == 0) {
			fprintf(stderr, "Found READ, expected WRITE\n");
			return;
		}
	} else {
		if (exclusive.pid != 0) {
			fprintf(stderr, "Found WRITE, expected READ\n");
			return;
		}
	}

	pid = (exclusive.pid != 0) ? &exclusive : &shared[0];

	if (!server_id_equal(pid, &state->self)) {
		struct server_id_buf tmp1, tmp2;
		fprintf(stderr, "found pid %s, expected %s\n",
			server_id_str_buf(*pid, &tmp1),
			server_id_str_buf(state->self, &tmp2));
		return;
	}

	state->ok = true;
}

/*
 * Test lock upgrade/downgrade
 */

bool run_g_lock3(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock3";
	struct lock3_parser_state state;
	NTSTATUS status;
	bool ret = false;
	bool ok;

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	state.self = messaging_server_id(msg);

	status = g_lock_lock(ctx, string_term_tdb_data(lockname), G_LOCK_READ,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	state.lock_type = G_LOCK_READ;
	state.ok = false;

	status = g_lock_dump(ctx, string_term_tdb_data(lockname),
			     lock3_parser, &state);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		fprintf(stderr, "g_lock_dump returned %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (!state.ok) {
		goto fail;
	}

	status = g_lock_lock(ctx, string_term_tdb_data(lockname), G_LOCK_UPGRADE,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	state.lock_type = G_LOCK_WRITE;
	state.ok = false;

	status = g_lock_dump(ctx, string_term_tdb_data(lockname),
			     lock3_parser, &state);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
		fprintf(stderr, "g_lock_dump returned %s\n",
			nt_errstr(status));
		goto fail;
	}
	if (!state.ok) {
		goto fail;
	}


	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

static bool lock4_child(const char *lockname,
			enum g_lock_type lock_type,
			int ready_pipe,
			int exit_pipe)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	NTSTATUS status;
	ssize_t n;
	bool ok;

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		return false;
	}

	status = g_lock_lock(
		ctx,
		string_term_tdb_data(lockname),
		lock_type,
		(struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "child: g_lock_lock returned %s\n",
			nt_errstr(status));
		return false;
	}

	n = sys_write(ready_pipe, &ok, sizeof(ok));
	if (n != sizeof(ok)) {
		fprintf(stderr, "child: write failed\n");
		return false;
	}

	if (ok) {
		n = sys_read(exit_pipe, &ok, sizeof(ok));
		if (n != 0) {
			fprintf(stderr, "child: read failed\n");
			return false;
		}
	}

	return true;
}

static void lock4_done(struct tevent_req *subreq)
{
	int *done = tevent_req_callback_data_void(subreq);
	NTSTATUS status;

	status = g_lock_lock_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock_recv returned %s\n",
			nt_errstr(status));
		*done = -1;
		return;
	}
	*done = 1;
}

static void lock4_waited(struct tevent_req *subreq)
{
        int *exit_pipe = tevent_req_callback_data_void(subreq);
	pid_t child;
	int status;
	bool ok;

	printf("waited\n");

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		fprintf(stderr, "tevent_wakeup_recv failed\n");
	}
	close(*exit_pipe);

	child = wait(&status);

	printf("child %d exited with %d\n", (int)child, status);
}

struct lock4_check_state {
	struct server_id me;
	bool ok;
};

static void lock4_check(struct server_id exclusive,
			size_t num_shared,
			struct server_id *shared,
			const uint8_t *data,
			size_t datalen,
			void *private_data)
{
	struct lock4_check_state *state = private_data;
	size_t num_locks = num_shared + ((exclusive.pid != 0) ? 1 : 0);

	if (num_locks != 1) {
		fprintf(stderr, "num_locks=%zu\n", num_locks);
		return;
	}

	if (exclusive.pid == 0) {
		fprintf(stderr, "Wrong lock type, not WRITE\n");
		return;
	}

	if (!server_id_equal(&state->me, &exclusive)) {
		struct server_id_buf buf1, buf2;
		fprintf(stderr, "me=%s, locker=%s\n",
			server_id_str_buf(state->me, &buf1),
			server_id_str_buf(exclusive, &buf2));
		return;
	}

	state->ok = true;
}

/*
 * Test a lock conflict: Contend with a WRITE lock
 */

bool run_g_lock4(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock4";
	TDB_DATA key = string_term_tdb_data(lockname);
	pid_t child;
	int ready_pipe[2];
	int exit_pipe[2];
	NTSTATUS status;
	bool ret = false;
	struct tevent_req *req;
	bool ok;
	int done;

	if ((pipe(ready_pipe) != 0) || (pipe(exit_pipe) != 0)) {
		perror("pipe failed");
		return false;
	}

	child = fork();

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	if (child == -1) {
		perror("fork failed");
		return false;
	}

	if (child == 0) {
		close(ready_pipe[0]);
		close(exit_pipe[1]);
		ok = lock4_child(
			lockname, G_LOCK_WRITE, ready_pipe[1], exit_pipe[0]);
		exit(ok ? 0 : 1);
	}

	close(ready_pipe[1]);
	close(exit_pipe[0]);

	if (sys_read(ready_pipe[0], &ok, sizeof(ok)) != sizeof(ok)) {
		perror("read failed");
		return false;
	}

	if (!ok) {
		fprintf(stderr, "child returned error\n");
		return false;
	}

	status = g_lock_lock(
		ctx, key, G_LOCK_WRITE, (struct timeval) { .tv_usec = 1 });
	if (!NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_lock(
		ctx, key, G_LOCK_READ, (struct timeval) { .tv_usec = 1 });
	if (!NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	req = g_lock_lock_send(ev, ev, ctx, key, G_LOCK_WRITE);
	if (req == NULL) {
		fprintf(stderr, "g_lock_lock send failed\n");
		goto fail;
	}
	tevent_req_set_callback(req, lock4_done, &done);

	req = tevent_wakeup_send(ev, ev, timeval_current_ofs(1, 0));
	if (req == NULL) {
		fprintf(stderr, "tevent_wakeup_send failed\n");
		goto fail;
	}
	tevent_req_set_callback(req, lock4_waited, &exit_pipe[1]);

	done = 0;

	while (done == 0) {
		int tevent_ret = tevent_loop_once(ev);
		if (tevent_ret != 0) {
			perror("tevent_loop_once failed");
			goto fail;
		}
	}

	{
		struct lock4_check_state state = {
			.me = messaging_server_id(msg)
		};

		status = g_lock_dump(ctx, key, lock4_check, &state);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "g_lock_dump failed: %s\n",
				nt_errstr(status));
			goto fail;
		}
		if (!state.ok) {
			fprintf(stderr, "lock4_check failed\n");
			goto fail;
		}
	}

	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

/*
 * Test a lock conflict: Contend with a READ lock
 */

bool run_g_lock4a(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock4a";
	TDB_DATA key = string_term_tdb_data(lockname);
	pid_t child;
	int ready_pipe[2];
	int exit_pipe[2];
	NTSTATUS status;
	bool ret = false;
	struct tevent_req *req;
	bool ok;
	int done;

	if ((pipe(ready_pipe) != 0) || (pipe(exit_pipe) != 0)) {
		perror("pipe failed");
		return false;
	}

	child = fork();

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	if (child == -1) {
		perror("fork failed");
		return false;
	}

	if (child == 0) {
		close(ready_pipe[0]);
		close(exit_pipe[1]);
		ok = lock4_child(
			lockname, G_LOCK_READ, ready_pipe[1], exit_pipe[0]);
		exit(ok ? 0 : 1);
	}

	close(ready_pipe[1]);
	close(exit_pipe[0]);

	if (sys_read(ready_pipe[0], &ok, sizeof(ok)) != sizeof(ok)) {
		perror("read failed");
		return false;
	}

	if (!ok) {
		fprintf(stderr, "child returned error\n");
		return false;
	}

	status = g_lock_lock(
		ctx, key, G_LOCK_WRITE, (struct timeval) { .tv_usec = 1 });
	if (!NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_lock(
		ctx, key, G_LOCK_READ, (struct timeval) { .tv_usec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = g_lock_unlock(ctx, key);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"g_lock_unlock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	req = g_lock_lock_send(ev, ev, ctx, key, G_LOCK_WRITE);
	if (req == NULL) {
		fprintf(stderr, "g_lock_lock send failed\n");
		goto fail;
	}
	tevent_req_set_callback(req, lock4_done, &done);

	req = tevent_wakeup_send(ev, ev, timeval_current_ofs(1, 0));
	if (req == NULL) {
		fprintf(stderr, "tevent_wakeup_send failed\n");
		goto fail;
	}
	tevent_req_set_callback(req, lock4_waited, &exit_pipe[1]);

	done = 0;

	while (done == 0) {
		int tevent_ret = tevent_loop_once(ev);
		if (tevent_ret != 0) {
			perror("tevent_loop_once failed");
			goto fail;
		}
	}

	{
		struct lock4_check_state state = {
			.me = messaging_server_id(msg)
		};

		status = g_lock_dump(ctx, key, lock4_check, &state);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "g_lock_dump failed: %s\n",
				nt_errstr(status));
			goto fail;
		}
		if (!state.ok) {
			fprintf(stderr, "lock4_check failed\n");
			goto fail;
		}
	}

	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

struct lock5_parser_state {
	size_t num_locks;
};

static void lock5_parser(struct server_id exclusive,
			 size_t num_shared,
			 struct server_id *shared,
			 const uint8_t *data,
			 size_t datalen,
			 void *private_data)
{
	struct lock5_parser_state *state = private_data;
	state->num_locks = num_shared + ((exclusive.pid != 0) ? 1 : 0);
}

/*
 * Test heuristic cleanup
 */

bool run_g_lock5(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock5";
	pid_t child;
	int exit_pipe[2], ready_pipe[2];
	NTSTATUS status;
	size_t i, nprocs;
	int ret;
	bool ok;
	ssize_t nread;
	char c;

	nprocs = 5;

	if ((pipe(exit_pipe) != 0) || (pipe(ready_pipe) != 0)) {
		perror("pipe failed");
		return false;
	}

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		fprintf(stderr, "get_g_lock_ctx failed");
		return false;
	}

	for (i=0; i<nprocs; i++) {

		child = fork();

		if (child == -1) {
			perror("fork failed");
			return false;
		}

		if (child == 0) {
			TALLOC_FREE(ctx);

			status = reinit_after_fork(msg, ev, false, "");

			close(ready_pipe[0]);
			close(exit_pipe[1]);

			ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
			if (!ok) {
				fprintf(stderr, "get_g_lock_ctx failed");
				exit(1);
			}
			status = g_lock_lock(ctx,
					     string_term_tdb_data(lockname),
					     G_LOCK_READ,
					     (struct timeval) { .tv_sec = 1 });
			if (!NT_STATUS_IS_OK(status)) {
				fprintf(stderr,
					"child g_lock_lock failed %s\n",
					nt_errstr(status));
				exit(1);
			}
			close(ready_pipe[1]);
			nread = sys_read(exit_pipe[0], &c, sizeof(c));
			if (nread != 0) {
				fprintf(stderr, "sys_read returned %zu (%s)\n",
					nread, strerror(errno));
				exit(1);
			}
			exit(0);
		}
	}

	close(ready_pipe[1]);

	nread = sys_read(ready_pipe[0], &c, sizeof(c));
	if (nread != 0) {
		fprintf(stderr, "sys_read returned %zu (%s)\n",
			nread, strerror(errno));
		return false;
	}

	close(exit_pipe[1]);

	for (i=0; i<nprocs; i++) {
		int child_status;
		ret = waitpid(-1, &child_status, 0);
		if (ret == -1) {
			perror("waitpid failed");
			return false;
		}
	}

	for (i=0; i<nprocs; i++) {
		struct lock5_parser_state state;

		status = g_lock_dump(ctx, string_term_tdb_data(lockname),
				     lock5_parser, &state);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "g_lock_dump returned %s\n",
				nt_errstr(status));
			return false;
		}

		if (state.num_locks != (nprocs - i)) {
			fprintf(stderr, "nlocks=%zu, expected %zu\n",
				state.num_locks, (nprocs-i));
			return false;
		}

		status = g_lock_lock(ctx, string_term_tdb_data(lockname),
				     G_LOCK_READ,
				     (struct timeval) { .tv_sec = 1 });
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "g_lock_lock failed %s\n",
				nt_errstr(status));
			return false;
		}
		status = g_lock_unlock(ctx, string_term_tdb_data(lockname));
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "g_lock_unlock failed %s\n",
				nt_errstr(status));
			return false;
		}
	}


	return true;
}

struct lock6_parser_state {
	size_t num_locks;
};

static void lock6_parser(struct server_id exclusive,
			 size_t num_shared,
			 struct server_id *shared,
			 const uint8_t *data,
			 size_t datalen,
			 void *private_data)
{
	struct lock6_parser_state *state = private_data;
	state->num_locks = num_shared + ((exclusive.pid != 0) ? 1 : 0);
}

/*
 * Test cleanup with contention and stale locks
 */

bool run_g_lock6(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	TDB_DATA lockname = string_term_tdb_data("lock6");
	pid_t child;
	int exit_pipe[2], ready_pipe[2];
	NTSTATUS status;
	size_t i, nprocs;
	int ret;
	bool ok;
	ssize_t nread;
	char c;

	if ((pipe(exit_pipe) != 0) || (pipe(ready_pipe) != 0)) {
		perror("pipe failed");
		return false;
	}

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		fprintf(stderr, "get_g_lock_ctx failed");
		return false;
	}

	/*
	 * Wipe all stale locks -- in clustered mode there's no
	 * CLEAR_IF_FIRST
	 */
	status = g_lock_lock(ctx, lockname, G_LOCK_WRITE,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock failed: %s\n",
			nt_errstr(status));
		return false;
	}
	status = g_lock_unlock(ctx, lockname);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_unlock failed: %s\n",
			nt_errstr(status));
		return false;
	}

	nprocs = 2;
	for (i=0; i<nprocs; i++) {

		child = fork();

		if (child == -1) {
			perror("fork failed");
			return false;
		}

		if (child == 0) {
			TALLOC_FREE(ctx);

			status = reinit_after_fork(msg, ev, false, "");
			if (!NT_STATUS_IS_OK(status)) {
				fprintf(stderr, "reinit_after_fork failed: %s\n",
					nt_errstr(status));
				exit(1);
			}

			close(ready_pipe[0]);
			close(exit_pipe[1]);

			ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
			if (!ok) {
				fprintf(stderr, "get_g_lock_ctx failed");
				exit(1);
			}
			status = g_lock_lock(ctx,
					     lockname,
					     G_LOCK_READ,
					     (struct timeval) { .tv_sec = 1 });
			if (!NT_STATUS_IS_OK(status)) {
				fprintf(stderr,
					"child g_lock_lock failed %s\n",
					nt_errstr(status));
				exit(1);
			}
			if (i == 0) {
				exit(0);
			}
			close(ready_pipe[1]);
			nread = sys_read(exit_pipe[0], &c, sizeof(c));
			if (nread != 0) {
				fprintf(stderr, "sys_read returned %zu (%s)\n",
					nread, strerror(errno));
				exit(1);
			}
			exit(0);
		}
	}

	close(ready_pipe[1]);

	nread = sys_read(ready_pipe[0], &c, sizeof(c));
	if (nread != 0) {
		fprintf(stderr, "sys_read returned %zd (%s)\n",
			nread, strerror(errno));
		return false;
	}

	{
		int child_status;
		ret = waitpid(-1, &child_status, 0);
		if (ret == -1) {
			perror("waitpid failed");
			return false;
		}
	}

	{
		struct lock6_parser_state state;

		status = g_lock_dump(ctx, lockname, lock6_parser, &state);
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "g_lock_dump returned %s\n",
				nt_errstr(status));
			return false;
		}

		if (state.num_locks != nprocs) {
			fprintf(stderr, "nlocks=%zu, expected %zu\n",
				state.num_locks, nprocs);
			return false;
		}

		status = g_lock_lock(ctx,
				     lockname,
				     G_LOCK_WRITE,
				     (struct timeval) { .tv_sec = 1 });
		if (!NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
			fprintf(stderr, "g_lock_lock should have failed with %s - %s\n",
				nt_errstr(NT_STATUS_IO_TIMEOUT),
				nt_errstr(status));
			return false;
		}

		status = g_lock_lock(ctx, lockname, G_LOCK_READ,
				     (struct timeval) { .tv_sec = 1 });
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "g_lock_lock failed: %s\n",
				nt_errstr(status));
			return false;
		}
	}

	close(exit_pipe[1]);

	{
		int child_status;
		ret = waitpid(-1, &child_status, 0);
		if (ret == -1) {
			perror("waitpid failed");
			return false;
		}
	}

	status = g_lock_lock(ctx, lockname, G_LOCK_UPGRADE,
			     (struct timeval) { .tv_sec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock failed: %s\n",
			nt_errstr(status));
		return false;
	}

	return true;
}

/*
 * Test upgrade deadlock
 */

bool run_g_lock7(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	const char *lockname = "lock7";
	TDB_DATA key = string_term_tdb_data(lockname);
	pid_t child;
	int ready_pipe[2];
	int down_pipe[2];
	ssize_t n;
	NTSTATUS status;
	bool ret = false;
	bool ok = true;

	if ((pipe(ready_pipe) != 0) || (pipe(down_pipe) != 0)) {
		perror("pipe failed");
		return false;
	}

	child = fork();

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	if (child == -1) {
		perror("fork failed");
		return false;
	}

	if (child == 0) {
		struct tevent_req *req = NULL;

		close(ready_pipe[0]);
		ready_pipe[0] = -1;
		close(down_pipe[1]);
		down_pipe[1] = -1;

		status = reinit_after_fork(msg, ev, false, "");
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr,
				"reinit_after_fork failed: %s\n",
				nt_errstr(status));
			exit(1);
		}

		printf("%d: locking READ\n", (int)getpid());

		status = g_lock_lock(
			ctx,
			key,
			G_LOCK_READ,
			(struct timeval) { .tv_usec = 1 });
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr,
				"g_lock_lock(READ) failed: %s\n",
				nt_errstr(status));
			exit(1);
		}

		ok = true;

		n = sys_write(ready_pipe[1], &ok, sizeof(ok));
		if (n != sizeof(ok)) {
			fprintf(stderr,
				"sys_write failed: %s\n",
				strerror(errno));
			exit(1);
		}

		n = sys_read(down_pipe[0], &ok, sizeof(ok));
		if (n != sizeof(ok)) {
			fprintf(stderr,
				"sys_read failed: %s\n",
				strerror(errno));
			exit(1);
		}

		printf("%d: starting UPGRADE\n", (int)getpid());

		req = g_lock_lock_send(
			msg,
			ev,
			ctx,
			key,
			G_LOCK_UPGRADE);
		if (req == NULL) {
			fprintf(stderr, "g_lock_lock_send(UPGRADE) failed\n");
			exit(1);
		}

		n = sys_write(ready_pipe[1], &ok, sizeof(ok));
		if (n != sizeof(ok)) {
			fprintf(stderr,
				"sys_write failed: %s\n",
				strerror(errno));
			exit(1);
		}

		exit(0);
	}

	close(ready_pipe[1]);
	close(down_pipe[0]);

	if (sys_read(ready_pipe[0], &ok, sizeof(ok)) != sizeof(ok)) {
		perror("read failed");
		return false;
	}
	if (!ok) {
		fprintf(stderr, "child returned error\n");
		return false;
	}

	status = g_lock_lock(
		ctx,
		key,
		G_LOCK_READ,
		(struct timeval) { .tv_usec = 1 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"g_lock_lock(READ) failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	n = sys_write(down_pipe[1], &ok, sizeof(ok));
	if (n != sizeof(ok)) {
		fprintf(stderr,
			"sys_write failed: %s\n",
			strerror(errno));
		goto fail;
	}

	if (sys_read(ready_pipe[0], &ok, sizeof(ok)) != sizeof(ok)) {
		perror("read failed");
		goto fail;
	}

	status = g_lock_lock(
		ctx,
		key,
		G_LOCK_UPGRADE,
		(struct timeval) { .tv_sec = 10 });
	if (!NT_STATUS_EQUAL(status, NT_STATUS_POSSIBLE_DEADLOCK)) {
		fprintf(stderr,
			"g_lock_lock returned %s\n",
			nt_errstr(status));
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

bool run_g_lock8(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	struct tevent_req *req = NULL;
	TDB_DATA lockname = string_term_tdb_data("lock8");
	NTSTATUS status;
	bool ok;

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		fprintf(stderr, "get_g_lock_ctx failed");
		return false;
	}

	req = g_lock_watch_data_send(
		ev, ev, ctx, lockname, (struct server_id) { .pid = 0 });
	if (req == NULL) {
		fprintf(stderr, "get_g_lock_ctx failed");
		return false;
	}

	status = g_lock_lock(
		ctx,
		lockname,
		G_LOCK_WRITE,
		(struct timeval) { .tv_sec = 999 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"g_lock_lock failed: %s\n",
			nt_errstr(status));
		return false;
	}

	status = g_lock_write_data(
		ctx, lockname, lockname.dptr, lockname.dsize);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"g_lock_write_data failed: %s\n",
			nt_errstr(status));
		return false;
	}

	status = g_lock_write_data(ctx, lockname, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"g_lock_write_data failed: %s\n",
			nt_errstr(status));
		return false;
	}

	status = g_lock_unlock(ctx, lockname);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"g_lock_unlock failed: %s\n",
			nt_errstr(status));
		return false;
	}

	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		fprintf(stderr, "tevent_req_poll_ntstatus failed\n");
		return false;
	}
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"tevent_req_poll_ntstatus failed: %s\n",
			nt_errstr(status));
		return false;
	}

	return true;
}

extern int torture_numops;
extern int torture_nprocs;

static struct timeval tp1, tp2;

static void start_timer(void)
{
	gettimeofday(&tp1,NULL);
}

static double end_timer(void)
{
	gettimeofday(&tp2,NULL);
	return (tp2.tv_sec + (tp2.tv_usec*1.0e-6)) -
		(tp1.tv_sec + (tp1.tv_usec*1.0e-6));
}

/*
 * g_lock ping_pong
 */

bool run_g_lock_ping_pong(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *ctx = NULL;
	fstring name;
	NTSTATUS status;
	int i = 0;
	bool ret = false;
	bool ok;
	unsigned count = 0;

	torture_nprocs = MAX(2, torture_nprocs);

	ok = get_g_lock_ctx(talloc_tos(), &ev, &msg, &ctx);
	if (!ok) {
		goto fail;
	}

	start_timer();

	snprintf(name, sizeof(name), "ping_pong_%d", i);

	status = g_lock_lock(ctx, string_term_tdb_data(name), G_LOCK_WRITE,
			     (struct timeval) { .tv_sec = 60 });
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "g_lock_lock failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	for (i=0; i<torture_numops; i++) {

		name[10] = '0' + ((i+1) % torture_nprocs);

		status = g_lock_lock(ctx, string_term_tdb_data(name),
				     G_LOCK_WRITE,
				     (struct timeval) { .tv_sec = 60 });
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "g_lock_lock failed: %s\n",
				nt_errstr(status));
			goto fail;
		}

		name[10] = '0' + ((i) % torture_nprocs);

		status = g_lock_unlock(ctx, string_term_tdb_data(name));
		if (!NT_STATUS_IS_OK(status)) {
			fprintf(stderr, "g_lock_unlock failed: %s\n",
				nt_errstr(status));
			goto fail;
		}

		count++;

		if (end_timer() > 1.0) {
			printf("%8u locks/sec\r",
			       (unsigned)(2*count/end_timer()));
			fflush(stdout);
			start_timer();
			count=0;
		}
	}

	ret = true;
fail:
	TALLOC_FREE(ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}
