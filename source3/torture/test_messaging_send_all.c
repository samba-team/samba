/*
 * Unix SMB/CIFS implementation.
 * Test for a messaging_send_all bug
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
#include "lib/util/tevent_unix.h"
#include "messages.h"
#include "lib/async_req/async_sock.h"
#include "lib/util/sys_rw.h"

static pid_t fork_responder(struct messaging_context *msg_ctx,
			    int exit_pipe[2])
{
	struct tevent_context *ev = messaging_tevent_context(msg_ctx);
	struct tevent_req *req;
	pid_t child_pid;
	int ready_pipe[2];
	char c = 0;
	bool ok;
	int ret, err;
	NTSTATUS status;
	ssize_t nwritten;

	ret = pipe(ready_pipe);
	if (ret == -1) {
		perror("pipe failed");
		return -1;
	}

	child_pid = fork();
	if (child_pid == -1) {
		perror("fork failed");
		close(ready_pipe[0]);
		close(ready_pipe[1]);
		return -1;
	}

	if (child_pid != 0) {
		ssize_t nread;
		close(ready_pipe[1]);
		nread = read(ready_pipe[0], &c, 1);
		close(ready_pipe[0]);
		if (nread != 1) {
			perror("read failed");
			return -1;
		}
		return child_pid;
	}

	close(ready_pipe[0]);
	close(exit_pipe[1]);

	status = messaging_reinit(msg_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "messaging_reinit failed: %s\n",
			nt_errstr(status));
		close(ready_pipe[1]);
		exit(1);
	}

	nwritten = sys_write(ready_pipe[1], &c, 1);
	if (nwritten != 1) {
		fprintf(stderr, "write failed: %s\n", strerror(errno));
		exit(1);
	}

	close(ready_pipe[1]);

	req = wait_for_read_send(ev, ev, exit_pipe[0], false);
	if (req == NULL) {
		fprintf(stderr, "wait_for_read_send failed\n");
		exit(1);
	}

	ok = tevent_req_poll_unix(req, ev, &err);
	if (!ok) {
		fprintf(stderr, "tevent_req_poll_unix failed: %s\n",
			strerror(err));
		exit(1);
	}

	exit(0);
}

struct messaging_send_all_state {
	struct tevent_context *ev;
	struct messaging_context *msg;
	pid_t *senders;
	size_t num_received;
};

static void collect_pong_received(struct tevent_req *subreq);

static struct tevent_req *collect_pong_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct messaging_context *msg,
					    const pid_t *senders,
					    size_t num_senders)
{
	struct tevent_req *req, *subreq;
	struct messaging_send_all_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct messaging_send_all_state);
	if (req == NULL) {
		return NULL;
	}
	state->senders = talloc_memdup(
		state, senders, num_senders * sizeof(pid_t));
	if (tevent_req_nomem(state->senders, req)) {
		return tevent_req_post(req, ev);
	}
	state->ev = ev;
	state->msg = msg;

	subreq = messaging_read_send(state, state->ev, state->msg, MSG_PONG);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, collect_pong_received, req);
	return req;
}

static void collect_pong_received(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct messaging_send_all_state *state = tevent_req_data(
		req, struct messaging_send_all_state);
	size_t num_senders = talloc_array_length(state->senders);
	size_t i;
	struct messaging_rec *rec;
	int ret;

	ret = messaging_read_recv(subreq, state, &rec);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	/*
	 * We need to make sure we don't receive our own broadcast!
	 */

	if (rec->src.pid == (uint64_t)getpid()) {
		fprintf(stderr, "Received my own broadcast!\n");
		tevent_req_error(req, EMULTIHOP);
		return;
	}

	for (i=0; i<num_senders; i++) {
		if (state->senders[i] == (pid_t)rec->src.pid) {
			printf("got message from %"PRIu64"\n", rec->src.pid);
			state->senders[i] = 0;
			state->num_received += 1;
			break;
		}
	}

	if (state->num_received == num_senders) {
		printf("done\n");
		tevent_req_done(req);
		return;
	}

	subreq = messaging_read_send(state, state->ev, state->msg, MSG_PONG);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, collect_pong_received, req);
}

static int collect_pong_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

extern int torture_nprocs;

bool run_messaging_send_all(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	int exit_pipe[2];
	pid_t children[MAX(5, torture_nprocs)];
	struct tevent_req *req;
	size_t i;
	bool ok;
	int ret, err;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		return false;
	}
	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		return false;
	}
	ret = pipe(exit_pipe);
	if (ret != 0) {
		perror("parent: pipe failed for exit_pipe");
		return false;
	}

	for (i=0; i<ARRAY_SIZE(children); i++) {
		children[i] = fork_responder(msg_ctx, exit_pipe);
		if (children[i] == -1) {
			fprintf(stderr, "fork_responder(%zu) failed\n", i);
			return false;
		}
	}

	req = collect_pong_send(ev, ev, msg_ctx, children,
				ARRAY_SIZE(children));
	if (req == NULL) {
		perror("collect_pong failed");
		return false;
	}

	ok = tevent_req_set_endtime(req, ev,
				    tevent_timeval_current_ofs(10, 0));
	if (!ok) {
		perror("tevent_req_set_endtime failed");
		return false;
	}

	messaging_send_all(msg_ctx, MSG_PING, NULL, 0);

	ok = tevent_req_poll_unix(req, ev, &err);
	if (!ok) {
		perror("tevent_req_poll_unix failed");
		return false;
	}

	ret = collect_pong_recv(req);
	TALLOC_FREE(req);

	if (ret != 0) {
		fprintf(stderr, "collect_pong_send returned %s\n",
			strerror(ret));
		return false;
	}

	close(exit_pipe[1]);

	for (i=0; i<ARRAY_SIZE(children); i++) {
		pid_t child;
		int status;

		do {
			child = waitpid(children[i], &status, 0);
		} while ((child == -1) && (errno == EINTR));

		if (child != children[i]) {
			printf("waitpid(%d) failed\n", children[i]);
			return false;
		}
	}

	return true;
}
